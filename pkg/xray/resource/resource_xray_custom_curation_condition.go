package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

// conditionTemplateParams maps condition template IDs to their allowed parameters
var conditionTemplateParams = map[string][]string{
	"OpenSSF": {
		"list_of_scorecard_checks",
		"block_in_case_check_value_is_missing",
	},
	"BannedLabels": {
		"list_of_labels",
	},
	"AllowedLabels": {
		"list_of_labels",
	},
	"SpecificVersions": {
		"package_type",
		"package_name",
		"package_versions",
	},
	"AllowedLicenses": {
		"list_of_package_licenses",
		"multiple_license_permissive_approach",
	},
	"BannedLicenses": {
		"list_of_package_licenses",
		"multiple_license_permissive_approach",
	},
	"CVECVSSRange": {
		"vulnerability_cvss_score_range",
		"epss",
		"apply_only_if_fix_is_available",
		"do_not_apply_for_already_existing_vulnerabilities",
	},
	"isImmature": {
		"package_age_days",
		"vulnerability_cvss_score",
	},
	"CVEName": {
		"cve_name",
	},
}

// paramValuesJSONValidator validates the param_values JSON structure and value types
type paramValuesJSONValidator struct{}

func (v paramValuesJSONValidator) Description(ctx context.Context) string {
	return "validates that param_values JSON has correct structure and value types for each param_id"
}

func (v paramValuesJSONValidator) MarkdownDescription(ctx context.Context) string {
	return "validates that param_values JSON has correct structure and value types for each param_id"
}

func (v paramValuesJSONValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	jsonStr := req.ConfigValue.ValueString()

	// Parse the JSON string
	var paramValues []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &paramValues); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid param_values format",
			fmt.Sprintf("param_values must be valid JSON: %s", err.Error()),
		)
		return
	}

	// Get condition_template_id from the configuration first
	conditionTemplateID := ""
	var conditionTemplateIDValue attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root("condition_template_id"), &conditionTemplateIDValue)
	if !diags.HasError() && !conditionTemplateIDValue.IsNull() && !conditionTemplateIDValue.IsUnknown() {
		if strVal, ok := conditionTemplateIDValue.(types.String); ok {
			conditionTemplateID = strVal.ValueString()
		}
	}

	// Check for empty parameters (required for all templates)
	if len(paramValues) == 0 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid param_values format",
			"param_values must contain at least one parameter object",
		)
		return
	}

	// Special validation for condition templates that require exactly one parameter object
	switch conditionTemplateID {
	case "CVEName":
		if len(paramValues) != 1 {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid parameter count for CVEName",
				fmt.Sprintf("condition_template_id 'CVEName' must have exactly 1 parameter object, got %d", len(paramValues)),
			)
			return
		}
	case "BannedLabels", "AllowedLabels":
		if len(paramValues) != 1 {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				fmt.Sprintf("Invalid parameter count for %s", conditionTemplateID),
				fmt.Sprintf("condition_template_id '%s' must have exactly 1 parameter object, got %d", conditionTemplateID, len(paramValues)),
			)
			return
		}
	}

	providedParams := make(map[string]bool)
	hasInvalidParams := false

	for i, paramValue := range paramValues {
		// Check that each object has param_id and value
		paramID, hasParamID := paramValue["param_id"]
		value, hasValue := paramValue["value"]

		if !hasParamID {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid param_values format",
				fmt.Sprintf("Parameter object at index %d is missing 'param_id' field", i),
			)
			continue
		}

		if !hasValue {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid param_values format",
				fmt.Sprintf("Parameter object at index %d is missing 'value' field", i),
			)
			continue
		}

		paramIDStr, ok := paramID.(string)
		if !ok {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid param_values format",
				fmt.Sprintf("Parameter object at index %d has non-string 'param_id'", i),
			)
			continue
		}

		// Validate param_id against condition_template_id
		if conditionTemplateID != "" {
			allowedParams, exists := conditionTemplateParams[conditionTemplateID]
			if exists {
				isValidParam := false
				for _, allowedParam := range allowedParams {
					if paramIDStr == allowedParam {
						isValidParam = true
						break
					}
				}
				if !isValidParam {
					resp.Diagnostics.AddAttributeError(
						req.Path,
						"Invalid param_id for condition_template_id",
						fmt.Sprintf("param_id '%s' is not allowed for condition_template_id '%s'. Allowed parameters: %v", paramIDStr, conditionTemplateID, allowedParams),
					)
					hasInvalidParams = true
					continue
				}
			}
		}

		// Validate value type based on param_id
		v.validateValueType(req.Path, paramIDStr, value, resp)

		providedParams[paramIDStr] = true
	}

	// Skip missing parameter validation if there were invalid param_ids
	if hasInvalidParams {
		return
	}

	// Validate required parameters for condition_template_id
	if conditionTemplateID != "" {
		v.validateRequiredParams(req.Path, conditionTemplateID, providedParams, resp)
	}
}

func (v paramValuesJSONValidator) validateValueType(path path.Path, paramID string, value interface{}, resp *validator.StringResponse) {
	switch paramID {
	case "list_of_scorecard_checks":
		// Should be a map/object
		if valueMap, ok := value.(map[string]interface{}); ok {
			// Validate each scorecard check
			for checkName, checkScore := range valueMap {
				// Validate score is a number between 0 and 10
				var scoreFloat float64
				switch score := checkScore.(type) {
				case float64:
					scoreFloat = score
				case int:
					scoreFloat = float64(score)
				default:
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid scorecard check score type",
						fmt.Sprintf("Parameter %s: score for check '%s' must be a number, got %T", paramID, checkName, checkScore),
					)
					continue
				}

				if scoreFloat < 0 || scoreFloat > 10 {
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid scorecard check score range",
						fmt.Sprintf("Parameter %s: score for check '%s' must be between 0 and 10, got %g", paramID, checkName, scoreFloat),
					)
				}
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for list_of_scorecard_checks",
				fmt.Sprintf("Parameter %s: value must be an object/map, got %T", paramID, value),
			)
		}

	case "apply_only_if_fix_is_available", "multiple_license_permissive_approach", "block_in_case_check_value_is_missing", "do_not_apply_for_already_existing_vulnerabilities":
		// Should be a boolean
		if _, ok := value.(bool); !ok {
			// Provide more user-friendly type names
			var typeName string
			switch v := value.(type) {
			case string:
				typeName = "string"
			case float64:
				// Check if it's actually an integer value
				if v == float64(int64(v)) {
					typeName = "integer"
				} else {
					typeName = "number"
				}
			case int, int64:
				typeName = "integer"
			case []interface{}:
				typeName = "array"
			case map[string]interface{}:
				typeName = "object"
			default:
				typeName = fmt.Sprintf("%T", value)
			}

			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for boolean parameter",
				fmt.Sprintf("Parameter %s: value must be a boolean (true or false), got %s", paramID, typeName),
			)
		}

	case "package_age_days":
		// Should be an integer between 1 and 99
		switch v := value.(type) {
		case float64:
			if v != float64(int(v)) {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid value for package_age_days",
					fmt.Sprintf("Parameter %s: value must be an integer, got %g", paramID, v),
				)
			}
			intVal := int(v)
			if intVal < 1 || intVal > 99 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid value range for package_age_days",
					fmt.Sprintf("Parameter %s: value must be between 1 and 99 (inclusive), got %d", paramID, intVal),
				)
			}
		case int:
			if v < 1 || v > 99 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid value range for package_age_days",
					fmt.Sprintf("Parameter %s: value must be between 1 and 99 (inclusive), got %d", paramID, v),
				)
			}
		default:
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for package_age_days",
				fmt.Sprintf("Parameter %s: value must be an integer, got %T", paramID, value),
			)
		}

	case "vulnerability_cvss_score":
		// Should be a number with one decimal digit between 0 and 10
		switch v := value.(type) {
		case float64:
			if v < 0 || v > 10 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid CVSS score range",
					fmt.Sprintf("Parameter %s: value must be between 0 and 10 (inclusive), got %g", paramID, v),
				)
			}
			// Check if it has more than one decimal place
			if v*10 != float64(int(v*10)) {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid decimal precision for vulnerability_cvss_score",
					fmt.Sprintf("Parameter %s: value must have at most one decimal digit, got %g", paramID, v),
				)
			}
		case int:
			if v < 0 || v > 10 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid CVSS score range",
					fmt.Sprintf("Parameter %s: value must be between 0 and 10 (inclusive), got %d", paramID, v),
				)
			}
		default:
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for vulnerability_cvss_score",
				fmt.Sprintf("Parameter %s: value must be a number, got %T", paramID, value),
			)
		}

	case "epss":
		// Should be an object with either percentile or score property
		if valueMap, ok := value.(map[string]interface{}); ok {
			percentileValue, hasPercentile := valueMap["percentile"]
			scoreValue, hasScore := valueMap["score"]

			// Validate that exactly one of percentile or score is present
			if !hasPercentile && !hasScore {
				resp.Diagnostics.AddAttributeError(
					path,
					"Missing EPSS property",
					fmt.Sprintf("Parameter %s: object must contain either 'percentile' or 'score' property", paramID),
				)
			} else if hasPercentile && hasScore {
				resp.Diagnostics.AddAttributeError(
					path,
					"Multiple EPSS properties",
					fmt.Sprintf("Parameter %s: object must contain only one of 'percentile' or 'score' properties, not both", paramID),
				)
			} else if hasPercentile {
				// Validate percentile: 0-100, max 2 decimal digits
				switch v := percentileValue.(type) {
				case float64:
					if v < 0 || v > 100 {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid EPSS percentile range",
							fmt.Sprintf("Parameter %s: percentile value must be between 0 and 100, got %g", paramID, v),
						)
					}
					// Check decimal places (max 2)
					if v*100 != float64(int(v*100)) {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid decimal precision for percentile",
							fmt.Sprintf("Parameter %s: percentile value can have at most 2 decimal digits, got %g", paramID, v),
						)
					}
				case int:
					if v < 0 || v > 100 {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid EPSS percentile range",
							fmt.Sprintf("Parameter %s: percentile value must be between 0 and 100, got %d", paramID, v),
						)
					}
				default:
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid EPSS percentile value type",
						fmt.Sprintf("Parameter %s: percentile value must be a number, got %T", paramID, percentileValue),
					)
				}
			} else if hasScore {
				// Validate score: 0.0-1.0
				switch v := scoreValue.(type) {
				case float64:
					if v < 0.0 || v > 1.0 {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid EPSS score range",
							fmt.Sprintf("Parameter %s: score value must be between 0.0 and 1.0, got %g", paramID, v),
						)
					}
				case int:
					// Convert int to float for validation
					floatVal := float64(v)
					if floatVal < 0.0 || floatVal > 1.0 {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid EPSS score range",
							fmt.Sprintf("Parameter %s: score value must be between 0.0 and 1.0, got %d", paramID, v),
						)
					}
				default:
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid EPSS score value type",
						fmt.Sprintf("Parameter %s: score value must be a number, got %T", paramID, scoreValue),
					)
				}
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for EPSS parameter",
				fmt.Sprintf("Parameter %s: value must be an object with either 'percentile' or 'score' property, got %T", paramID, value),
			)
		}

	case "vulnerability_cvss_score_range", "list_of_package_licenses", "list_of_labels":
		// Should be an array
		if valueArray, ok := value.([]interface{}); ok {
			if len(valueArray) == 0 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Empty array not allowed",
					fmt.Sprintf("Parameter %s: value array cannot be empty", paramID),
				)
			}
			// For CVSS range, validate it has exactly 2 numeric elements
			if paramID == "vulnerability_cvss_score_range" {
				if len(valueArray) != 2 {
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid CVSS range length",
						fmt.Sprintf("Parameter %s: value must contain exactly 2 elements (min and max), got %d", paramID, len(valueArray)),
					)
				} else {
					for j, elem := range valueArray {
						var elemFloat float64
						switch e := elem.(type) {
						case float64:
							elemFloat = e
						case int:
							elemFloat = float64(e)
						default:
							resp.Diagnostics.AddAttributeError(
								path,
								"Invalid CVSS range element type",
								fmt.Sprintf("Parameter %s: element at index %d must be a number, got %T", paramID, j, elem),
							)
							continue
						}
						if elemFloat < 0 || elemFloat > 10 {
							resp.Diagnostics.AddAttributeError(
								path,
								"Invalid CVSS range value",
								fmt.Sprintf("Parameter %s: element at index %d must be between 0 and 10, got %g", paramID, j, elemFloat),
							)
						}
					}
				}
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for array parameter",
				fmt.Sprintf("Parameter %s: value must be an array, got %T", paramID, value),
			)
		}

	case "package_versions":
		// Handle object format with version constraint operators
		if valueObj, ok := value.(map[string]interface{}); ok {
			if len(valueObj) == 0 {
				resp.Diagnostics.AddAttributeError(
					path,
					"Empty object not allowed",
					fmt.Sprintf("Parameter %s: value object cannot be empty", paramID),
				)
				return
			}

			validOperators := []string{"equals", "gte", "lte", "gt", "lt", "ranges", "any"}
			singleUseOperators := map[string]bool{"equals": true, "any": true}
			operatorUsage := make(map[string]bool)

			// Validate each operator in the object
			for operator, operatorValue := range valueObj {
				// Check if operator is valid
				isValidOperator := false
				for _, validOp := range validOperators {
					if operator == validOp {
						isValidOperator = true
						break
					}
				}
				if !isValidOperator {
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid package_versions operator",
						fmt.Sprintf("Parameter %s: invalid operator '%s', must be one of %v", paramID, operator, validOperators),
					)
					continue
				}

				// Check if single-use operators (equals, any) are already used
				if singleUseOperators[operator] && operatorUsage[operator] {
					resp.Diagnostics.AddAttributeError(
						path,
						fmt.Sprintf("Multiple '%s' operators not allowed", operator),
						fmt.Sprintf("Parameter %s: '%s' operator can only be used once", paramID, operator),
					)
					continue
				}
				operatorUsage[operator] = true

				switch operator {
				case "equals":

					// Validate "equals" operator value must be an array
					if equalsArray, ok := operatorValue.([]interface{}); ok {
						if len(equalsArray) == 0 {
							resp.Diagnostics.AddAttributeError(
								path,
								"Empty 'equals' array not allowed",
								fmt.Sprintf("Parameter %s: 'equals' operator cannot have empty array", paramID),
							)
						}
						// Validate each version in the "equals" array
						for j, ver := range equalsArray {
							if _, ok := ver.(string); !ok {
								resp.Diagnostics.AddAttributeError(
									path,
									"Invalid version format in 'equals' operator",
									fmt.Sprintf("Parameter %s: version at index %d in 'equals' operator must be string, got %T", paramID, j, ver),
								)
							}
						}
					} else {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid 'equals' operator value type",
							fmt.Sprintf("Parameter %s: 'equals' operator must have array value, got %T", paramID, operatorValue),
						)
					}

				case "any":
					// Validate "any" operator should be used alone
					if len(valueObj) > 1 {
						resp.Diagnostics.AddAttributeError(
							path,
							"'any' operator must be used alone",
							fmt.Sprintf("Parameter %s: 'any' operator cannot be combined with other operators", paramID),
						)
					}

					// Validate "any" operator value (can be boolean true or empty string)
					if boolValue, ok := operatorValue.(bool); ok {
						if !boolValue {
							resp.Diagnostics.AddAttributeError(
								path,
								"Invalid 'any' operator value",
								fmt.Sprintf("Parameter %s: 'any' operator must be true, got false", paramID),
							)
						}
					} else if strValue, ok := operatorValue.(string); ok {
						if strValue != "" {
							resp.Diagnostics.AddAttributeError(
								path,
								"Invalid 'any' operator value",
								fmt.Sprintf("Parameter %s: 'any' operator string value must be empty, got '%s'", paramID, strValue),
							)
						}
					} else {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid 'any' operator value type",
							fmt.Sprintf("Parameter %s: 'any' operator must have boolean or string value, got %T", paramID, operatorValue),
						)
					}

				case "gte", "lte", "gt", "lt":
					// Validate operator values must be arrays of strings
					if operatorArray, ok := operatorValue.([]interface{}); ok {
						if len(operatorArray) == 0 {
							resp.Diagnostics.AddAttributeError(
								path,
								fmt.Sprintf("Empty '%s' array not allowed", operator),
								fmt.Sprintf("Parameter %s: '%s' operator cannot have empty array", paramID, operator),
							)
						}
						// Validate each version in the array
						for j, ver := range operatorArray {
							if _, ok := ver.(string); !ok {
								resp.Diagnostics.AddAttributeError(
									path,
									fmt.Sprintf("Invalid version format in '%s' operator", operator),
									fmt.Sprintf("Parameter %s: version at index %d in '%s' operator must be string, got %T", paramID, j, operator, ver),
								)
							}
						}
					} else {
						resp.Diagnostics.AddAttributeError(
							path,
							fmt.Sprintf("Invalid '%s' operator value type", operator),
							fmt.Sprintf("Parameter %s: '%s' operator must have array value, got %T", paramID, operator, operatorValue),
						)
					}

				case "ranges":
					// Validate "ranges" operator value must be an array of objects
					if rangesArray, ok := operatorValue.([]interface{}); ok {
						if len(rangesArray) == 0 {
							resp.Diagnostics.AddAttributeError(
								path,
								"Empty 'ranges' array not allowed",
								fmt.Sprintf("Parameter %s: 'ranges' operator cannot have empty array", paramID),
							)
						}
						// Validate each range object in the array
						for j, rangeItem := range rangesArray {
							if rangeObj, ok := rangeItem.(map[string]interface{}); ok {
								if len(rangeObj) == 0 {
									resp.Diagnostics.AddAttributeError(
										path,
										"Empty range object not allowed",
										fmt.Sprintf("Parameter %s: range object at index %d cannot be empty", paramID, j),
									)
									continue
								}
								// Validate each operator in the range object
								for rangeOp, rangeValue := range rangeObj {
									if rangeOp != "gte" && rangeOp != "lte" && rangeOp != "gt" && rangeOp != "lt" {
										resp.Diagnostics.AddAttributeError(
											path,
											"Invalid range operator",
											fmt.Sprintf("Parameter %s: range object at index %d has invalid operator '%s', must be one of [gte, lte, gt, lt]", paramID, j, rangeOp),
										)
										continue
									}
									if _, ok := rangeValue.(string); !ok {
										resp.Diagnostics.AddAttributeError(
											path,
											"Invalid range operator value type",
											fmt.Sprintf("Parameter %s: range object at index %d operator '%s' must have string value, got %T", paramID, j, rangeOp, rangeValue),
										)
									}
								}
							} else {
								resp.Diagnostics.AddAttributeError(
									path,
									"Invalid range format",
									fmt.Sprintf("Parameter %s: range at index %d must be an object, got %T", paramID, j, rangeItem),
								)
							}
						}
					} else {
						resp.Diagnostics.AddAttributeError(
							path,
							"Invalid 'ranges' operator value type",
							fmt.Sprintf("Parameter %s: 'ranges' operator must have array value, got %T", paramID, operatorValue),
						)
					}
				}
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for package_versions",
				fmt.Sprintf("Parameter %s: value must be an object with constraint operators, got %T", paramID, value),
			)
		}

	case "package_type":
		// Should be a string with valid package type
		if strValue, ok := value.(string); ok {
			validTypes := []string{"npm", "PyPI", "Maven", "Go", "NuGet", "Conan", "Gems", "Gradle", "Cargo"}
			valid := false
			for _, validType := range validTypes {
				if strValue == validType {
					valid = true
					break
				}
			}
			if !valid {
				resp.Diagnostics.AddAttributeError(
					path,
					"Invalid package type",
					fmt.Sprintf("Parameter %s: value must be one of %v, got '%s'", paramID, validTypes, strValue),
				)
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for package_type",
				fmt.Sprintf("Parameter %s: value must be a string, got %T", paramID, value),
			)
		}

	case "package_name", "cve_name":
		// Should be a non-empty string
		if strValue, ok := value.(string); ok {
			if strings.TrimSpace(strValue) == "" {
				resp.Diagnostics.AddAttributeError(
					path,
					"Empty string not allowed",
					fmt.Sprintf("Parameter %s: value cannot be empty", paramID),
				)
			}
			// Additional validation for CVE format
			if paramID == "cve_name" {
				cvePattern := `^CVE-\d{4}-\d{4,}$`
				if matched, _ := regexp.MatchString(cvePattern, strValue); !matched {
					resp.Diagnostics.AddAttributeError(
						path,
						"Invalid CVE format",
						fmt.Sprintf("Parameter %s: value must be in format CVE-YYYY-NNNN (e.g., CVE-2021-45105), got '%s'", paramID, strValue),
					)
				}
			}
		} else {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid value type for string parameter",
				fmt.Sprintf("Parameter %s: value must be a string, got %T", paramID, value),
			)
		}

	default:
		// For unknown param_ids, accept any type but warn
		// This allows for future extensibility without breaking existing configs
	}
}

func (v paramValuesJSONValidator) validateRequiredParams(path path.Path, conditionTemplateID string, providedParams map[string]bool, resp *validator.StringResponse) {
	allowedParams, exists := conditionTemplateParams[conditionTemplateID]
	if !exists {
		return // Should be caught by the initial check, but as a fallback
	}

	// Special validation for condition templates that require exactly one parameter
	switch conditionTemplateID {
	case "CVEName":
		// CVEName must have exactly one parameter: cve_name
		if len(providedParams) != 1 {
			resp.Diagnostics.AddAttributeError(
				path,
				"Invalid parameter count for CVEName",
				fmt.Sprintf("condition_template_id 'CVEName' must have exactly 1 parameter, got %d", len(providedParams)),
			)
			return
		}
		if !providedParams["cve_name"] {
			resp.Diagnostics.AddAttributeError(
				path,
				"Missing required parameter",
				"Parameter 'cve_name' is required for condition_template_id 'CVEName'",
			)
		}
	case "BannedLabels", "AllowedLabels":
		// These must have exactly one parameter: list_of_labels
		if len(providedParams) != 1 {
			resp.Diagnostics.AddAttributeError(
				path,
				fmt.Sprintf("Invalid parameter count for %s", conditionTemplateID),
				fmt.Sprintf("condition_template_id '%s' must have exactly 1 parameter, got %d", conditionTemplateID, len(providedParams)),
			)
			return
		}
		if !providedParams["list_of_labels"] {
			resp.Diagnostics.AddAttributeError(
				path,
				"Missing required parameter",
				fmt.Sprintf("Parameter 'list_of_labels' is required for condition_template_id '%s'", conditionTemplateID),
			)
		}
	case "OpenSSF":
		// OpenSSF requires both parameters
		requiredParams := []string{"list_of_scorecard_checks", "block_in_case_check_value_is_missing"}
		for _, requiredParam := range requiredParams {
			if !providedParams[requiredParam] {
				resp.Diagnostics.AddAttributeError(
					path,
					"Missing required parameter",
					fmt.Sprintf("Parameter '%s' is required for condition_template_id 'OpenSSF'", requiredParam),
				)
			}
		}
	case "SpecificVersions":
		// SpecificVersions requires all three parameters
		requiredParams := []string{"package_type", "package_name", "package_versions"}
		for _, requiredParam := range requiredParams {
			if !providedParams[requiredParam] {
				resp.Diagnostics.AddAttributeError(
					path,
					"Missing required parameter",
					fmt.Sprintf("Parameter '%s' is required for condition_template_id 'SpecificVersions'", requiredParam),
				)
			}
		}
	case "AllowedLicenses", "BannedLicenses":
		// These require at least list_of_package_licenses, multiple_license_permissive_approach is optional
		if !providedParams["list_of_package_licenses"] {
			resp.Diagnostics.AddAttributeError(
				path,
				"Missing required parameter",
				fmt.Sprintf("Parameter 'list_of_package_licenses' is required for condition_template_id '%s'", conditionTemplateID),
			)
		}
	case "CVECVSSRange":
		// CVECVSSRange requires at least vulnerability_cvss_score_range
		if !providedParams["vulnerability_cvss_score_range"] {
			resp.Diagnostics.AddAttributeError(
				path,
				"Missing required parameter",
				"Parameter 'vulnerability_cvss_score_range' is required for condition_template_id 'CVECVSSRange'",
			)
		}
	case "isImmature":
		// isImmature requires at least package_age_days, vulnerability_cvss_score is optional
		if !providedParams["package_age_days"] {
			resp.Diagnostics.AddAttributeError(
				path,
				"Missing required parameter",
				"Parameter 'package_age_days' is required for condition_template_id 'isImmature'",
			)
		}
	default:
		// For other condition templates, check that all required parameters are provided
		for _, allowedParam := range allowedParams {
			if !providedParams[allowedParam] {
				resp.Diagnostics.AddAttributeError(
					path,
					"Missing required parameter",
					fmt.Sprintf("Parameter '%s' is required for condition_template_id '%s' but not provided in param_values.", allowedParam, conditionTemplateID),
				)
			}
		}
	}
}

func validateParamValuesJSON() validator.String {
	return paramValuesJSONValidator{}
}

// transformSpecificVersionsConstraints converts object format to API array format for SpecificVersions
func transformSpecificVersionsConstraints(userVersions interface{}) interface{} {
	// Handle object format with constraint operators
	if versionObj, ok := userVersions.(map[string]interface{}); ok {
		var transformedArray []interface{}

		// Handle "any" operator first (should be alone)
		if any, hasAny := versionObj["any"]; hasAny {
			// Convert any=true or any="" to API format
			if boolValue, ok := any.(bool); ok && boolValue {
				return []interface{}{map[string]interface{}{"any": ""}}
			} else if strValue, ok := any.(string); ok && strValue == "" {
				return []interface{}{map[string]interface{}{"any": ""}}
			}
		}

		// Handle "equals" operator - convert to "in" for API
		if equals, hasEquals := versionObj["equals"]; hasEquals {
			if equalsArray, ok := equals.([]interface{}); ok {
				transformedArray = append(transformedArray, map[string]interface{}{
					"in": equalsArray,
				})
			}
		}

		// Handle simple operators: gte, lte, gt, lt
		for _, operator := range []string{"gte", "lte", "gt", "lt"} {
			if values, hasOperator := versionObj[operator]; hasOperator {
				if valuesArray, ok := values.([]interface{}); ok {
					for _, value := range valuesArray {
						transformedArray = append(transformedArray, map[string]interface{}{
							operator: value,
						})
					}
				}
			}
		}

		// Handle "ranges" operator
		if ranges, hasRanges := versionObj["ranges"]; hasRanges {
			if rangesArray, ok := ranges.([]interface{}); ok {
				for _, rangeItem := range rangesArray {
					if rangeObj, ok := rangeItem.(map[string]interface{}); ok {
						// Pass through the range object as-is
						transformedArray = append(transformedArray, rangeObj)
					}
				}
			}
		}

		return transformedArray
	}

	// If not an object, return as-is
	return userVersions
}

// convertAPIArrayToUserObject converts API array format back to user's object format
func convertAPIArrayToUserObject(apiValue interface{}) interface{} {
	// Handle array format from API
	if apiArray, ok := apiValue.([]interface{}); ok {
		userObj := make(map[string]interface{})
		var ranges []interface{}

		// Process each constraint in the API array
		for _, constraint := range apiArray {
			if constraintObj, ok := constraint.(map[string]interface{}); ok {
				// Check if it's a simple constraint (single operator) or range constraint (multiple operators)
				if len(constraintObj) == 1 {
					// Simple constraint with single operator
					for operator, value := range constraintObj {
						switch operator {
						case "in":
							// Convert "in" back to "equals"
							userObj["equals"] = value
						case "any":
							// Handle any operator
							userObj["any"] = true
						case "gte", "lte", "gt", "lt":
							// Add to the respective operator array
							if existingArray, exists := userObj[operator]; exists {
								if existingSlice, ok := existingArray.([]interface{}); ok {
									userObj[operator] = append(existingSlice, value)
								}
							} else {
								userObj[operator] = []interface{}{value}
							}
						}
					}
				} else {
					// Range constraint with multiple operators
					ranges = append(ranges, constraintObj)
				}
			}
		}

		// Add ranges if any exist
		if len(ranges) > 0 {
			userObj["ranges"] = ranges
		}

		return userObj
	}

	// If not an array, return as-is
	return apiValue
}

// OpenSSF scorecard check name mappings - allows users to use descriptive names
var openSSFCheckNameMappings = map[string]string{
	// User-friendly name -> Actual API name (all 16 checks from API)
	"aggregated_score":    "Aggregated score",
	"binary_artifacts":    "Binary-Artifacts",
	"branch_protection":   "Branch-Protection",
	"cii_best_practices":  "CII-Best-Practices",
	"code_review":         "Code-Review",
	"dangerous_workflow":  "Dangerous-Workflow",
	"fuzzing":             "Fuzzing",
	"license":             "License",
	"maintained":          "Maintained",
	"packaging":           "Packaging",
	"pinned_dependencies": "Pinned-Dependencies",
	"sast":                "SAST",
	"security_policy":     "Security-Policy",
	"signed_releases":     "Signed-Releases",
	"token_permissions":   "Token-Permissions",
	"vulnerabilities":     "Vulnerabilities",
}

// mapOpenSSFCheckName converts user-friendly names to actual API names
func mapOpenSSFCheckName(userFriendlyName string) string {
	// First try exact match (case-insensitive)
	lowerName := strings.ToLower(userFriendlyName)
	if apiName, exists := openSSFCheckNameMappings[lowerName]; exists {
		return apiName
	}

	// If no mapping found, return the original name (might be the actual API name)
	return userFriendlyName
}

// reverseMapOpenSSFCheckName maps API check names back to user-friendly names
func reverseMapOpenSSFCheckName(apiName string) string {
	// Create reverse mapping from the original mapping
	reverseMap := map[string]string{
		"Aggregated score":    "aggregated_score",
		"Binary-Artifacts":    "binary_artifacts",
		"Branch-Protection":   "branch_protection",
		"CII-Best-Practices":  "cii_best_practices",
		"Code-Review":         "code_review",
		"Dangerous-Workflow":  "dangerous_workflow",
		"Fuzzing":             "fuzzing",
		"License":             "license",
		"Maintained":          "maintained",
		"Packaging":           "packaging",
		"Pinned-Dependencies": "pinned_dependencies",
		"SAST":                "sast",
		"Security-Policy":     "security_policy",
		"Signed-Releases":     "signed_releases",
		"Token-Permissions":   "token_permissions",
		"Vulnerabilities":     "vulnerabilities",
	}

	if userFriendlyName, exists := reverseMap[apiName]; exists {
		return userFriendlyName
	}

	// If not found, return the original name (fallback)
	return apiName
}

var _ resource.Resource = &CustomCurationConditionResource{}

type CustomCurationConditionResource struct {
	util.JFrogResource
}

func NewCustomCurationConditionResource() resource.Resource {
	return &CustomCurationConditionResource{
		JFrogResource: util.JFrogResource{
			TypeName:              "xray_custom_curation_condition",
			ValidXrayVersion:      "3.116.0",
			CatalogHealthRequired: true,
		},
	}
}

type CustomCurationConditionResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	ConditionTemplateID types.String `tfsdk:"condition_template_id"`
	ParamValues         types.String `tfsdk:"param_values"`
}

type ParamValueAPIModel struct {
	ParamID string      `json:"param_id"`
	Value   interface{} `json:"value"`
}

type CustomCurationConditionAPIModel struct {
	ID                  string               `json:"id,omitempty"`
	Name                string               `json:"name"`
	ConditionTemplateID string               `json:"condition_template_id"`
	ParamValues         []ParamValueAPIModel `json:"param_values"`
	IsCustom            bool                 `json:"is_custom,omitempty"`
	CreatedBy           string               `json:"created_by,omitempty"`
	CreatedAt           string               `json:"created_at,omitempty"`
	UpdatedBy           string               `json:"updated_by,omitempty"`
	UpdatedAt           string               `json:"updated_at,omitempty"`
	RiskType            string               `json:"risk_type,omitempty"`
	SupportedPkgTypes   []string             `json:"supported_pkg_types,omitempty"`
}

const (
	CustomCurationConditionEndpoint = "xray/api/v1/curation/conditions"
)

func (r *CustomCurationConditionResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "xray_custom_curation_condition"
}

func (r *CustomCurationConditionResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The ID of the condition, used as path parameter when updating or deleting the condition and when referring to it in a policy.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the condition.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"condition_template_id": schema.StringAttribute{
				Required:    true,
				Description: "One of the IDs of the supported condition templates returned by the list condition templates API.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.OneOf(
						"OpenSSF",
						"BannedLabels",
						"AllowedLabels",
						"SpecificVersions",
						"AllowedLicenses",
						"BannedLicenses",
						"CVECVSSRange",
						"isImmature",
						"CVEName",
					),
				},
			},
			"param_values": schema.StringAttribute{
				Required:    true,
				Description: "JSON array of parameter values. Each parameter should be an object with param_id and value fields. All required parameters must be explicitly provided. For EPSS parameter, value should be an object with either 'percentile' (0-100, max 2 decimal digits) or 'score' (0.0-1.0) property. For SpecificVersions condition template: all three parameters (package_type, package_name, package_versions) must be specified. Supported package_versions format: object with operators like {\"equals\": [\"1.0.0\", \"1.1.0\"], \"gte\": [\"2.0.0\", \"3.0.0\"], \"lte\": [\"4.0.0\"], \"ranges\": [{\"gte\": \"1.0.0\", \"lte\": \"2.0.0\"}], \"any\": true}. The 'equals' creates one constraint with multiple values, while 'gte', 'lte', 'gt', 'lt' create separate constraints for each array value. Only 'equals' and 'any' can appear once. Example: '[{\"param_id\":\"package_type\",\"value\":\"Maven\"},{\"param_id\":\"package_name\",\"value\":\"log4j-core\"},{\"param_id\":\"package_versions\",\"value\":{\"any\":true}}]'",
				Validators: []validator.String{
					validateParamValuesJSON(),
				},
			},
		},
		MarkdownDescription: "Provides an Xray custom curation condition resource. This resource allows you to create, read, update, and delete custom curation conditions in Xray. See [JFrog Curation REST APIs](https://jfrog.com/help/r/jfrog-rest-apis/create-custom-curation-condition)  [Official documentation](https://jfrog.com/help/r/jfrog-security-user-guide/products/curation/configure-curation/create-custom-conditions) for more details. \n\n" +
			"~> Requires JFrog Catalog service to be available.",
	}
}

func (r *CustomCurationConditionResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	providerData := req.ProviderData.(util.ProviderMetadata)
	r.ProviderData = &providerData

	// Perform catalog health check if this resource requires it
	err := r.JFrogResource.ValidateCatalogHealth(&providerData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Catalog Health Check Failed",
			fmt.Sprintf("Resource requires catalog functionality but catalog health check failed: %s", err.Error()),
		)
		return
	}
}

func (r *CustomCurationConditionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Call the Xray version validation from the embedded JFrogResource
	r.JFrogResource.ValidateXrayConfig(ctx, req, resp)
}

func (plan *CustomCurationConditionResourceModel) toAPIModel(ctx context.Context, condition *CustomCurationConditionAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	condition.Name = plan.Name.ValueString()
	condition.ConditionTemplateID = plan.ConditionTemplateID.ValueString()

	// Convert param_values from JSON string to API model
	var paramValues []ParamValueAPIModel
	if !plan.ParamValues.IsNull() && !plan.ParamValues.IsUnknown() {
		jsonStr := plan.ParamValues.ValueString()

		// Parse JSON string
		var paramList []map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &paramList); err != nil {
			diags.AddError("Invalid JSON", fmt.Sprintf("param_values must be valid JSON: %s", err.Error()))
			return diags
		}

		// Note: No automatic default addition to avoid "inconsistent result" errors
		// Users must explicitly provide all required parameters

		// Process each parameter
		for _, paramObj := range paramList {
			paramID, ok := paramObj["param_id"].(string)
			if !ok {
				diags.AddError("Invalid param_id", "param_id must be a string")
				continue
			}

			value := paramObj["value"]

			// Convert value based on parameter type
			var apiValue interface{}
			switch paramID {
			case "list_of_scorecard_checks":
				// Handle map of check names to scores
				if valueMap, ok := value.(map[string]interface{}); ok {
					var checks []map[string]interface{}
					for checkName, checkScore := range valueMap {
						// Map user-friendly name to actual API name
						apiCheckName := mapOpenSSFCheckName(checkName)
						checks = append(checks, map[string]interface{}{
							"checkName":  apiCheckName,
							"checkValue": checkScore,
						})
					}
					apiValue = checks
				} else {
					diags.AddError("Invalid scorecard checks", "list_of_scorecard_checks value must be a map")
					continue
				}
			case "apply_only_if_fix_is_available", "multiple_license_permissive_approach", "block_in_case_check_value_is_missing", "do_not_apply_for_already_existing_vulnerabilities":
				// Handle boolean parameters
				if boolVal, ok := value.(bool); ok {
					apiValue = boolVal
				} else {
					diags.AddError("Invalid boolean value", fmt.Sprintf("%s must be a boolean", paramID))
					continue
				}
			case "package_age_days":
				// Handle integer parameters
				if intVal, ok := value.(float64); ok {
					apiValue = int(intVal)
				} else {
					diags.AddError("Invalid integer value", fmt.Sprintf("%s must be an integer", paramID))
					continue
				}
			case "vulnerability_cvss_score":
				// Handle float parameters (with one decimal digit precision)
				if floatVal, ok := value.(float64); ok {
					apiValue = floatVal
				} else if intVal, ok := value.(int); ok {
					apiValue = float64(intVal)
				} else {
					diags.AddError("Invalid numeric value", fmt.Sprintf("%s must be a number", paramID))
					continue
				}
			case "epss":
				// Handle EPSS object parameter - transform from user format to API format
				if objVal, ok := value.(map[string]interface{}); ok {
					// Transform from user format {percentile: 95} or {score: 0.7}
					// to API format {field_name: "percentile", value: 95}
					if percentileVal, hasPercentile := objVal["percentile"]; hasPercentile {
						apiValue = map[string]interface{}{
							"field_name": "percentile",
							"value":      percentileVal,
						}
					} else if scoreVal, hasScore := objVal["score"]; hasScore {
						apiValue = map[string]interface{}{
							"field_name": "score",
							"value":      scoreVal,
						}
					} else {
						diags.AddError("Invalid EPSS format", "EPSS object must contain either 'percentile' or 'score' property")
						continue
					}
				} else {
					diags.AddError("Invalid object value", fmt.Sprintf("%s must be an object with either 'percentile' or 'score' property", paramID))
					continue
				}
			case "vulnerability_cvss_score_range", "list_of_package_licenses", "list_of_labels":
				// Handle array parameters
				if arrayVal, ok := value.([]interface{}); ok {
					apiValue = arrayVal
				} else {
					diags.AddError("Invalid array value", fmt.Sprintf("%s must be an array", paramID))
					continue
				}
			case "package_versions":
				// For SpecificVersions condition template, transform "equals" to "in" for API
				// For other condition templates, use transformation logic
				if condition.ConditionTemplateID == "SpecificVersions" {
					apiValue = transformSpecificVersionsConstraints(value)
				} else {
					// package_versions should only be used with SpecificVersions, but pass through as-is if encountered
					apiValue = value
				}
			default:
				// Default to string for unknown parameters
				apiValue = fmt.Sprintf("%v", value)
			}

			paramValue := ParamValueAPIModel{
				ParamID: paramID,
				Value:   apiValue,
			}
			paramValues = append(paramValues, paramValue)
		}
	}

	condition.ParamValues = paramValues
	return diags
}

func (plan *CustomCurationConditionResourceModel) fromAPIModel(ctx context.Context, condition *CustomCurationConditionAPIModel) diag.Diagnostics {
	var diags diag.Diagnostics

	plan.ID = types.StringValue(condition.ID)
	plan.Name = types.StringValue(condition.Name)
	plan.ConditionTemplateID = types.StringValue(condition.ConditionTemplateID)

	// Convert param_values from API model to JSON string (preserving user's original format)
	var paramList []map[string]interface{}
	for _, param := range condition.ParamValues {
		paramObj := map[string]interface{}{
			"param_id": param.ParamID,
		}

		// Convert API response back to user's original format first
		var convertedValue interface{}
		switch param.ParamID {
		case "list_of_scorecard_checks":
			// Convert API format back to user-friendly map
			if checks, ok := param.Value.([]interface{}); ok {
				userFriendlyMap := make(map[string]interface{})
				for _, check := range checks {
					if checkMap, ok := check.(map[string]interface{}); ok {
						checkName := checkMap["checkName"].(string)
						checkValue := checkMap["checkValue"]

						// Map API name back to user-friendly name
						userFriendlyName := reverseMapOpenSSFCheckName(checkName)
						userFriendlyMap[userFriendlyName] = checkValue
					}
				}
				convertedValue = userFriendlyMap
			} else {
				convertedValue = param.Value
			}
		case "epss":
			// Transform from API format {field_name: "score", value: 0.7}
			// back to user format {score: 0.7} or {percentile: 95}
			if epssObj, ok := param.Value.(map[string]interface{}); ok {
				if fieldName, hasFieldName := epssObj["field_name"]; hasFieldName {
					if epssValue, hasValue := epssObj["value"]; hasValue {
						userEpssObj := make(map[string]interface{})
						userEpssObj[fieldName.(string)] = epssValue
						convertedValue = userEpssObj
					} else {
						convertedValue = param.Value
					}
				} else {
					convertedValue = param.Value
				}
			} else {
				convertedValue = param.Value
			}
		case "package_versions":
			// Convert API array format back to user's object format for SpecificVersions
			// Always convert for SpecificVersions regardless of template ID (to handle API variations)
			convertedValue = convertAPIArrayToUserObject(param.Value)
		default:
			// For all other types, keep as-is
			convertedValue = param.Value
		}

		// Do not filter out any parameters - show the actual API state
		// This prevents inconsistent result errors when users explicitly provide default values

		// Set the converted value
		paramObj["value"] = convertedValue
		paramList = append(paramList, paramObj)
	}

	// Convert to JSON string
	if len(paramList) > 0 {
		jsonBytes, err := json.Marshal(paramList)
		if err != nil {
			diags.AddError("JSON Marshal Error", fmt.Sprintf("Failed to marshal param_values: %s", err.Error()))
		} else {
			plan.ParamValues = types.StringValue(string(jsonBytes))
		}
	} else {
		plan.ParamValues = types.StringValue("[]")
	}

	return diags
}

func (r *CustomCurationConditionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CustomCurationConditionResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var condition CustomCurationConditionAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &condition)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the custom curation condition
	response, err := r.ProviderData.Client.R().
		SetBody(condition).
		SetResult(&condition).
		Post(CustomCurationConditionEndpoint)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating custom curation condition",
			"An unexpected error occurred while creating the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.IsError() {
		resp.Diagnostics.AddError(
			"Error creating custom curation condition",
			"An unexpected error occurred while creating the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+response.String(),
		)
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(plan.fromAPIModel(ctx, &condition)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the refreshed state
	resp.State.Set(ctx, &plan)
}

func (r *CustomCurationConditionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CustomCurationConditionResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the custom curation condition
	var condition CustomCurationConditionAPIModel
	response, err := r.ProviderData.Client.R().
		SetResult(&condition).
		Get(fmt.Sprintf("%s/%s", CustomCurationConditionEndpoint, state.ID.ValueString()))

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading custom curation condition",
			"An unexpected error occurred while reading the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if response.IsError() {
		resp.Diagnostics.AddError(
			"Error reading custom curation condition",
			"An unexpected error occurred while reading the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+response.String(),
		)
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(state.fromAPIModel(ctx, &condition)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CustomCurationConditionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CustomCurationConditionResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var condition CustomCurationConditionAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &condition)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the custom curation condition
	response, err := r.ProviderData.Client.R().
		SetBody(condition).
		SetResult(&condition).
		Put(fmt.Sprintf("%s/%s", CustomCurationConditionEndpoint, plan.ID.ValueString()))

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating custom curation condition",
			"An unexpected error occurred while updating the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.IsError() {
		resp.Diagnostics.AddError(
			"Error updating custom curation condition",
			"An unexpected error occurred while updating the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+response.String(),
		)
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(plan.fromAPIModel(ctx, &condition)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CustomCurationConditionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CustomCurationConditionResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the custom curation condition
	response, err := r.ProviderData.Client.R().
		Delete(fmt.Sprintf("%s/%s", CustomCurationConditionEndpoint, state.ID.ValueString()))

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting custom curation condition",
			"An unexpected error occurred while deleting the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.IsError() && response.StatusCode() != http.StatusNotFound {
		resp.Diagnostics.AddError(
			"Error deleting custom curation condition",
			"An unexpected error occurred while deleting the custom curation condition. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+response.String(),
		)
		return
	}
}

func (r *CustomCurationConditionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Set the ID to the imported resource ID
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
