package xray

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func ResourceXraySecurityPolicyV2() *schema.Resource {
	var criteriaSchema = map[string]*schema.Schema{
		"min_severity": {
			Type:             schema.TypeString,
			Optional:         true,
			Description:      "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
			ValidateDiagFunc: validator.StringInSlice(true, "All Severities", "Critical", "High", "Medium", "Low"),
		},
		"fix_version_dependant": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Default value is `false`. Issues that do not have a fixed version are not generated until a fixed version is available. Must be `false` with `malicious_package` enabled.",
		},
		"malicious_package": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Default value is `false`. Generating a violation on a malicious package.",
		},
		"cvss_range": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The CVSS score range to apply to the rule. This is used for a fine-grained control, rather than using the predefined severities. The score range is based on CVSS v3 scoring, and CVSS v2 score is CVSS v3 score is not available.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"from": {
						Type:             schema.TypeFloat,
						Required:         true,
						Description:      "The beginning of the range of CVS scores (from 1-10, float) to flag.",
						ValidateDiagFunc: validation.ToDiagFunc(validation.FloatBetween(0, 10)),
					},
					"to": {
						Type:             schema.TypeFloat,
						Required:         true,
						Description:      "The end of the range of CVS scores (from 1-10, float) to flag. ",
						ValidateDiagFunc: validation.ToDiagFunc(validation.FloatBetween(0, 10)),
					},
				},
			},
		},
		"vulnerability_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    100,
			MinItems:    1,
			Description: "Creates policy rules for specific vulnerability IDs that you input. You can add multiple vulnerabilities IDs up to 100. CVEs and Xray IDs are supported. Example - CVE-2015-20107, XRAY-2344",
			Elem: &schema.Schema{
				Type: schema.TypeString,
				ValidateDiagFunc: validation.ToDiagFunc(
					validation.StringMatch(regexp.MustCompile(`(CVE\W*\d{4}\W+\d{4,}|XRAY-\d{4,})`), "invalid Vulnerability, must be a valid CVE or Xray ID, example CVE-2021-12345, XRAY-1234"),
				),
			},
		},
		"exposures": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "Works only with JFrog Advanced Security license. Creates policy rules for specific exposures.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"min_severity": {
						Type:             schema.TypeString,
						Optional:         true,
						Default:          "All Severities",
						Description:      "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
						ValidateDiagFunc: validator.StringInSlice(true, "All Severities", "Critical", "High", "Medium", "Low"),
					},
					"secrets": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     true,
						Description: "Secrets exposures.",
					},
					"applications": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     true,
						Description: "Applications exposures.",
					},
					"services": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     true,
						Description: "Services exposures.",
					},
					"iac": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     true,
						Description: "Iac exposures.",
					},
				},
			},
		},
	}

	return &schema.Resource{
		SchemaVersion: 1,
		CreateContext: resourceXrayPolicyCreate,
		ReadContext:   resourceXrayPolicyRead,
		UpdateContext: resourceXrayPolicyUpdate,
		DeleteContext: resourceXrayPolicyDelete,
		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",

		Importer: &schema.ResourceImporter{
			StateContext: resourceImporterForProjectKey,
		},
		CustomizeDiff: criteriaMaliciousPkgDiff,
		Schema:        getPolicySchema(criteriaSchema, commonActionsSchema),
	}
}

var criteriaMaliciousPkgDiff = func(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
	rules := diff.Get("rule").(*schema.Set).List()
	if len(rules) == 0 {
		return nil
	}
	criteria := rules[0].(map[string]interface{})["criteria"].(*schema.Set).List()
	if len(criteria) == 0 {
		return nil
	}

	criterion := criteria[0].(map[string]interface{})
	// fixVersionDependant can't be set with malicious_package
	fixVersionDependant := criterion["fix_version_dependant"].(bool)
	// Only one of the following:
	minSeverity := criterion["min_severity"].(string)
	cvssRange := criterion["cvss_range"].([]interface{})
	vulnerabilityIDs := criterion["vulnerability_ids"].(*schema.Set).List()
	maliciousPackage := criterion["malicious_package"].(bool)
	exposures := criterion["exposures"].([]interface{})

	if len(exposures) > 0 && maliciousPackage || (len(exposures) > 0 && len(cvssRange) > 0) ||
		(len(exposures) > 0 && len(minSeverity) > 0) || (len(exposures) > 0 && len(vulnerabilityIDs) > 0) {
		return fmt.Errorf("exsposures can't be set together with cvss_range, min_severity, malicious_package and vulnerability_ids")
	}
	// If `malicious_package` is enabled in the UI, `fix_version_dependant` is set to `false` in the UI call.
	// UI itself doesn't have this checkbox at all. We are adding this check to avoid unexpected behavior.
	if maliciousPackage && fixVersionDependant {
		return fmt.Errorf("fix_version_dependant must be set to false if malicious_package is true")
	}
	if (maliciousPackage && len(minSeverity) > 0) || (maliciousPackage && len(cvssRange) > 0) {
		return fmt.Errorf("malicious_package can't be set together with min_severity and/or cvss_range")
	}
	if len(minSeverity) > 0 && len(cvssRange) > 0 {
		return fmt.Errorf("min_severity can't be set together with cvss_range")
	}
	if (len(vulnerabilityIDs) > 0 && maliciousPackage) || (len(vulnerabilityIDs) > 0 && len(minSeverity) > 0) ||
		(len(vulnerabilityIDs) > 0 && len(cvssRange) > 0) || (len(vulnerabilityIDs) > 0 && len(exposures) > 0) {
		return fmt.Errorf("vulnerability_ids can't be set together with with malicious_package, min_severity, cvss_range and exposures")
	}

	return nil
}
