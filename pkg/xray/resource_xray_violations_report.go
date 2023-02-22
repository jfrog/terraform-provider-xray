package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXrayViolationsReport() *schema.Resource {
	var violationsFilterSchema = map[string]*schema.Schema{
		"type": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringInSlice(true, "security", "license", "operational_risk"),
			Description:      "Violation type.",
		},
		"watch_names": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Select Xray watch by names. Only one attribute - 'watch_names' or 'watch_patterns' can be set.",
		},
		"watch_patterns": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Select Xray watch name by patterns. Only one attribute - 'watch_names' or 'watch_patterns' can be set.",
		},
		"component": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Filter by component name, you can use (*) at the beginning or end of a substring as a wildcard.",
		},
		"artifact": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Filter by artifact name, you can use (*) at the beginning or end of a substring as a wildcard.",
		},
		"policy_names": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Select Xray policies by name.",
		},
		"severities": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Risk/severity levels. Allowed values: 'None', 'Low', 'Medium', 'High'.",
		},
		"updated": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"start": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Created from date.",
					},
					"end": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Created to date.",
					},
				},
			},
		},
		"security_filters": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: "Security Filters.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"cve": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validator.StringIsNotEmpty,
						Description:      "CVE.",
					},
					"issue_id": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validator.StringIsNotEmpty,
						Description:      "Issue ID.",
					},
					"cvss_score": {
						Type:        schema.TypeSet,
						Optional:    true,
						MaxItems:    1,
						Description: "CVSS score.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"min_score": {
									Type:         schema.TypeFloat,
									Optional:     true,
									ValidateFunc: validation.FloatBetween(0, 10),
									Description:  "Minimum CVSS score.",
								},
								"max_score": {
									Type:         schema.TypeFloat,
									Optional:     true,
									ValidateFunc: validation.FloatBetween(0, 10),
									Description:  "Maximum CVSS score.",
								},
							},
						},
					},
					"summary_contains": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validator.StringIsNotEmpty,
						Description:      "Vulnerability Summary.",
					},
					"has_remediation": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Whether the issue has a fix or not.",
					},
				},
			},
		},
		"license_filters": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: "Licenses Filters.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"unknown": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Unknown displays the components that Xray could not discover any licenses for.",
					},
					"unrecognized": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Unrecognized displays the components that Xray found licenses for, but these licenses are not Xray recognized licenses.",
					},
					"license_names": {
						Type:        schema.TypeSet,
						Elem:        &schema.Schema{Type: schema.TypeString},
						Set:         schema.HashString,
						Optional:    true,
						Description: "Filter licenses by names.",
					},
					"license_patterns": {
						Type:        schema.TypeSet,
						Elem:        &schema.Schema{Type: schema.TypeString},
						Set:         schema.HashString,
						Optional:    true,
						Description: "Filter licenses by patterns.",
					},
				},
			},
		},
	}

	return &schema.Resource{
		SchemaVersion: 1,
		CreateContext: resourceXrayViolationsReportCreate,
		ReadContext:   resourceXrayReportRead,
		UpdateContext: resourceXrayViolationsReportCreate,
		DeleteContext: resourceXrayReportDelete,
		Description: "Creates Xray Violations report. The Violations report provides you with information on security " +
			"and license violations for each component in the selected scope. Violations information includes " +
			"information such as type of violation, impacted artifacts, and severity.",

		CustomizeDiff: reportResourceDiff,

		Schema: getReportSchema(violationsFilterSchema),
	}
}
