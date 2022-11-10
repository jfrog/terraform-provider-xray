package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXrayVulnerabilitiesReport() *schema.Resource {
	var vulnerabilitiesFilterSchema = map[string]*schema.Schema{
		"vulnerable_component": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Filter by component name, you can use (*) at the beginning or end of a substring as a wildcard.",
		},
		"impacted_artifact": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Filter by artifact name, you can use (*) at the eginning or end of a substring as a wildcard.",
		},
		"has_remediation": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Whether the issue has a fix or not.", // UI has an option 'All', when the field is empty. Not clear how to make it work with bool.
		},
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
		"severities": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Severity levels. Allowed values: 'Low', 'Medium', 'High', 'Critical'",
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
		"published": {
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
						Description:      "Published from date.",
					},
					"end": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Published to date.",
					},
				},
			},
		},
		"scan_date": {
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
						Description:      "Scanned from date.",
					},
					"end": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Scanned to date.",
					},
				},
			},
		},
	}

	return &schema.Resource{
		SchemaVersion: 1,
		CreateContext: resourceXrayVulnerabilitiesReportCreate,
		ReadContext:   resourceXrayReportRead,
		UpdateContext: resourceXrayVulnerabilitiesReportCreate,
		DeleteContext: resourceXrayReportDelete,
		Description: "Creates Xray Vulnerabilities report. The Vulnerabilities report provides information about " +
			"vulnerabilities in your artifacts, builds, and release bundles. In addition to the information provided in " +
			"the JFrog Platform on each of these entities, the report gives you a wider range of information such as " +
			"vulnerabilities in multiple repositories, builds and release bundles. Criteria such as vulnerable component," +
			" CVE, cvss score, and severity are available in the report.",

		CustomizeDiff: reportResourceDiff,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: getReportSchema(vulnerabilitiesFilterSchema),
	}
}
