package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXrayOperationalRisksReport() *schema.Resource {
	var operationalRisksFilterSchema = map[string]*schema.Schema{
		"component": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Artifact's component.",
		},
		"artifact": {
			Type:             schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: validator.StringIsNotEmpty,
			Description:      "Artifact name.",
		},
		"risks": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Operational risk level. Allowed values: 'None', 'Low', 'Medium', 'High'.",
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
						Description:      "Scan start date.",
					},
					"end": {
						Type:             schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Scan end date.",
					},
				},
			},
		},
	}

	return &schema.Resource{
		SchemaVersion: 1,
		CreateContext: resourceXrayOperationalRisksReportCreate,
		ReadContext:   resourceXrayReportRead,
		UpdateContext: resourceXrayOperationalRisksReportCreate,
		DeleteContext: resourceXrayReportDelete,
		Description: "Creates Xray Operational Risks report. The Operational Risk report provides you with additional " +
			"data on OSS components that will help you gain insights into the risk level of the components in use, " +
			"such as; EOL, Version Age, Number of New Versions, and so on.  For more information, see " +
			"[Components Operational Risk](https://www.jfrog.com/confluence/display/JFROG/Components+Operational+Risk)",

		CustomizeDiff: reportResourceDiff,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: getReportSchema(operationalRisksFilterSchema),
	}
}
