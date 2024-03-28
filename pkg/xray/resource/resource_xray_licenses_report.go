package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func ResourceXrayLicensesReport() *schema.Resource {
	var licensesFilterSchema = map[string]*schema.Schema{
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
			Description: "Filter licenses by names. Only one of 'license_names' or 'license_patterns' can be set.",
		},
		"license_patterns": {
			Type:        schema.TypeSet,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Set:         schema.HashString,
			Optional:    true,
			Description: "Filter licenses by patterns. Only one of 'license_names' or 'license_patterns' can be set.",
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
		CreateContext: resourceXrayLicensesReportCreate,
		ReadContext:   resourceXrayReportRead,
		UpdateContext: resourceXrayLicensesReportCreate,
		DeleteContext: resourceXrayReportDelete,
		Description: "Creates Xray License Due Diligence report. The License Due Diligence report provides you with a " +
			"list of components and artifacts and their relevant licenses. This enables you to review and verify that " +
			"the components and artifacts comply with the license requirements. This report provides due diligence " +
			"license related information on each component for a selected scope. Due diligence license information " +
			"includes information such as unknown licenses and unrecognized licenses found in your components.",

		CustomizeDiff: reportResourceDiff,

		Schema: getReportSchema(licensesFilterSchema),
	}
}
