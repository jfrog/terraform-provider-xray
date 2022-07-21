package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXraySecurityPolicyV2() *schema.Resource {
	var criteriaSchema = map[string]*schema.Schema{
		"min_severity": {
			Type:             schema.TypeString,
			Optional:         true,
			Description:      "The minimum security vulnerability severity that will be impacted by the policy.",
			ValidateDiagFunc: validator.StringInSlice(true, "All Severities", "Critical", "High", "Medium", "Low"),
		},
		"fix_version_dependant": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Default value is `false`. Issues that do not have a fixed version are not generated until a fixed version is available.",
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
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: getPolicySchema(criteriaSchema, commonActionsSchema),
	}
}
