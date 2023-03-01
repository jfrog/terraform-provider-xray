package xray

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXrayOperationalRiskPolicy() *schema.Resource {

	var criteriaDiff = func(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
		rules := diff.Get("rule").([]interface{})
		if len(rules) == 0 {
			return nil
		}

		criteria := rules[0].(map[string]interface{})["criteria"].(*schema.Set).List()
		if len(criteria) == 0 {
			return nil
		}

		criterion := criteria[0].(map[string]interface{})

		minRisk := criterion["op_risk_min_risk"].(string)
		customCriteria := criterion["op_risk_custom"].([]interface{})

		if len(minRisk) > 0 && len(customCriteria) > 0 {
			return fmt.Errorf("attribute 'op_risk_min_risk' cannot be set together with 'op_risk_custom'")
		}

		return nil
	}

	var criteriaSchema = map[string]*schema.Schema{
		"op_risk_min_risk": {
			Type:             schema.TypeString,
			Optional:         true,
			Description:      "The minimum operational risk that will be impacted by the policy.",
			ValidateDiagFunc: validator.StringInSlice(true, "High", "Medium", "Low"),
		},
		"op_risk_custom": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "Custom Condition",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"use_and_condition": {
						Type:        schema.TypeBool,
						Required:    true,
						Description: "Use 'AND' between conditions (true) or 'OR' condition (false)",
					},
					"is_eol": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Is End-of-Life?",
					},
					"release_date_greater_than_months": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          6,
						Description:      "Release age greater than (in months): 6, 12, 18, 24, 30, or 36",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IntInSlice([]int{6, 12, 18, 24, 30, 36})),
					},
					"newer_versions_greater_than": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          1,
						Description:      "Number of releases since greater than: 1, 2, 3, 4, or 5",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IntInSlice([]int{1, 2, 3, 4, 5})),
					},
					"release_cadence_per_year_less_than": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          1,
						Description:      "Release cadence less than per year: 1, 2, 3, 4, or 5",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IntInSlice([]int{1, 2, 3, 4, 5})),
					},
					"commits_less_than": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          10,
						Description:      "Number of commits less than per year: 10, 25, 50, or 100",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IntInSlice([]int{10, 25, 50, 100})),
					},
					"committers_less_than": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          1,
						Description:      "Number of committers less than per year: 1, 2, 3, 4, or 5",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IntInSlice([]int{1, 2, 3, 4, 5})),
					},
					"risk": {
						Type:             schema.TypeString,
						Optional:         true,
						Default:          "low",
						Description:      "Risk severity: low, medium, high",
						ValidateDiagFunc: validator.StringInSlice(true, "high", "medium", "low"),
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

		CustomizeDiff: criteriaDiff,

		Schema: getPolicySchema(criteriaSchema, commonActionsSchema),
	}
}
