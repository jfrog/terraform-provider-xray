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

		CustomizeDiff: criteriaDiff,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "Name of the policy (must be unique)",
				ValidateDiagFunc: validator.StringIsNotEmpty,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "More verbose description of the policy",
			},
			"type": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Type of the policy",
				ValidateDiagFunc: validator.StringInSlice(true, "Security", "License", "Operational_Risk"),
			},
			"author": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User, who created the policy",
			},
			"created": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation timestamp",
			},
			"modified": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Modification timestamp",
			},
			"rule": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Nested block describing security rule. Described below",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "Name of the rule",
							ValidateDiagFunc: validator.StringIsNotEmpty,
						},
						"priority": {
							Type:             schema.TypeInt,
							Required:         true,
							ValidateDiagFunc: validator.IntAtLeast(1),
							Description:      "Integer describing the rule priority. Must be at least 1",
						},
						"criteria": {
							Type:        schema.TypeSet,
							Required:    true,
							MinItems:    1,
							MaxItems:    1,
							Description: "Nested block describing the criteria for the policy. Described below.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
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
								},
							},
						},
						"actions": {
							Type:        schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "Nested block describing the actions to be applied by the policy. Described below.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"webhooks": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "A list of Xray-configured webhook URLs to be invoked if a violation is triggered.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"mails": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "A list of email addressed that will get emailed when a violation is triggered.",
										Elem: &schema.Schema{
											Type:             schema.TypeString,
											ValidateDiagFunc: validator.IsEmail,
										},
									},
									"block_download": {
										Type:        schema.TypeSet,
										Required:    true,
										MaxItems:    1,
										Description: "Nested block describing artifacts that should be blocked for download if a violation is triggered. Described below.",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"unscanned": {
													Type:        schema.TypeBool,
													Required:    true,
													Description: "Whether or not to block download of artifacts that meet the artifact `filters` for the associated `xray_watch` resource but have not been scanned yet.",
												},
												"active": {
													Type:        schema.TypeBool,
													Required:    true,
													Description: "Whether or not to block download of artifacts that meet the artifact and severity `filters` for the associated `xray_watch` resource.",
												},
											},
										},
									},
									"block_release_bundle_distribution": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     true,
										Description: "Blocks Release Bundle distribution to Edge nodes if a violation is found.",
									},
									"fail_build": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     true,
										Description: "Whether or not the related CI build should be marked as failed if a violation is triggered. This option is only available when the policy is applied to an `xray_watch` resource with a `type` of `builds`.",
									},
									"notify_deployer": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "Sends an email message to component deployer with details about the generated Violations.",
									},
									"notify_watch_recipients": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "Sends an email message to all configured recipients inside a specific watch with details about the generated Violations.",
									},
									"create_ticket_enabled": {
										Type:        schema.TypeBool,
										Optional:    true,
										Default:     false,
										Description: "Create Jira Ticket for this Policy Violation. Requires configured Jira integration.",
									},
									"build_failure_grace_period_in_days": {
										Type:             schema.TypeInt,
										Optional:         true,
										Description:      "Allow grace period for certain number of days. All violations will be ignored during this time. To be used only if `fail_build` is enabled.",
										ValidateDiagFunc: validator.IntAtLeast(0),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
