package xray

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
)

var _ resource.Resource = &SecurityPolicyV2Resource{}

func NewSecurityPolicyV2Resource() resource.Resource {
	return &SecurityPolicyV2Resource{
		TypeName: "xray_security_policy",
	}
}

type SecurityPolicyV2Resource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *SecurityPolicyV2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type SecurityPolicyV2ResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	ProjectKey  types.String `tfsdk:"project_key"`
	Type        types.String `tfsdk:"type"`
	Rules       types.Set    `tfsdk:"rule"`
	Author      types.String `tfsdk:"author"`
	Created     types.String `tfsdk:"created"`
	Modified    types.String `tfsdk:"modified"`
}

func (m SecurityPolicyV2ResourceModel) toAPIModel(ctx context.Context, apiModel *PolicyAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	rules := lo.Map(
		m.Rules.Elements(),
		func(elem attr.Value, _ int) PolicyRuleAPIModel {
			attrs := elem.(types.Object).Attributes()

			var criteria *PolicyRuleCriteriaAPIModel
			criteriaElems := attrs["criteria"].(types.Set).Elements()
			if len(criteriaElems) > 0 {
				attrs := criteriaElems[0].(types.Object).Attributes()

				var vulnerabilityIds []string
				d := attrs["vulnerability_ids"].(types.Set).ElementsAs(ctx, &vulnerabilityIds, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var cvssRange *PolicyCVSSRangeAPIModel
				cvssRangeElems := attrs["cvss_range"].(types.List).Elements()
				if len(cvssRangeElems) > 0 {
					attrs := cvssRangeElems[0].(types.Object).Attributes()

					cvssRange = &PolicyCVSSRangeAPIModel{
						From: attrs["from"].(types.Float64).ValueFloat64Pointer(),
						To:   attrs["to"].(types.Float64).ValueFloat64Pointer(),
					}
				}

				var exposures *PolicyExposuresAPIModel
				exposuresElem := attrs["exposures"].(types.List).Elements()
				if len(exposuresElem) > 0 {
					attrs := exposuresElem[0].(types.Object).Attributes()

					exposures = &PolicyExposuresAPIModel{
						MinSeverity:  attrs["min_severity"].(types.String).ValueStringPointer(),
						Secrets:      attrs["secrets"].(types.Bool).ValueBoolPointer(),
						Applications: attrs["applications"].(types.Bool).ValueBoolPointer(),
						Services:     attrs["services"].(types.Bool).ValueBoolPointer(),
						Iac:          attrs["iac"].(types.Bool).ValueBoolPointer(),
					}
				}

				var packageVersions []string
				d = attrs["package_versions"].(types.Set).ElementsAs(ctx, &packageVersions, false)
				if d.HasError() {
					diags.Append(d...)
				}

				criteria = &PolicyRuleCriteriaAPIModel{
					MinimumSeverity:     attrs["min_severity"].(types.String).ValueString(),
					CVSSRange:           cvssRange,
					FixVersionDependant: attrs["fix_version_dependant"].(types.Bool).ValueBool(),
					ApplicableCVEsOnly:  attrs["applicable_cves_only"].(types.Bool).ValueBool(),
					MaliciousPackage:    attrs["malicious_package"].(types.Bool).ValueBool(),
					VulnerabilityIds:    vulnerabilityIds,
					Exposures:           exposures,
					PackageName:         attrs["package_name"].(types.String).ValueString(),
					PackageType:         attrs["package_type"].(types.String).ValueString(),
					PackageVersions:     packageVersions,
				}
			}

			actions := PolicyRuleActionsAPIModel{}
			actionsElems := attrs["actions"].(types.Set).Elements()
			if len(actionsElems) > 0 {
				attrs := actionsElems[0].(types.Object).Attributes()

				var webhooks []string
				d := attrs["webhooks"].(types.Set).ElementsAs(ctx, &webhooks, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var mails []string
				d = attrs["mails"].(types.Set).ElementsAs(ctx, &mails, false)
				if d.HasError() {
					diags.Append(d...)
				}

				blockDownload := BlockDownloadSettingsAPIModel{}
				blockDownloadElems := attrs["block_download"].(types.Set).Elements()
				if len(blockDownloadElems) > 0 {
					attrs := blockDownloadElems[0].(types.Object).Attributes()

					blockDownload.Unscanned = attrs["unscanned"].(types.Bool).ValueBool()
					blockDownload.Active = attrs["active"].(types.Bool).ValueBool()
				}

				actions.Webhooks = webhooks
				actions.Mails = mails
				actions.FailBuild = attrs["fail_build"].(types.Bool).ValueBool()
				actions.BlockDownload = blockDownload
				actions.BlockReleaseBundleDistribution = attrs["block_release_bundle_distribution"].(types.Bool).ValueBool()
				actions.BlockReleaseBundlePromotion = attrs["block_release_bundle_promotion"].(types.Bool).ValueBool()
				actions.NotifyWatchRecipients = attrs["notify_watch_recipients"].(types.Bool).ValueBool()
				actions.NotifyDeployer = attrs["notify_deployer"].(types.Bool).ValueBool()
				actions.CreateJiraTicketEnabled = attrs["create_ticket_enabled"].(types.Bool).ValueBool()
				actions.FailureGracePeriodDays = attrs["build_failure_grace_period_in_days"].(types.Int64).ValueInt64()
				// actions.CustomSeverity = attrs["custom_severity"].(types.String).ValueString()
			}

			return PolicyRuleAPIModel{
				Name:     attrs["name"].(types.String).ValueString(),
				Priority: attrs["priority"].(types.Int64).ValueInt64(),
				Criteria: criteria,
				Actions:  actions,
			}
		},
	)

	*apiModel = PolicyAPIModel{
		Name:        m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Type:        m.Type.ValueString(),
		Rules:       &rules,
	}

	return diags
}

var cvssRangeAttrType = map[string]attr.Type{
	"from": types.Float64Type,
	"to":   types.Float64Type,
}

var cvssRangeElementType = types.ObjectType{
	AttrTypes: cvssRangeAttrType,
}

var exposuresAttrType = map[string]attr.Type{
	"min_severity": types.StringType,
	"secrets":      types.BoolType,
	"applications": types.BoolType,
	"services":     types.BoolType,
	"iac":          types.BoolType,
}

var exposuresElementType = types.ObjectType{
	AttrTypes: exposuresAttrType,
}

var criteriaAttrTypes = map[string]attr.Type{
	"min_severity":          types.StringType,
	"fix_version_dependant": types.BoolType,
	"applicable_cves_only":  types.BoolType,
	"malicious_package":     types.BoolType,
	"cvss_range":            types.ListType{ElemType: cvssRangeElementType},
	"vulnerability_ids":     types.SetType{ElemType: types.StringType},
	"exposures":             types.ListType{ElemType: exposuresElementType},
	"package_name":          types.StringType,
	"package_type":          types.StringType,
	"package_versions":      types.SetType{ElemType: types.StringType},
}

var criteriaSetElementType = types.ObjectType{
	AttrTypes: criteriaAttrTypes,
}

var blockDownloadAttrTypes = map[string]attr.Type{
	"unscanned": types.BoolType,
	"active":    types.BoolType,
}

var blockDownloadElementType = types.ObjectType{
	AttrTypes: blockDownloadAttrTypes,
}

var actionsAttrTypes = map[string]attr.Type{
	"webhooks":                           types.SetType{ElemType: types.StringType},
	"mails":                              types.SetType{ElemType: types.StringType},
	"block_download":                     types.SetType{ElemType: blockDownloadElementType},
	"block_release_bundle_distribution":  types.BoolType,
	"block_release_bundle_promotion":     types.BoolType,
	"fail_build":                         types.BoolType,
	"notify_deployer":                    types.BoolType,
	"notify_watch_recipients":            types.BoolType,
	"create_ticket_enabled":              types.BoolType,
	"build_failure_grace_period_in_days": types.Int64Type,
}

var actionsSetElementType = types.ObjectType{
	AttrTypes: actionsAttrTypes,
}

var ruleAttrTypes = map[string]attr.Type{
	"name":     types.StringType,
	"priority": types.Int64Type,
	"criteria": types.SetType{ElemType: criteriaSetElementType},
	"actions":  types.SetType{ElemType: actionsSetElementType},
}

var ruleSetElementType = types.ObjectType{
	AttrTypes: ruleAttrTypes,
}

func (m *SecurityPolicyV2ResourceModel) fromAPIModel(ctx context.Context, apiModel PolicyAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	rules := lo.Map(
		*apiModel.Rules,
		func(rule PolicyRuleAPIModel, _ int) attr.Value {
			criteriaSet := types.SetNull(criteriaSetElementType)
			if rule.Criteria != nil {
				minimumSeverity := types.StringNull()
				if rule.Criteria.MinimumSeverity != "" {
					minimumSeverity = types.StringValue(rule.Criteria.MinimumSeverity)
				}

				cvssRangeList := types.ListNull(cvssRangeElementType)
				if rule.Criteria.CVSSRange != nil {
					cvssRange, d := types.ObjectValue(
						cvssRangeAttrType,
						map[string]attr.Value{
							"from": types.Float64PointerValue(rule.Criteria.CVSSRange.From),
							"to":   types.Float64PointerValue(rule.Criteria.CVSSRange.To),
						},
					)
					if d.HasError() {
						diags.Append(d...)
					}

					cr, d := types.ListValue(
						cvssRangeElementType,
						[]attr.Value{cvssRange},
					)
					if d.HasError() {
						diags.Append(d...)
					}

					cvssRangeList = cr
				}

				vulnerabilityIDs, d := types.SetValueFrom(ctx, types.StringType, rule.Criteria.VulnerabilityIds)
				if d.HasError() {
					diags.Append(d...)
				}

				exposuresList := types.ListNull(exposuresElementType)
				if rule.Criteria.Exposures != nil {
					exposures, d := types.ObjectValue(
						exposuresAttrType,
						map[string]attr.Value{
							"min_severity": types.StringPointerValue(rule.Criteria.Exposures.MinSeverity),
							"secrets":      types.BoolPointerValue(rule.Criteria.Exposures.Secrets),
							"applications": types.BoolPointerValue(rule.Criteria.Exposures.Applications),
							"services":     types.BoolPointerValue(rule.Criteria.Exposures.Services),
							"iac":          types.BoolPointerValue(rule.Criteria.Exposures.Iac),
						},
					)
					if d.HasError() {
						diags.Append(d...)
					}

					es, d := types.ListValue(
						exposuresElementType,
						[]attr.Value{exposures},
					)
					if d.HasError() {
						diags.Append(d...)
					}

					exposuresList = es
				}

				packageName := types.StringNull()
				if rule.Criteria.PackageName != "" {
					packageName = types.StringValue(rule.Criteria.PackageName)
				}

				packageType := types.StringNull()
				if rule.Criteria.PackageType != "" {
					packageType = types.StringValue(rule.Criteria.PackageType)
				}

				packageVersions, d := types.SetValueFrom(ctx, types.StringType, rule.Criteria.PackageVersions)
				if d.HasError() {
					diags.Append(d...)
				}

				criteria, d := types.ObjectValue(
					criteriaAttrTypes,
					map[string]attr.Value{
						"min_severity":          minimumSeverity,
						"fix_version_dependant": types.BoolValue(rule.Criteria.FixVersionDependant),
						"applicable_cves_only":  types.BoolValue(rule.Criteria.ApplicableCVEsOnly),
						"malicious_package":     types.BoolValue(rule.Criteria.MaliciousPackage),
						"cvss_range":            cvssRangeList,
						"vulnerability_ids":     vulnerabilityIDs,
						"exposures":             exposuresList,
						"package_name":          packageName,
						"package_type":          packageType,
						"package_versions":      packageVersions,
					},
				)
				if d.HasError() {
					diags.Append(d...)
				}
				cs, d := types.SetValue(
					criteriaSetElementType,
					[]attr.Value{criteria},
				)
				if d.HasError() {
					diags.Append(d...)
				}

				criteriaSet = cs
			}

			webhooks, d := types.SetValueFrom(ctx, types.StringType, rule.Actions.Webhooks)
			if d.HasError() {
				diags.Append(d...)
			}

			mails, d := types.SetValueFrom(ctx, types.StringType, rule.Actions.Mails)
			if d.HasError() {
				diags.Append(d...)
			}

			blockDownload, d := types.ObjectValue(
				blockDownloadAttrTypes,
				map[string]attr.Value{
					"unscanned": types.BoolValue(rule.Actions.BlockDownload.Unscanned),
					"active":    types.BoolValue(rule.Actions.BlockDownload.Active),
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}
			blockDownloadSet, d := types.SetValue(
				blockDownloadElementType,
				[]attr.Value{blockDownload},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			actions, d := types.ObjectValue(
				actionsAttrTypes,
				map[string]attr.Value{
					"webhooks":                           webhooks,
					"mails":                              mails,
					"block_download":                     blockDownloadSet,
					"block_release_bundle_distribution":  types.BoolValue(rule.Actions.BlockReleaseBundleDistribution),
					"block_release_bundle_promotion":     types.BoolValue(rule.Actions.BlockReleaseBundlePromotion),
					"fail_build":                         types.BoolValue(rule.Actions.FailBuild),
					"notify_deployer":                    types.BoolValue(rule.Actions.NotifyDeployer),
					"notify_watch_recipients":            types.BoolValue(rule.Actions.NotifyWatchRecipients),
					"create_ticket_enabled":              types.BoolValue(rule.Actions.CreateJiraTicketEnabled),
					"build_failure_grace_period_in_days": types.Int64Value(rule.Actions.FailureGracePeriodDays),
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}
			actionsSet, d := types.SetValue(
				actionsSetElementType,
				[]attr.Value{actions},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			r, d := types.ObjectValue(
				ruleAttrTypes,
				map[string]attr.Value{
					"name":     types.StringValue(rule.Name),
					"priority": types.Int64Value(rule.Priority),
					"criteria": criteriaSet,
					"actions":  actionsSet,
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			return r
		},
	)

	rulesSet, d := types.SetValue(
		ruleSetElementType,
		rules,
	)
	if d.HasError() {
		diags.Append(d...)
	}

	m.ID = types.StringValue(apiModel.Name)
	m.Name = types.StringValue(apiModel.Name)
	m.Description = types.StringValue(apiModel.Description)
	m.Type = types.StringValue(apiModel.Type)
	m.Author = types.StringValue(apiModel.Author)
	m.Created = types.StringValue(apiModel.Created)
	m.Modified = types.StringValue(apiModel.Modified)

	m.Rules = rulesSet

	return diags
}

var projectKeySchemaAttrs = func(isForceNew bool, additionalDescription string) map[string]schema.Attribute {
	description := fmt.Sprintf("Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters. %s", additionalDescription)
	planModifiers := []planmodifier.String{}

	if isForceNew {
		planModifiers = append(planModifiers, stringplanmodifier.RequiresReplace())
	}

	return map[string]schema.Attribute{
		"project_key": schema.StringAttribute{
			Optional: true,
			Validators: []validator.String{
				validatorfw_string.ProjectKey(),
			},
			PlanModifiers: planModifiers,
			Description:   description,
		},
	}
}

var policySchemaAttrs = lo.Assign(
	projectKeySchemaAttrs(false, ""),
	map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true,
		},
		"name": schema.StringAttribute{
			Required: true,
			Validators: []validator.String{
				stringvalidator.LengthAtLeast(1),
			},
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
			Description: "Name of the policy (must be unique)",
		},
		"description": schema.StringAttribute{
			Optional:    true,
			Description: "More verbose description of the policy",
		},
		"type": schema.StringAttribute{
			Required: true,
			Validators: []validator.String{
				stringvalidator.OneOf("security", "license", "operational_risk"),
			},
			Description: "Type of the policy",
		},
		"author": schema.StringAttribute{
			Computed:    true,
			Description: "User, who created the policy",
		},
		"created": schema.StringAttribute{
			Computed:    true,
			Description: "Creation timestamp",
		},
		"modified": schema.StringAttribute{
			Computed:    true,
			Description: "Modification timestamp",
		},
	},
)

var commonActionsBlocks = map[string]schema.Block{
	"block_download": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"unscanned": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(false),
					Description: "Whether or not to block download of artifacts that meet the artifact `filters` for the associated `xray_watch` resource but have not been scanned yet. Can not be set to `true` if attribute `active` is `false`. Default value is `false`.",
				},
				"active": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(false),
					Description: "Whether or not to block download of artifacts that meet the artifact and severity `filters` for the associated `xray_watch` resource. Default value is `false`.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.IsRequired(),
			setvalidator.SizeAtMost(1),
		},
		Description: "Block download of artifacts that meet the Artifact Filter and Severity Filter specifications for this watch",
	},
}

var commonActionsAttrs = map[string]schema.Attribute{
	"webhooks": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Description: "A list of Xray-configured webhook URLs to be invoked if a violation is triggered.",
	},
	"mails": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Description: "A list of email addressed that will get emailed when a violation is triggered.",
	},
	"block_release_bundle_distribution": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Blocks Release Bundle distribution to Edge nodes if a violation is found. Default value is `false`.",
	},
	"block_release_bundle_promotion": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Blocks Release Bundle promotion if a violation is found. Default value is `false`.",
	},
	"fail_build": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Whether or not the related CI build should be marked as failed if a violation is triggered. This option is only available when the policy is applied to an `xray_watch` resource with a `type` of `builds`. Default value is `false`.",
	},
	"notify_deployer": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Sends an email message to component deployer with details about the generated Violations. Default value is `false`.",
	},
	"notify_watch_recipients": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Sends an email message to all configured recipients inside a specific watch with details about the generated Violations. Default value is `false`.",
	},
	"create_ticket_enabled": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Create Jira Ticket for this Policy Violation. Requires configured Jira integration. Default value is `false`.",
	},
	"build_failure_grace_period_in_days": schema.Int64Attribute{
		Optional: true,
		Validators: []validator.Int64{
			int64validator.AtLeast(0),
		},
		Description: "Allow grace period for certain number of days. All violations will be ignored during this time. To be used only if `fail_build` is enabled.",
	},
}

var securityPolicyCriteriaBlocks = map[string]schema.Block{
	"cvss_range": schema.ListNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"from": schema.Float64Attribute{
					Required: true,
					Validators: []validator.Float64{
						float64validator.Between(0, 10),
					},
					Description: "The beginning of the range of CVS scores (from 1-10, float) to flag.",
				},
				"to": schema.Float64Attribute{
					Required: true,
					Validators: []validator.Float64{
						float64validator.Between(0, 10),
					},
					Description: "The end of the range of CVS scores (from 1-10, float) to flag. ",
				},
			},
		},
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
		},
		Description: "The CVSS score range to apply to the rule. This is used for a fine-grained control, rather than using the predefined severities. The score range is based on CVSS v3 scoring, and CVSS v2 score is CVSS v3 score is not available.",
	},
	"exposures": schema.ListNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"min_severity": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString("All Severities"),
					Validators: []validator.String{
						stringvalidator.OneOfCaseInsensitive("All Severities", "Critical", "High", "Medium", "Low"),
					},
					MarkdownDescription: "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
				},
				"secrets": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Secrets exposures.",
				},
				"applications": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Applications exposures.",
				},
				"services": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Services exposures.",
				},
				"iac": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Iac exposures.",
				},
			},
		},
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("min_severity"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("malicious_package"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("vulnerability_ids"),
			),
		},
		Description: "Creates policy rules for specific exposures.\n\n~>Only supported by JFrog Advanced Security",
	},
}

var securityPolicyCriteriaAttrs = map[string]schema.Attribute{
	"min_severity": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.OneOfCaseInsensitive("All Severities", "Critical", "High", "Medium", "Low"),
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
		},
		Description: "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
	},
	"fix_version_dependant": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Default value is `false`. Issues that do not have a fixed version are not generated until a fixed version is available. Must be `false` with `malicious_package` enabled.",
	},
	"applicable_cves_only": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Default value is `false`. Mark to skip CVEs that are not applicable in the context of the artifact. The contextual analysis operation might be long and affect build time if the `fail_build` action is set.\n\n~>Only supported by JFrog Advanced Security",
	},
	"malicious_package": schema.BoolAttribute{
		Optional: true,
		Computed: true,
		Default:  booldefault.StaticBool(false),
		Validators: []validator.Bool{
			boolvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("min_severity"),
			),
			boolvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
		},
		Description: "Default value is `false`. Generating a violation on a malicious package.",
	},
	"vulnerability_ids": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.Set{
			setvalidator.SizeBetween(1, 100),
			setvalidator.ValueStringsAre(
				stringvalidator.RegexMatches(regexp.MustCompile(`(CVE\W*\d{4}\W+\d{4,}|XRAY-\d{4,})`), "invalid Vulnerability, must be a valid CVE or Xray ID, example CVE-2021-12345, XRAY-1234"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("malicious_package"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("min_severity"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("exposures"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("package_name"),
				path.MatchRelative().AtParent().AtName("package_type"),
				path.MatchRelative().AtParent().AtName("package_versions"),
			),
		},
		Description: "Creates policy rules for specific vulnerability IDs that you input. You can add multiple vulnerabilities IDs up to 100. CVEs and Xray IDs are supported. Example - CVE-2015-20107, XRAY-2344",
	},
	"package_name": schema.StringAttribute{
		Optional:    true,
		Description: "The package name to create a rule for",
		Validators: []validator.String{
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("package_type"),
			),
		},
	},
	"package_type": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.OneOfCaseInsensitive(validPackageTypesSupportedXraySecPolicies...),
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("package_name"),
			),
		},
		Description: "The package type to create a rule for",
	},
	"package_versions": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.Set{
			setvalidator.ValueStringsAre(
				stringvalidator.RegexMatches(regexp.MustCompile(`((^(\(|\[)((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))\,((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))(\)|\])$|^\[(\d+\.)?(\d+\.)?(\*|\d+)\]$))`), "invalid Range, must be one of the follows: Any Version: (,) or Specific Version: [1.2], [3] or Range: (1,), [,1.2.3], (4.5.0,6.5.2]"),
			),
		},
		Description: "package versions to apply the rule on can be (,) for any version or an open range (1,4) or closed [1,4] or one version [1]",
	},
}

var policyBlocks = func(criteriaAttrs map[string]schema.Attribute, criteriaBlocks map[string]schema.Block, actionsAttrs map[string]schema.Attribute, actionsBlocks map[string]schema.Block) map[string]schema.Block {
	return map[string]schema.Block{
		"rule": schema.SetNestedBlock{
			NestedObject: schema.NestedBlockObject{
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Required: true,
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
						},
						Description: "Name of the rule",
					},
					"priority": schema.Int64Attribute{
						Required: true,
						Validators: []validator.Int64{
							int64validator.AtLeast(1),
						},
						Description: "Integer describing the rule priority. Must be at least 1",
					},
				},
				Blocks: map[string]schema.Block{
					"criteria": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: criteriaAttrs,
							Blocks:     criteriaBlocks,
						},
						Validators: []validator.Set{
							setvalidator.IsRequired(),
							setvalidator.SizeBetween(1, 1),
						},
						Description: "The set of security conditions to examine when an scanned artifact is scanned.",
					},
					"actions": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: actionsAttrs,
							Blocks:     actionsBlocks,
						},
						Validators: []validator.Set{
							setvalidator.IsRequired(),
							setvalidator.SizeBetween(1, 1),
						},
						Description: "Specifies the actions to take once a security policy violation has been triggered.",
					},
				},
			},
			Validators: []validator.Set{
				setvalidator.IsRequired(),
				setvalidator.SizeAtLeast(1),
			},
			Description: "A list of user-defined rules allowing you to trigger violations for specific vulnerability or license breaches by setting a license or security criteria, with a corresponding set of automatic actions according to your needs. Rules are processed according to the ascending order in which they are placed in the Rules list on the Policy. If a rule is met, the subsequent rules in the list will not be applied.",
		},
	}
}

func (r *SecurityPolicyV2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: policySchemaAttrs,
		Blocks:     policyBlocks(securityPolicyCriteriaAttrs, securityPolicyCriteriaBlocks, commonActionsAttrs, commonActionsBlocks),
		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",
	}
}

func (r *SecurityPolicyV2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r SecurityPolicyV2Resource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data SecurityPolicyV2ResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If rule is not configured, return without warning.
	if data.Rules.IsNull() || data.Rules.IsUnknown() {
		return
	}

	for _, rule := range data.Rules.Elements() {
		ruleAttrs := rule.(types.Object).Attributes()
		criteria := ruleAttrs["criteria"].(types.Set)
		attrs := criteria.Elements()[0].(types.Object).Attributes()

		fixVersionDependant := attrs["fix_version_dependant"].(types.Bool).ValueBool()
		maliciousPackage := attrs["malicious_package"].(types.Bool).ValueBool()

		packageName := attrs["package_name"].(types.String)
		packagType := attrs["package_type"].(types.String)
		packageVersions := attrs["package_versions"].(types.Set)

		if maliciousPackage && fixVersionDependant {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtSetValue(rule).AtName("criteria").AtSetValue(criteria.Elements()[0]).AtName("fix_version_dependant"),
				"Invalid Attribute Configuration",
				"fix_version_dependant must be set to 'false' if malicious_package is 'true'",
			)
			return
		}

		if fixVersionDependant && (!packageName.IsNull() || !packagType.IsNull() || !packageVersions.IsNull()) {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtSetValue(rule).AtName("criteria").AtSetValue(criteria.Elements()[0]).AtName("fix_version_dependant"),
				"Invalid Attribute Configuration",
				"fix_version_dependant must be set to 'false' if any package attribute is set",
			)
			return
		}
	}
}

func (r *SecurityPolicyV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan SecurityPolicyV2ResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request, err := getRestyRequest(r.ProviderData.Client, plan.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var policy PolicyAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyError PolicyError
	response, err := request.
		SetBody(policy).
		SetError(&policyError).
		Post(PoliciesEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, policyError.Error)
		return
	}

	response, err = request.
		SetResult(&policy).
		SetPathParam("name", plan.Name.ValueString()).
		SetError(&policyError).
		Get(PolicyEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, policyError.Error)
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SecurityPolicyV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state SecurityPolicyV2ResourceModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request, err := getRestyRequest(r.ProviderData.Client, state.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var policy PolicyAPIModel
	var policyError PolicyError

	response, err := request.
		SetResult(&policy).
		SetPathParam("name", state.Name.ValueString()).
		SetError(&policyError).
		Get(PolicyEndpoint)

	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, policyError.Error)
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SecurityPolicyV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan SecurityPolicyV2ResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request, err := getRestyRequest(r.ProviderData.Client, plan.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var policy PolicyAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policyError PolicyError

	response, err := request.
		SetPathParam("name", plan.Name.ValueString()).
		SetBody(policy).
		SetError(&policyError).
		Put(PolicyEndpoint)

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, policyError.Error)
		return
	}

	response, err = request.
		SetResult(&policy).
		SetPathParam("name", plan.Name.ValueString()).
		SetError(&policyError).
		Get(PolicyEndpoint)

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, policyError.Error)
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(ctx, policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SecurityPolicyV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state SecurityPolicyV2ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	request, err := getRestyRequest(r.ProviderData.Client, state.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var policyError PolicyError
	response, err := request.
		SetPathParam("name", state.Name.ValueString()).
		SetError(&policyError).
		Delete(PolicyEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToDeleteResourceError(resp, policyError.Error)
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *SecurityPolicyV2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}

//
// func ResourceXraySecurityPolicyV2() *schema.Resource {
// 	var criteriaSchema = map[string]*schema.Schema{
// 		"min_severity": {
// 			Type:             schema.TypeString,
// 			Optional:         true,
// 			Description:      "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
// 			ValidateDiagFunc: validator.StringInSlice(true, "All Severities", "Critical", "High", "Medium", "Low"),
// 		},
// 		"fix_version_dependant": {
// 			Type:        schema.TypeBool,
// 			Optional:    true,
// 			Default:     false,
// 			Description: "Default value is `false`. Issues that do not have a fixed version are not generated until a fixed version is available. Must be `false` with `malicious_package` enabled.",
// 		},
// 		"applicable_cves_only": {
// 			Type:        schema.TypeBool,
// 			Optional:    true,
// 			Default:     false,
// 			Description: "Default value is `false`. Mark to skip CVEs that are not applicable in the context of the artifact. The contextual analysis operation might be long and affect build time if the `fail_build` action is set.\n\n~>Only supported by JFrog Advanced Security",
// 		},
// 		"malicious_package": {
// 			Type:        schema.TypeBool,
// 			Optional:    true,
// 			Default:     false,
// 			Description: "Default value is `false`. Generating a violation on a malicious package.",
// 		},
// 		"cvss_range": {
// 			Type:        schema.TypeList,
// 			Optional:    true,
// 			MaxItems:    1,
// 			Description: "The CVSS score range to apply to the rule. This is used for a fine-grained control, rather than using the predefined severities. The score range is based on CVSS v3 scoring, and CVSS v2 score is CVSS v3 score is not available.",
// 			Elem: &schema.Resource{
// 				Schema: map[string]*schema.Schema{
// 					"from": {
// 						Type:             schema.TypeFloat,
// 						Required:         true,
// 						Description:      "The beginning of the range of CVS scores (from 1-10, float) to flag.",
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.FloatBetween(0, 10)),
// 					},
// 					"to": {
// 						Type:             schema.TypeFloat,
// 						Required:         true,
// 						Description:      "The end of the range of CVS scores (from 1-10, float) to flag. ",
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.FloatBetween(0, 10)),
// 					},
// 				},
// 			},
// 		},
// 		"vulnerability_ids": {
// 			Type:        schema.TypeSet,
// 			Optional:    true,
// 			MaxItems:    100,
// 			MinItems:    1,
// 			Description: "Creates policy rules for specific vulnerability IDs that you input. You can add multiple vulnerabilities IDs up to 100. CVEs and Xray IDs are supported. Example - CVE-2015-20107, XRAY-2344",
// 			Elem: &schema.Schema{
// 				Type: schema.TypeString,
// 				ValidateDiagFunc: validation.ToDiagFunc(
// 					validation.StringMatch(regexp.MustCompile(`(CVE\W*\d{4}\W+\d{4,}|XRAY-\d{4,})`), "invalid Vulnerability, must be a valid CVE or Xray ID, example CVE-2021-12345, XRAY-1234"),
// 				),
// 			},
// 		},
// 		"exposures": {
// 			Type:        schema.TypeList,
// 			Optional:    true,
// 			MaxItems:    1,
// 			Description: "Creates policy rules for specific exposures.\n\n~>Only supported by JFrog Advanced Security",
// 			Elem: &schema.Resource{
// 				Schema: map[string]*schema.Schema{
// 					"min_severity": {
// 						Type:             schema.TypeString,
// 						Optional:         true,
// 						Default:          "All Severities",
// 						Description:      "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
// 						ValidateDiagFunc: validator.StringInSlice(true, "All Severities", "Critical", "High", "Medium", "Low"),
// 					},
// 					"secrets": {
// 						Type:        schema.TypeBool,
// 						Optional:    true,
// 						Default:     true,
// 						Description: "Secrets exposures.",
// 					},
// 					"applications": {
// 						Type:        schema.TypeBool,
// 						Optional:    true,
// 						Default:     true,
// 						Description: "Applications exposures.",
// 					},
// 					"services": {
// 						Type:        schema.TypeBool,
// 						Optional:    true,
// 						Default:     true,
// 						Description: "Services exposures.",
// 					},
// 					"iac": {
// 						Type:        schema.TypeBool,
// 						Optional:    true,
// 						Default:     true,
// 						Description: "Iac exposures.",
// 					},
// 				},
// 			},
// 		},
// 		"package_name": {
// 			Type:        schema.TypeString,
// 			Optional:    true,
// 			Description: "The package name to create a rule for",
// 		},
// 		"package_type": {
// 			Type:             schema.TypeString,
// 			Optional:         true,
// 			Description:      "The package type to create a rule for",
// 			ValidateDiagFunc: validator.StringInSlice(true, validPackageTypesSupportedXraySecPolicies...),
// 		},
// 		"package_versions": {
// 			Type:        schema.TypeSet,
// 			Optional:    true,
// 			Description: "package versions to apply the rule on can be (,) for any version or an open range (1,4) or closed [1,4] or one version [1]",
// 			Elem: &schema.Schema{
// 				Type: schema.TypeString,
// 				ValidateDiagFunc: validation.ToDiagFunc(
// 					validation.StringMatch(regexp.MustCompile(`((^(\(|\[)((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))\,((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))(\)|\])$|^\[(\d+\.)?(\d+\.)?(\*|\d+)\]$))`), "invalid Range, must be one of the follows: Any Version: (,) or Specific Version: [1.2], [3] or Range: (1,), [,1.2.3], (4.5.0,6.5.2]"),
// 				),
// 			},
// 		},
// 	}
//
// 	return &schema.Resource{
// 		SchemaVersion: 1,
// 		CreateContext: resourceXrayPolicyCreate,
// 		ReadContext:   resourceXrayPolicyRead,
// 		UpdateContext: resourceXrayPolicyUpdate,
// 		DeleteContext: resourceXrayPolicyDelete,
// 		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
// 			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",
//
// 		Importer: &schema.ResourceImporter{
// 			StateContext: resourceImporterForProjectKey,
// 		},
// 		CustomizeDiff: criteriaMaliciousPkgDiff,
// 		Schema:        getPolicySchema(criteriaSchema, commonActionsSchema),
// 	}
// }
//
// var criteriaMaliciousPkgDiff = func(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
// 	rules := diff.Get("rule").(*schema.Set).List()
// 	if len(rules) == 0 {
// 		return nil
// 	}
// 	criteria := rules[0].(map[string]interface{})["criteria"].(*schema.Set).List()
// 	if len(criteria) == 0 {
// 		return nil
// 	}
//
// 	criterion := criteria[0].(map[string]interface{})
// 	// fixVersionDependant can't be set with malicious_package
// 	fixVersionDependant := criterion["fix_version_dependant"].(bool)
// 	// Only one of the following:
// 	minSeverity := criterion["min_severity"].(string)
// 	cvssRange := criterion["cvss_range"].([]interface{})
// 	vulnerabilityIDs := criterion["vulnerability_ids"].(*schema.Set).List()
// 	maliciousPackage := criterion["malicious_package"].(bool)
// 	exposures := criterion["exposures"].([]interface{})
// 	package_name := criterion["package_name"].(string)
// 	package_type := criterion["package_type"].(string)
// 	package_versions := criterion["package_versions"].(*schema.Set).List()
// 	isPackageSet := len(package_name) > 0 || len(package_type) > 0 || len(package_versions) > 0 //if one of them is not defined the API will return an error guiding which one is missing
//
// 	if len(exposures) > 0 && maliciousPackage || (len(exposures) > 0 && len(cvssRange) > 0) ||
// 		(len(exposures) > 0 && len(minSeverity) > 0) || (len(exposures) > 0 && len(vulnerabilityIDs) > 0) {
// 		return fmt.Errorf("exsposures can't be set together with cvss_range, min_severity, malicious_package and vulnerability_ids")
// 	}
// 	// If `malicious_package` is enabled in the UI, `fix_version_dependant` is set to `false` in the UI call.
// 	// UI itself doesn't have this checkbox at all. We are adding this check to avoid unexpected behavior.
// 	if maliciousPackage && fixVersionDependant {
// 		return fmt.Errorf("fix_version_dependant must be set to false if malicious_package is true")
// 	}
// 	if (maliciousPackage && len(minSeverity) > 0) || (maliciousPackage && len(cvssRange) > 0) {
// 		return fmt.Errorf("malicious_package can't be set together with min_severity and/or cvss_range")
// 	}
// 	if len(minSeverity) > 0 && len(cvssRange) > 0 {
// 		return fmt.Errorf("min_severity can't be set together with cvss_range")
// 	}
// 	if (len(vulnerabilityIDs) > 0 && maliciousPackage) || (len(vulnerabilityIDs) > 0 && len(minSeverity) > 0) ||
// 		(len(vulnerabilityIDs) > 0 && len(cvssRange) > 0) || (len(vulnerabilityIDs) > 0 && len(exposures) > 0) {
// 		return fmt.Errorf("vulnerability_ids can't be set together with with malicious_package, min_severity, cvss_range and exposures")
// 	}
//
// 	if (isPackageSet && len(vulnerabilityIDs) > 0) || (isPackageSet && maliciousPackage) ||
// 		(isPackageSet && len(cvssRange) > 0) || (isPackageSet && len(minSeverity) > 0) ||
// 		(isPackageSet && len(exposures) > 0) {
// 		return fmt.Errorf("package_name, package_type and package versions can't be set together with with vulnerability_ids, malicious_package, min_severity, cvss_range and exposures")
// 	}
//
// 	if isPackageSet && fixVersionDependant {
// 		return fmt.Errorf("fix_version_dependant must be set to false if package type policy is used")
// 	}
//
// 	return nil
// }
