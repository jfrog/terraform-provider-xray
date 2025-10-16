package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/samber/lo"
)

var _ resource.Resource = &LicensePolicyResource{}

func NewLicensePolicyResource() resource.Resource {
	return &LicensePolicyResource{
		PolicyResource: PolicyResource{
			TypeName: "xray_license_policy",
		},
	}
}

type LicensePolicyResource struct {
	PolicyResource
}

func (r *LicensePolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r LicensePolicyResource) toCriteriaAPIModel(ctx context.Context, criteriaElems []attr.Value) (*PolicyRuleCriteriaAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var criteria *PolicyRuleCriteriaAPIModel
	if len(criteriaElems) > 0 {
		attrs := criteriaElems[0].(types.Object).Attributes()

		var allowedLicenses []string
		d := attrs["allowed_licenses"].(types.List).ElementsAs(ctx, &allowedLicenses, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var bannedLicenses []string
		d = attrs["banned_licenses"].(types.List).ElementsAs(ctx, &bannedLicenses, false)
		if d.HasError() {
			diags.Append(d...)
		}

		criteria = &PolicyRuleCriteriaAPIModel{
			AllowedLicenses:        allowedLicenses,
			AllowUnknown:           attrs["allow_unknown"].(types.Bool).ValueBoolPointer(),
			BannedLicenses:         bannedLicenses,
			MultiLicensePermissive: attrs["multi_license_permissive"].(types.Bool).ValueBoolPointer(),
		}
	}

	return criteria, diags
}

func (r LicensePolicyResource) toActionsAPIModel(ctx context.Context, actionsElems []attr.Value) (PolicyRuleActionsAPIModel, diag.Diagnostics) {
	actions, ds := toActionsAPIModel(ctx, actionsElems)

	if len(actionsElems) > 0 {
		attrs := actionsElems[0].(types.Object).Attributes()
		actions.CustomSeverity = attrs["custom_severity"].(types.String).ValueString()
	}

	return actions, ds
}

func (r LicensePolicyResource) toAPIModel(ctx context.Context, plan PolicyResourceModel, policy *PolicyAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, policy, r.toCriteriaAPIModel, r.toActionsAPIModel)
}

var licenseCriteriaAttrTypes = lo.Assign(
	map[string]attr.Type{
		"allow_unknown":            types.BoolType,
		"allowed_licenses":         types.ListType{ElemType: types.StringType},
		"banned_licenses":          types.ListType{ElemType: types.StringType},
		"multi_license_permissive": types.BoolType,
	},
)

var licenseCriteriaSetElementType = types.ObjectType{
	AttrTypes: licenseCriteriaAttrTypes,
}

func (r *LicensePolicyResource) fromCriteriaAPIModel(ctx context.Context, criteraAPIModel *PolicyRuleCriteriaAPIModel) (types.List, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	criteriaSet := types.ListNull(licenseCriteriaSetElementType)
	if criteraAPIModel != nil {
		allowedLicenses, d := types.ListValueFrom(ctx, types.StringType, criteraAPIModel.AllowedLicenses)
		if d.HasError() {
			diags.Append(d...)
		}

		bannedLicenses, d := types.ListValueFrom(ctx, types.StringType, criteraAPIModel.BannedLicenses)
		if d.HasError() {
			diags.Append(d...)
		}

		criteria, d := types.ObjectValue(
			licenseCriteriaAttrTypes,
			map[string]attr.Value{
				"allow_unknown":            types.BoolPointerValue(criteraAPIModel.AllowUnknown),
				"allowed_licenses":         allowedLicenses,
				"banned_licenses":          bannedLicenses,
				"multi_license_permissive": types.BoolPointerValue(criteraAPIModel.MultiLicensePermissive),
			},
		)
		if d.HasError() {
			diags.Append(d...)
		}
		cs, d := types.ListValue(
			licenseCriteriaSetElementType,
			[]attr.Value{criteria},
		)
		if d.HasError() {
			diags.Append(d...)
		}

		criteriaSet = cs
	}

	return criteriaSet, diags
}

var licenseActionsAttrTypes = lo.Assign(
	actionsAttrTypes,
	map[string]attr.Type{
		"custom_severity": types.StringType,
	},
)

var licenseActionsSetElementType = types.ObjectType{
	AttrTypes: licenseActionsAttrTypes,
}

func (m *LicensePolicyResource) fromActionsAPIModel(ctx context.Context, actionsAPIModel PolicyRuleActionsAPIModel) (types.Set, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	webhooks := types.SetNull(types.StringType)
	if len(actionsAPIModel.Webhooks) > 0 {
		ws, d := types.SetValueFrom(ctx, types.StringType, actionsAPIModel.Webhooks)
		if d.HasError() {
			diags.Append(d...)
		}

		webhooks = ws
	}

	mails := types.SetNull(types.StringType)
	if len(actionsAPIModel.Mails) > 0 {
		ms, d := types.SetValueFrom(ctx, types.StringType, actionsAPIModel.Mails)
		if d.HasError() {
			diags.Append(d...)
		}

		mails = ms
	}

	blockDownload, d := types.ObjectValue(
		blockDownloadAttrTypes,
		map[string]attr.Value{
			"unscanned": types.BoolValue(actionsAPIModel.BlockDownload.Unscanned),
			"active":    types.BoolValue(actionsAPIModel.BlockDownload.Active),
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
		licenseActionsAttrTypes,
		map[string]attr.Value{
			"webhooks":                           webhooks,
			"mails":                              mails,
			"block_download":                     blockDownloadSet,
			"block_release_bundle_distribution":  types.BoolValue(actionsAPIModel.BlockReleaseBundleDistribution),
			"block_release_bundle_promotion":     types.BoolValue(actionsAPIModel.BlockReleaseBundlePromotion),
			"fail_build":                         types.BoolValue(actionsAPIModel.FailBuild),
			"notify_deployer":                    types.BoolValue(actionsAPIModel.NotifyDeployer),
			"notify_watch_recipients":            types.BoolValue(actionsAPIModel.NotifyWatchRecipients),
			"create_ticket_enabled":              types.BoolValue(actionsAPIModel.CreateJiraTicketEnabled),
			"build_failure_grace_period_in_days": types.Int64Value(actionsAPIModel.FailureGracePeriodDays),
			"custom_severity":                    types.StringValue(actionsAPIModel.CustomSeverity),
		},
	)
	if d.HasError() {
		diags.Append(d...)
	}

	actionsSet, d := types.SetValue(
		licenseActionsSetElementType,
		[]attr.Value{actions},
	)
	if d.HasError() {
		diags.Append(d...)
	}

	return actionsSet, diags
}

func (r LicensePolicyResource) fromAPIModel(ctx context.Context, policy PolicyAPIModel, plan *PolicyResourceModel) diag.Diagnostics {
	return plan.fromAPIModel(ctx, policy, r.fromCriteriaAPIModel, r.fromActionsAPIModel)
}

var licenseRuleAttrTypes = map[string]attr.Type{
	"name":     types.StringType,
	"priority": types.Int64Type,
	"criteria": types.ListType{ElemType: licenseCriteriaSetElementType},
	"actions":  types.SetType{ElemType: licenseActionsSetElementType},
}

var licenseRuleSetElementType = types.ObjectType{
	AttrTypes: licenseRuleAttrTypes,
}

var licensePolicyCriteriaAttrs = map[string]schema.Attribute{
	"banned_licenses": schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.List{
			listvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("allowed_licenses")),
		},
		Description: "A list of OSS license names that may not be attached to a component. Supports custom licenses added by the user, but there is no verification if the license exists on the Xray side. If the added license doesn't exist, the policy won't trigger the violation.",
	},
	"allowed_licenses": schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.List{
			listvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("banned_licenses")),
		},
		Description: "A list of OSS license names that may be attached to a component. Supports custom licenses added by the user, but there is no verification if the license exists on the Xray side. If the added license doesn't exist, the policy won't trigger the violation.",
	},
	"allow_unknown": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(true),
		Description: "A violation will be generated for artifacts with unknown licenses (`true` or `false`).",
	},
	"multi_license_permissive": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Do not generate a violation if at least one license is valid in cases whereby multiple licenses were detected on the component.",
	},
}

var licensePolicyCriteriaBlocks = map[string]schema.Block{}

var licensePolicyActionsAttrs = lo.Assign(
	commonActionsAttrs,
	map[string]schema.Attribute{
		"custom_severity": schema.StringAttribute{
			Optional: true,
			Computed: true,
			Default:  stringdefault.StaticString("High"),
			Validators: []validator.String{
				stringvalidator.OneOf("Critical", "High", "Medium", "Low"),
			},
			Description: "The severity of violation to be triggered if the `criteria` are met.",
		},
	},
)

func (r *LicensePolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: policySchemaAttrs,
		Blocks:     policyBlocks(licensePolicyCriteriaAttrs, licensePolicyCriteriaBlocks, licensePolicyActionsAttrs, commonActionsBlocks),
		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",
	}
}

func (r *LicensePolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *LicensePolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.PolicyResource.Create(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *LicensePolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.PolicyResource.Read(ctx, r.fromAPIModel, req, resp)
}

func (r *LicensePolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.PolicyResource.Update(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *LicensePolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.PolicyResource.Delete(ctx, req, resp)
}

// ImportState imports the resource into the Terraform state.
func (r *LicensePolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	r.PolicyResource.ImportState(ctx, req, resp)
}
