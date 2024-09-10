package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
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
)

var _ resource.Resource = &OperationalRiskPolicyResource{}

func NewOperationalRiskPolicyResource() resource.Resource {
	return &OperationalRiskPolicyResource{
		PolicyResource: PolicyResource{
			TypeName: "xray_operational_risk_policy",
		},
	}
}

type OperationalRiskPolicyResource struct {
	PolicyResource
}

func (r OperationalRiskPolicyResource) toCriteriaAPIModel(ctx context.Context, criteriaElems []attr.Value) (*PolicyRuleCriteriaAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var criteria *PolicyRuleCriteriaAPIModel
	if len(criteriaElems) > 0 {
		attrs := criteriaElems[0].(types.Object).Attributes()

		var opRiskCustom *OperationalRiskCriteriaAPIModel
		customElem := attrs["op_risk_custom"].(types.List).Elements()
		if len(customElem) > 0 {
			attrs := customElem[0].(types.Object).Attributes()

			opRiskCustom = &OperationalRiskCriteriaAPIModel{
				UseAndCondition:               attrs["use_and_condition"].(types.Bool).ValueBool(),
				IsEOL:                         attrs["is_eol"].(types.Bool).ValueBool(),
				ReleaseDateGreaterThanMonths:  attrs["release_date_greater_than_months"].(types.Int64).ValueInt64Pointer(),
				NewerVersionsGreaterThan:      attrs["newer_versions_greater_than"].(types.Int64).ValueInt64Pointer(),
				ReleaseCadencePerYearLessThan: attrs["release_cadence_per_year_less_than"].(types.Int64).ValueInt64Pointer(),
				CommitsLessThan:               attrs["commits_less_than"].(types.Int64).ValueInt64Pointer(),
				CommittersLessThan:            attrs["committers_less_than"].(types.Int64).ValueInt64Pointer(),
				Risk:                          attrs["risk"].(types.String).ValueString(),
			}
		}

		criteria = &PolicyRuleCriteriaAPIModel{
			OperationalRiskMinRisk: attrs["op_risk_min_risk"].(types.String).ValueString(),
			OperationalRiskCustom:  opRiskCustom,
		}
	}

	return criteria, diags
}

func (r OperationalRiskPolicyResource) toAPIModel(ctx context.Context, plan PolicyResourceModel, policy *PolicyAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, policy, r.toCriteriaAPIModel, toActionsAPIModel)
}

func (r *OperationalRiskPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var opRiskPolicyCriteriaAttrs = map[string]schema.Attribute{
	"op_risk_min_risk": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.OneOfCaseInsensitive("High", "Medium", "Low"),
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("op_risk_custom"),
			),
		},
		Description: "The minimum operational risk that will be impacted by the policy: High, Medium, Low",
	},
}

var opRiskPolicyCriteriaBlocks = map[string]schema.Block{
	"op_risk_custom": schema.ListNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"use_and_condition": schema.BoolAttribute{
					Required:            true,
					MarkdownDescription: "Use `AND` between conditions (true) or `OR` condition (false)",
				},
				"is_eol": schema.BoolAttribute{
					Optional:            true,
					Computed:            true,
					Default:             booldefault.StaticBool(false),
					MarkdownDescription: "Is End-of-Life?",
				},
				"release_date_greater_than_months": schema.Int64Attribute{
					Optional: true,
					Validators: []validator.Int64{
						int64validator.OneOf(6, 12, 18, 24, 30, 36),
					},
					Description: "Release age greater than (in months): 6, 12, 18, 24, 30, or 36",
				},
				"newer_versions_greater_than": schema.Int64Attribute{
					Optional: true,
					Validators: []validator.Int64{
						int64validator.OneOf(1, 2, 3, 4, 5),
					},
					Description: "Number of releases since greater than: 1, 2, 3, 4, or 5",
				},
				"release_cadence_per_year_less_than": schema.Int64Attribute{
					Optional: true,
					Validators: []validator.Int64{
						int64validator.OneOf(1, 2, 3, 4, 5),
					},
					Description: "Release cadence less than per year: 1, 2, 3, 4, or 5",
				},
				"commits_less_than": schema.Int64Attribute{
					Optional: true,
					Validators: []validator.Int64{
						int64validator.OneOf(10, 25, 50, 100),
					},
					Description: "Number of commits less than per year: 10, 25, 50, or 100",
				},
				"committers_less_than": schema.Int64Attribute{
					Optional: true,
					Validators: []validator.Int64{
						int64validator.OneOf(1, 2, 3, 4, 5),
					},
					Description: "Number of committers less than per year: 1, 2, 3, 4, or 5",
				},
				"risk": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString("low"),
					Validators: []validator.String{
						stringvalidator.OneOfCaseInsensitive("high", "medium", "low"),
					},
					Description: "Risk severity: low, medium, high",
				},
			},
		},
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("op_risk_min_risk"),
			),
		},
		Description: "Custom Condition",
	},
}

var opRiskCustomAttrType = map[string]attr.Type{
	"use_and_condition":                  types.BoolType,
	"is_eol":                             types.BoolType,
	"release_date_greater_than_months":   types.Int64Type,
	"newer_versions_greater_than":        types.Int64Type,
	"release_cadence_per_year_less_than": types.Int64Type,
	"commits_less_than":                  types.Int64Type,
	"committers_less_than":               types.Int64Type,
	"risk":                               types.StringType,
}

var opRiskCustomElementType = types.ObjectType{
	AttrTypes: opRiskCustomAttrType,
}

var opRiskCriteriaAttrTypes = map[string]attr.Type{
	"op_risk_min_risk": types.StringType,
	"op_risk_custom":   types.ListType{ElemType: opRiskCustomElementType},
}

var opRiskCriteriaSetElementType = types.ObjectType{
	AttrTypes: opRiskCriteriaAttrTypes,
}

func (r *OperationalRiskPolicyResource) fromCriteriaAPIModel(ctx context.Context, criteraAPIModel *PolicyRuleCriteriaAPIModel) (types.Set, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	criteriaSet := types.SetNull(opRiskCriteriaSetElementType)
	if criteraAPIModel != nil {
		minRisk := types.StringNull()
		if criteraAPIModel.OperationalRiskMinRisk != "" {
			minRisk = types.StringValue(criteraAPIModel.OperationalRiskMinRisk)
		}

		customList := types.ListNull(opRiskCustomElementType)
		if criteraAPIModel.OperationalRiskCustom != nil {
			risk := types.StringNull()
			if criteraAPIModel.OperationalRiskCustom.Risk != "" {
				risk = types.StringValue(criteraAPIModel.OperationalRiskCustom.Risk)
			}

			releaseDateGreaterThanMonths := types.Int64Null()
			if criteraAPIModel.OperationalRiskCustom.ReleaseDateGreaterThanMonths != nil {
				releaseDateGreaterThanMonths = types.Int64PointerValue(criteraAPIModel.OperationalRiskCustom.ReleaseDateGreaterThanMonths)
			}

			newerVersionsGreaterThan := types.Int64Null()
			if criteraAPIModel.OperationalRiskCustom.NewerVersionsGreaterThan != nil {
				newerVersionsGreaterThan = types.Int64PointerValue(criteraAPIModel.OperationalRiskCustom.NewerVersionsGreaterThan)
			}

			releaseCadencePerYearLessThan := types.Int64Null()
			if criteraAPIModel.OperationalRiskCustom.ReleaseCadencePerYearLessThan != nil {
				releaseCadencePerYearLessThan = types.Int64PointerValue(criteraAPIModel.OperationalRiskCustom.ReleaseCadencePerYearLessThan)
			}

			commitsLessThan := types.Int64Null()
			if criteraAPIModel.OperationalRiskCustom.CommitsLessThan != nil {
				commitsLessThan = types.Int64PointerValue(criteraAPIModel.OperationalRiskCustom.CommitsLessThan)
			}

			committersLessThan := types.Int64Null()
			if criteraAPIModel.OperationalRiskCustom.CommittersLessThan != nil {
				committersLessThan = types.Int64PointerValue(criteraAPIModel.OperationalRiskCustom.CommittersLessThan)
			}

			custom, d := types.ObjectValue(
				opRiskCustomAttrType,
				map[string]attr.Value{
					"use_and_condition":                  types.BoolValue(criteraAPIModel.OperationalRiskCustom.UseAndCondition),
					"is_eol":                             types.BoolValue(criteraAPIModel.OperationalRiskCustom.IsEOL),
					"release_date_greater_than_months":   releaseDateGreaterThanMonths,
					"newer_versions_greater_than":        newerVersionsGreaterThan,
					"release_cadence_per_year_less_than": releaseCadencePerYearLessThan,
					"commits_less_than":                  commitsLessThan,
					"committers_less_than":               committersLessThan,
					"risk":                               risk,
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			c, d := types.ListValue(
				opRiskCustomElementType,
				[]attr.Value{custom},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			customList = c
		}

		criteria, d := types.ObjectValue(
			opRiskCriteriaAttrTypes,
			map[string]attr.Value{
				"op_risk_min_risk": minRisk,
				"op_risk_custom":   customList,
			},
		)
		if d.HasError() {
			diags.Append(d...)
		}
		cs, d := types.SetValue(
			opRiskCriteriaSetElementType,
			[]attr.Value{criteria},
		)
		if d.HasError() {
			diags.Append(d...)
		}

		criteriaSet = cs
	}

	return criteriaSet, diags
}

var opRiskRuleAttrTypes = map[string]attr.Type{
	"name":     types.StringType,
	"priority": types.Int64Type,
	"criteria": types.SetType{ElemType: opRiskCriteriaSetElementType},
	"actions":  types.SetType{ElemType: actionsSetElementType},
}

var opRiskRuleSetElementType = types.ObjectType{
	AttrTypes: opRiskRuleAttrTypes,
}

func (r OperationalRiskPolicyResource) fromAPIModel(ctx context.Context, policy PolicyAPIModel, plan *PolicyResourceModel) diag.Diagnostics {
	return plan.fromAPIModel(ctx, policy, r.fromCriteriaAPIModel, fromActionsAPIModel)
}

func (r *OperationalRiskPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: policySchemaAttrs,
		Blocks:     policyBlocks(opRiskPolicyCriteriaAttrs, opRiskPolicyCriteriaBlocks, commonActionsAttrs, commonActionsBlocks),
		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",
	}
}

func (r *OperationalRiskPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *OperationalRiskPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.PolicyResource.Create(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *OperationalRiskPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.PolicyResource.Read(ctx, r.fromAPIModel, req, resp)
}

func (r *OperationalRiskPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.PolicyResource.Update(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *OperationalRiskPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.PolicyResource.Delete(ctx, req, resp)
}

// ImportState imports the resource into the Terraform state.
func (r *OperationalRiskPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	r.PolicyResource.ImportState(ctx, req, resp)
}
