package xray

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/samber/lo"
)

const (
	PoliciesEndpoint = "xray/api/v2/policies"
	PolicyEndpoint   = "xray/api/v2/policies/{name}"
)

var validPackageTypesSupportedXraySecPolicies = []string{
	"alpine",
	"bower",
	"cargo",
	"composer",
	"conan",
	"conda",
	"cran",
	"debian",
	"docker",
	"generic",
	"go",
	"huggingface",
	"maven",
	"npm",
	"nuget",
	"oci",
	"pypi",
	"rpm",
	"rubygems",
	"terraformbe",
}

type PolicyResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type PolicyResourceModel struct {
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

var toActionsAPIModel = func(ctx context.Context, actionsElems []attr.Value) (PolicyRuleActionsAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	actions := PolicyRuleActionsAPIModel{}
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
	}

	return actions, diags
}

func (m PolicyResourceModel) toAPIModel(
	ctx context.Context,
	apiModel *PolicyAPIModel,
	toCriteriaAPIModel func(ctx context.Context, criteriaElems []attr.Value) (*PolicyRuleCriteriaAPIModel, diag.Diagnostics),
	toActionsAPIModel func(ctx context.Context, actionsElems []attr.Value) (PolicyRuleActionsAPIModel, diag.Diagnostics),
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	rules := lo.Map(
		m.Rules.Elements(),
		func(elem attr.Value, _ int) PolicyRuleAPIModel {
			attrs := elem.(types.Object).Attributes()

			criteria, ds := toCriteriaAPIModel(ctx, attrs["criteria"].(types.Set).Elements())
			if ds.HasError() {
				diags.Append(ds...)
			}

			actions, ds := toActionsAPIModel(ctx, attrs["actions"].(types.Set).Elements())
			if ds.HasError() {
				diags.Append(ds...)
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

var fromActionsAPIModel = func(ctx context.Context, actionsAPIModel PolicyRuleActionsAPIModel) (types.Set, diag.Diagnostics) {
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
		actionsAttrTypes,
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

	return actionsSet, diags
}

func (m *PolicyResourceModel) fromAPIModel(
	ctx context.Context,
	apiModel PolicyAPIModel,
	fromCriteriaAPIModel func(ctx context.Context, criteraAPIModel *PolicyRuleCriteriaAPIModel) (types.Set, diag.Diagnostics),
	fromActionsAPIModel func(ctx context.Context, actionsAPIModel PolicyRuleActionsAPIModel) (types.Set, diag.Diagnostics),
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	var ruleAttrTypes map[string]attr.Type
	var ruleSetElementType types.ObjectType

	switch apiModel.Type {
	case "license":
		ruleAttrTypes = licenseRuleAttrTypes
		ruleSetElementType = licenseRuleSetElementType
	case "security":
		ruleAttrTypes = securityRuleAttrTypes
		ruleSetElementType = securityRuleSetElementType
	case "operational_risk":
		ruleAttrTypes = opRiskRuleAttrTypes
		ruleSetElementType = opRiskRuleSetElementType
	}

	rules := lo.Map(
		*apiModel.Rules,
		func(rule PolicyRuleAPIModel, _ int) attr.Value {
			criteriaSet, d := fromCriteriaAPIModel(ctx, rule.Criteria)
			if d.HasError() {
				diags.Append(d...)
			}

			actionsSet, d := fromActionsAPIModel(ctx, rule.Actions)
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
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
		},
		Description: "A list of Xray-configured webhook URLs to be invoked if a violation is triggered.",
	},
	"mails": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
		},
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

type PolicyCVSSRangeAPIModel struct {
	To   *float64 `json:"to,omitempty"`
	From *float64 `json:"from,omitempty"`
}

type PolicyExposuresAPIModel struct {
	MinSeverity  *string `json:"min_severity,omitempty"`
	Secrets      *bool   `json:"secrets,omitempty"`
	Applications *bool   `json:"applications,omitempty"`
	Services     *bool   `json:"services,omitempty"`
	Iac          *bool   `json:"iac,omitempty"`
}

type OperationalRiskCriteriaAPIModel struct {
	UseAndCondition               bool   `json:"use_and_condition"`
	IsEOL                         bool   `json:"is_eol"`
	ReleaseDateGreaterThanMonths  *int64 `json:"release_date_greater_than_months,omitempty"`
	NewerVersionsGreaterThan      *int64 `json:"newer_versions_greater_than,omitempty"`
	ReleaseCadencePerYearLessThan *int64 `json:"release_cadence_per_year_less_than,omitempty"`
	CommitsLessThan               *int64 `json:"commits_less_than,omitempty"`
	CommittersLessThan            *int64 `json:"committers_less_than,omitempty"`
	Risk                          string `json:"risk,omitempty"`
}

type PolicyRuleCriteriaAPIModel struct {
	// Security Criteria
	MinimumSeverity string                   `json:"min_severity,omitempty"` // Omitempty is used because the empty field is conflicting with CVSSRange
	CVSSRange       *PolicyCVSSRangeAPIModel `json:"cvss_range,omitempty"`
	// Omitempty is used in FixVersionDependant because an empty field throws an error in Xray below 3.44.3
	FixVersionDependant bool                     `json:"fix_version_dependant,omitempty"`
	ApplicableCVEsOnly  bool                     `json:"applicable_cves_only,omitempty"`
	MaliciousPackage    bool                     `json:"malicious_package,omitempty"`
	VulnerabilityIds    []string                 `json:"vulnerability_ids,omitempty"`
	Exposures           *PolicyExposuresAPIModel `json:"exposures,omitempty"`
	PackageName         string                   `json:"package_name,omitempty"`
	PackageType         string                   `json:"package_type,omitempty"`
	PackageVersions     []string                 `json:"package_versions,omitempty"`
	// We use pointer for CVSSRange to address nil-verification for non-primitive types.
	// Unlike primitive types, when the non-primitive type in the struct is set
	// to nil, the empty key will be created in the JSON body anyway.
	// Since CVSSRange is conflicting with MinimumSeverity, Xray will throw an error if .
	// Pointer can be set to nil value, so we can remove CVSSRange entirely only
	// if it's a pointer.
	// The nil pointer is used in conjunction with the omitempty flag in the JSON tag,
	// to remove the key completely in the payload.

	// License Criteria
	AllowUnknown           *bool    `json:"allow_unknown,omitempty"`            // Omitempty is used because the empty field is conflicting with MultiLicensePermissive
	MultiLicensePermissive *bool    `json:"multi_license_permissive,omitempty"` // Omitempty is used because the empty field is conflicting with AllowUnknown
	BannedLicenses         []string `json:"banned_licenses,omitempty"`
	AllowedLicenses        []string `json:"allowed_licenses,omitempty"`

	// Operational Risk custom criteria
	OperationalRiskCustom  *OperationalRiskCriteriaAPIModel `json:"op_risk_custom,omitempty"`
	OperationalRiskMinRisk string                           `json:"op_risk_min_risk,omitempty"`
}

type BlockDownloadSettingsAPIModel struct {
	Unscanned bool `json:"unscanned"`
	Active    bool `json:"active"`
}

type PolicyRuleActionsAPIModel struct {
	Webhooks                       []string                      `json:"webhooks,omitempty"`
	Mails                          []string                      `json:"mails,omitempty"`
	FailBuild                      bool                          `json:"fail_build"`
	BlockDownload                  BlockDownloadSettingsAPIModel `json:"block_download"`
	BlockReleaseBundleDistribution bool                          `json:"block_release_bundle_distribution"`
	BlockReleaseBundlePromotion    bool                          `json:"block_release_bundle_promotion"`
	NotifyWatchRecipients          bool                          `json:"notify_watch_recipients"`
	NotifyDeployer                 bool                          `json:"notify_deployer"`
	CreateJiraTicketEnabled        bool                          `json:"create_ticket_enabled"`
	FailureGracePeriodDays         int64                         `json:"build_failure_grace_period_in_days,omitempty"`
	// License Actions
	CustomSeverity string `json:"custom_severity,omitempty"`
}

type PolicyRuleAPIModel struct {
	Name     string                      `json:"name"`
	Priority int64                       `json:"priority"`
	Criteria *PolicyRuleCriteriaAPIModel `json:"criteria"`
	Actions  PolicyRuleActionsAPIModel   `json:"actions"`
}

type PolicyAPIModel struct {
	Name        string                `json:"name"`
	Type        string                `json:"type"`
	ProjectKey  string                `json:"-"`
	Author      string                `json:"author,omitempty"` // Omitempty is used because the field is computed
	Description string                `json:"description"`
	Rules       *[]PolicyRuleAPIModel `json:"rules"`
	Created     string                `json:"created,omitempty"`  // Omitempty is used because the field is computed
	Modified    string                `json:"modified,omitempty"` // Omitempty is used because the field is computed
}

type PolicyError struct {
	Error string `json:"error"`
}

func (r *PolicyResource) Create(
	ctx context.Context,
	toAPIModel func(context.Context, PolicyResourceModel, *PolicyAPIModel) diag.Diagnostics,
	fromAPIModel func(context.Context, PolicyAPIModel, *PolicyResourceModel) diag.Diagnostics,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan PolicyResourceModel

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
	resp.Diagnostics.Append(toAPIModel(ctx, plan, &policy)...)
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

	resp.Diagnostics.Append(fromAPIModel(ctx, policy, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PolicyResource) Read(
	ctx context.Context,
	fromAPIModel func(context.Context, PolicyAPIModel, *PolicyResourceModel) diag.Diagnostics,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state PolicyResourceModel

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

	resp.Diagnostics.Append(fromAPIModel(ctx, policy, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PolicyResource) Update(
	ctx context.Context,
	toAPIModel func(context.Context, PolicyResourceModel, *PolicyAPIModel) diag.Diagnostics,
	fromAPIModel func(context.Context, PolicyAPIModel, *PolicyResourceModel) diag.Diagnostics,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan PolicyResourceModel

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
	resp.Diagnostics.Append(toAPIModel(ctx, plan, &policy)...)
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

	resp.Diagnostics.Append(fromAPIModel(ctx, policy, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state PolicyResourceModel

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
func (r *PolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}
