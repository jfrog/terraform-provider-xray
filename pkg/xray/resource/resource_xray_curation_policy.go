package xray

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
)

// decisionOwnersRequiredValidator validates that decision_owners is provided when waiver_request_config is "manual"
type decisionOwnersRequiredValidator struct{}

func (v decisionOwnersRequiredValidator) Description(ctx context.Context) string {
	return "validates that decision_owners is provided and non-empty when waiver_request_config is 'manual'"
}

func (v decisionOwnersRequiredValidator) MarkdownDescription(ctx context.Context) string {
	return "validates that decision_owners is provided and non-empty when waiver_request_config is 'manual'"
}

func (v decisionOwnersRequiredValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	// If waiver_request_config is "manual", decision_owners must be provided and non-empty
	if req.ConfigValue.ValueString() == "manual" {
		var decisionOwnersValue attr.Value
		diags := req.Config.GetAttribute(ctx, path.Root("decision_owners"), &decisionOwnersValue)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}

		// Check if decision_owners is null, unknown, or empty
		if decisionOwnersValue.IsNull() || decisionOwnersValue.IsUnknown() {
			resp.Diagnostics.AddAttributeError(
				path.Root("decision_owners"),
				"Decision owners required",
				"Decision owners are required when waiver requests are manually approved (waiver_request_config = 'manual')",
			)
			return
		}

		// Check if the set is empty
		if setVal, ok := decisionOwnersValue.(types.Set); ok {
			if len(setVal.Elements()) == 0 {
				resp.Diagnostics.AddAttributeError(
					path.Root("decision_owners"),
					"Decision owners required",
					"Decision owners are required when waiver requests are manually approved (waiver_request_config = 'manual')",
				)
			}
		}
	}
}

// packageVersionsRequiredValidator validates that pkg_versions is provided when all_versions is false,
// and that pkg_versions is empty when all_versions is true
type packageVersionsRequiredValidator struct{}

func (v packageVersionsRequiredValidator) Description(ctx context.Context) string {
	return "validates that pkg_versions is provided when all_versions is false, and empty when all_versions is true"
}

func (v packageVersionsRequiredValidator) MarkdownDescription(ctx context.Context) string {
	return "validates that pkg_versions is provided when all_versions is false, and empty when all_versions is true"
}

func (v packageVersionsRequiredValidator) ValidateSet(ctx context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsUnknown() {
		return
	}

	// Get the all_versions value from the parent object
	var allVersionsValue attr.Value
	diags := req.Config.GetAttribute(ctx, req.Path.ParentPath().AtName("all_versions"), &allVersionsValue)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if allVersionsValue.IsNull() || allVersionsValue.IsUnknown() {
		return
	}

	allVersionsBool, ok := allVersionsValue.(types.Bool)
	if !ok {
		return
	}

	if allVersionsBool.ValueBool() {
		// When all_versions is true, pkg_versions should be empty or null
		if !req.ConfigValue.IsNull() && len(req.ConfigValue.Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Package versions not allowed",
				"When all_versions is true, pkg_versions should not be specified",
			)
		}
	} else {
		// When all_versions is false, pkg_versions must contain at least one version
		if req.ConfigValue.IsNull() || len(req.ConfigValue.Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Package versions required",
				"When all_versions is false, pkg_versions must contain at least one version",
			)
		}
	}
}

// scopeRequirementsValidator validates all scope-dependent requirements
type scopeRequirementsValidator struct{}

func (v scopeRequirementsValidator) Description(ctx context.Context) string {
	return "validates that required fields are provided based on the scope value"
}

func (v scopeRequirementsValidator) MarkdownDescription(ctx context.Context) string {
	return "validates that required fields are provided based on the scope value"
}

func (v scopeRequirementsValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	scope := req.ConfigValue.ValueString()

	// Get the repo_include value
	var repoIncludeValue attr.Value
	diags := req.Config.GetAttribute(ctx, path.Root("repo_include"), &repoIncludeValue)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Get the pkg_types_include value
	var pkgTypesIncludeValue attr.Value
	diags = req.Config.GetAttribute(ctx, path.Root("pkg_types_include"), &pkgTypesIncludeValue)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Get the repo_exclude value
	var repoExcludeValue attr.Value
	diags = req.Config.GetAttribute(ctx, path.Root("repo_exclude"), &repoExcludeValue)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Check requirements based on scope
	switch scope {
	case "specific_repos":
		// repo_include is mandatory
		if repoIncludeValue.IsNull() || (repoIncludeValue.(types.Set)).IsNull() || len((repoIncludeValue.(types.Set)).Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_include"),
				"Repository include required",
				"When scope is 'specific_repos', repo_include must contain at least one repository",
			)
		}

		// pkg_types_include and repo_exclude should not be used
		if !pkgTypesIncludeValue.IsNull() && len((pkgTypesIncludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("pkg_types_include"),
				"Package types include not allowed",
				"pkg_types_include cannot be used when scope is 'specific_repos'",
			)
		}
		if !repoExcludeValue.IsNull() && len((repoExcludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_exclude"),
				"Repository exclude not allowed",
				"repo_exclude cannot be used when scope is 'specific_repos'",
			)
		}

	case "pkg_types":
		// pkg_types_include is mandatory
		if pkgTypesIncludeValue.IsNull() || (pkgTypesIncludeValue.(types.Set)).IsNull() || len((pkgTypesIncludeValue.(types.Set)).Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("pkg_types_include"),
				"Package types include required",
				"When scope is 'pkg_types', pkg_types_include must contain at least one package type",
			)
		}

		// repo_include and repo_exclude should not be used
		if !repoIncludeValue.IsNull() && len((repoIncludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_include"),
				"Repository include not allowed",
				"repo_include cannot be used when scope is 'pkg_types'",
			)
		}
		if !repoExcludeValue.IsNull() && len((repoExcludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_exclude"),
				"Repository exclude not allowed",
				"repo_exclude cannot be used when scope is 'pkg_types'",
			)
		}

	case "all_repos":
		// repo_include and pkg_types_include should not be used
		if !repoIncludeValue.IsNull() && len((repoIncludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_include"),
				"Repository include not allowed",
				"repo_include cannot be used when scope is 'all_repos'",
			)
		}
		if !pkgTypesIncludeValue.IsNull() && len((pkgTypesIncludeValue.(types.Set)).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("pkg_types_include"),
				"Package types include not allowed",
				"pkg_types_include cannot be used when scope is 'all_repos'",
			)
		}

		// repo_exclude is optional but if provided, cannot be empty
		if !repoExcludeValue.IsNull() && len((repoExcludeValue.(types.Set)).Elements()) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("repo_exclude"),
				"Repository exclude cannot be empty",
				"When repo_exclude is specified, it must contain at least one repository",
			)
		}
	}
}

var _ resource.Resource = &CurationPolicyResource{}

type CurationPolicyResource struct {
	util.JFrogResource
}

func NewCurationPolicyResource() resource.Resource {
	return &CurationPolicyResource{
		JFrogResource: util.JFrogResource{
			TypeName:              "xray_curation_policy",
			ValidXrayVersion:      "3.116.0",
			CatalogHealthRequired: true,
		},
	}
}

type CurationPolicyResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	ConditionID         types.String `tfsdk:"condition_id"`
	Scope               types.String `tfsdk:"scope"`
	RepoExclude         types.Set    `tfsdk:"repo_exclude"`
	RepoInclude         types.Set    `tfsdk:"repo_include"`
	PkgTypesInclude     types.Set    `tfsdk:"pkg_types_include"`
	PolicyAction        types.String `tfsdk:"policy_action"`
	Waivers             types.Set    `tfsdk:"waivers"`
	LabelWaivers        types.Set    `tfsdk:"label_waivers"`
	NotifyEmails        types.Set    `tfsdk:"notify_emails"`
	WaiverRequestConfig types.String `tfsdk:"waiver_request_config"`
	DecisionOwners      types.Set    `tfsdk:"decision_owners"`
}

type PackageWaiverModel struct {
	PkgType       types.String `tfsdk:"pkg_type"`
	PkgName       types.String `tfsdk:"pkg_name"`
	AllVersions   types.Bool   `tfsdk:"all_versions"`
	PkgVersions   types.Set    `tfsdk:"pkg_versions"`
	Justification types.String `tfsdk:"justification"`
}

type LabelWaiverModel struct {
	Label         types.String `tfsdk:"label"`
	Justification types.String `tfsdk:"justification"`
}

type PackageWaiverAPIModel struct {
	PkgType       string   `json:"pkg_type"`
	PkgName       string   `json:"pkg_name"`
	AllVersions   bool     `json:"all_versions"`
	PkgVersions   []string `json:"pkg_versions,omitempty"`
	Justification string   `json:"justification"`
}

type LabelWaiverAPIModel struct {
	Label         string `json:"label"`
	Justification string `json:"justification"`
}

type CurationPolicyAPIModel struct {
	ID                  string                  `json:"id,omitempty"`
	Name                string                  `json:"name"`
	ConditionID         string                  `json:"condition_id"`
	Scope               string                  `json:"scope"`
	RepoExclude         []string                `json:"repo_exclude,omitempty"`
	RepoInclude         []string                `json:"repo_include,omitempty"`
	PkgTypesInclude     []string                `json:"pkg_types_include,omitempty"`
	PolicyAction        string                  `json:"policy_action"`
	Waivers             []PackageWaiverAPIModel `json:"waivers,omitempty"`
	LabelWaivers        []LabelWaiverAPIModel   `json:"label_waivers,omitempty"`
	NotifyEmails        []string                `json:"notify_emails,omitempty"`
	WaiverRequestConfig string                  `json:"waiver_request_config,omitempty"`
	DecisionOwners      []string                `json:"decision_owners,omitempty"`
}

const (
	CurationPolicyEndpoint = "xray/api/v1/curation/policies"
)

func (r *CurationPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "xray_curation_policy"
	r.TypeName = resp.TypeName
}

func (r *CurationPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "ID of the policy, used in path parameters to update or delete the policy.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"condition_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the condition used by the policy.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^\d+$`), "condition_id must be a numeric string (e.g., '3', '146')"),
				},
			},
			"scope": schema.StringAttribute{
				Required:    true,
				Description: "One of: all_repos, specific_repos or pkg_types.",
				Validators: []validator.String{
					stringvalidator.OneOf("all_repos", "specific_repos", "pkg_types"),
					scopeRequirementsValidator{},
				},
			},
			"repo_exclude": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Used with scope: all_repos. List of repositories to exclude.",
			},
			"repo_include": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Used with scope: specific_repos. List of repositories to include.",
			},
			"pkg_types_include": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Used with scope: pkg_types. List of package types to include.",
			},
			"policy_action": schema.StringAttribute{
				Required:    true,
				Description: "One of: block or dry_run. Dry run policies only accumulate audit logs, they don't block packages from being downloaded.",
				Validators: []validator.String{
					stringvalidator.OneOf("block", "dry_run"),
				},
			},
			"waivers": schema.SetNestedAttribute{
				Optional:    true,
				Description: "List of package waivers.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"pkg_type": schema.StringAttribute{
							Required:    true,
							Description: "Package type. One of: npm, PyPI, Maven, Go, NuGet, Conan, Gems, Gradle, HuggingFaceML or Docker.",
						},
						"pkg_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of package from Catalog.",
						},
						"all_versions": schema.BoolAttribute{
							Optional:    true,
							Description: "Set to true to indicate all versions.",
						},
						"pkg_versions": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "List of specific versions of the package from the Catalog.",
							Validators: []validator.Set{
								packageVersionsRequiredValidator{},
							},
						},
						"justification": schema.StringAttribute{
							Required:    true,
							Description: "A way to document why the waiver was created.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
					},
				},
			},
			"label_waivers": schema.SetNestedAttribute{
				Optional:    true,
				Description: "List of label waivers.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"label": schema.StringAttribute{
							Required:    true,
							Description: "A label from the custom Catalog.",
						},
						"justification": schema.StringAttribute{
							Required:    true,
							Description: "A way to document why the waiver was created.",
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
					},
				},
			},
			"notify_emails": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of email addresses that receive notifications when the policy causes a package to be blocked.",
			},
			"waiver_request_config": schema.StringAttribute{
				Optional:    true,
				Description: "One of: forbidden, manual or auto_approved.",
				Validators: []validator.String{
					stringvalidator.OneOf("forbidden", "manual", "auto_approved"),
					decisionOwnersRequiredValidator{},
				},
			},
			"decision_owners": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of JFrog Access groups used by waiver_request_config=manual",
			},
		},
		MarkdownDescription: "Provides an Xray curation policy resource. This resource allows you to create, read, update, and delete curation policies in Xray. See [JFrog Curation REST APIs](https://jfrog.com/help/r/jfrog-rest-apis/create-curation-policy) [Official documentation](https://jfrog.com/help/r/jfrog-security-user-guide/products/curation/configure-curation/create-policies) for more details. \n\n" +
			"~> Requires JFrog Catalog service to be available.",
	}
}

func (r *CurationPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	providerData := req.ProviderData.(util.ProviderMetadata)
	r.ProviderData = &providerData

	// Perform catalog health check if this resource requires it
	err := r.JFrogResource.ValidateCatalogHealth(&providerData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Catalog Health Check Failed",
			fmt.Sprintf("Resource requires catalog functionality but catalog health check failed: %s", err.Error()),
		)
		return
	}
}

func (r *CurationPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	// Call the Xray version validation from the embedded JFrogResource
	r.JFrogResource.ValidateXrayConfig(ctx, req, resp)
}

func (r *CurationPolicyResource) toAPIModel(ctx context.Context, plan CurationPolicyResourceModel, policy *CurationPolicyAPIModel) diag.Diagnostics {
	policy.Name = plan.Name.ValueString()
	policy.ConditionID = plan.ConditionID.ValueString()
	policy.Scope = plan.Scope.ValueString()
	policy.PolicyAction = plan.PolicyAction.ValueString()

	if !plan.WaiverRequestConfig.IsNull() {
		policy.WaiverRequestConfig = plan.WaiverRequestConfig.ValueString()
	}

	// Convert repo_exclude
	if !plan.RepoExclude.IsNull() {
		var repoExclude []string
		diags := plan.RepoExclude.ElementsAs(ctx, &repoExclude, false)
		if diags.HasError() {
			return diags
		}
		policy.RepoExclude = repoExclude
	}

	// Convert repo_include
	if !plan.RepoInclude.IsNull() {
		var repoInclude []string
		diags := plan.RepoInclude.ElementsAs(ctx, &repoInclude, false)
		if diags.HasError() {
			return diags
		}
		policy.RepoInclude = repoInclude
	}

	// Convert pkg_types_include
	if !plan.PkgTypesInclude.IsNull() {
		var pkgTypesInclude []string
		diags := plan.PkgTypesInclude.ElementsAs(ctx, &pkgTypesInclude, false)
		if diags.HasError() {
			return diags
		}
		policy.PkgTypesInclude = pkgTypesInclude
	}

	// Convert notify_emails
	if !plan.NotifyEmails.IsNull() {
		var notifyEmails []string
		diags := plan.NotifyEmails.ElementsAs(ctx, &notifyEmails, false)
		if diags.HasError() {
			return diags
		}
		policy.NotifyEmails = notifyEmails
	}

	// Convert decision_owners
	if !plan.DecisionOwners.IsNull() {
		var decisionOwners []string
		diags := plan.DecisionOwners.ElementsAs(ctx, &decisionOwners, false)
		if diags.HasError() {
			return diags
		}
		policy.DecisionOwners = decisionOwners
	}

	// Convert waivers
	if !plan.Waivers.IsNull() {
		var waiverModels []PackageWaiverModel
		diags := plan.Waivers.ElementsAs(ctx, &waiverModels, false)
		if diags.HasError() {
			return diags
		}

		var waivers []PackageWaiverAPIModel
		for _, waiverModel := range waiverModels {
			waiver := PackageWaiverAPIModel{
				PkgType:       waiverModel.PkgType.ValueString(),
				PkgName:       waiverModel.PkgName.ValueString(),
				AllVersions:   waiverModel.AllVersions.ValueBool(),
				Justification: waiverModel.Justification.ValueString(),
			}

			// Only set PkgVersions if all_versions is false and pkg_versions is provided
			if !waiverModel.AllVersions.ValueBool() && !waiverModel.PkgVersions.IsNull() {
				var pkgVersions []string
				diags := waiverModel.PkgVersions.ElementsAs(ctx, &pkgVersions, false)
				if diags.HasError() {
					return diags
				}
				waiver.PkgVersions = pkgVersions
			}

			waivers = append(waivers, waiver)
		}
		policy.Waivers = waivers
	}

	// Convert label_waivers
	if !plan.LabelWaivers.IsNull() {
		var labelWaiverModels []LabelWaiverModel
		diags := plan.LabelWaivers.ElementsAs(ctx, &labelWaiverModels, false)
		if diags.HasError() {
			return diags
		}

		var labelWaivers []LabelWaiverAPIModel
		for _, labelWaiverModel := range labelWaiverModels {
			labelWaiver := LabelWaiverAPIModel{
				Label:         labelWaiverModel.Label.ValueString(),
				Justification: labelWaiverModel.Justification.ValueString(),
			}

			labelWaivers = append(labelWaivers, labelWaiver)
		}
		policy.LabelWaivers = labelWaivers
	}
	// If no label_waivers, leave plan.LabelWaivers as null (don't force empty set)

	return nil
}

func (r *CurationPolicyResource) fromAPIModel(ctx context.Context, policy CurationPolicyAPIModel, plan *CurationPolicyResourceModel) diag.Diagnostics {
	plan.ID = types.StringValue(policy.ID)
	plan.Name = types.StringValue(policy.Name)
	plan.ConditionID = types.StringValue(policy.ConditionID)
	plan.Scope = types.StringValue(policy.Scope)
	plan.PolicyAction = types.StringValue(policy.PolicyAction)
	plan.WaiverRequestConfig = types.StringValue(policy.WaiverRequestConfig)

	// Convert string arrays to sets
	if len(policy.RepoExclude) > 0 {
		repoExclude := make([]attr.Value, len(policy.RepoExclude))
		for i, repo := range policy.RepoExclude {
			repoExclude[i] = types.StringValue(repo)
		}
		repoExcludeSet, diags := types.SetValue(types.StringType, repoExclude)
		if diags.HasError() {
			return diags
		}
		plan.RepoExclude = repoExcludeSet
	}

	if len(policy.RepoInclude) > 0 {
		repoInclude := make([]attr.Value, len(policy.RepoInclude))
		for i, repo := range policy.RepoInclude {
			repoInclude[i] = types.StringValue(repo)
		}
		repoIncludeSet, diags := types.SetValue(types.StringType, repoInclude)
		if diags.HasError() {
			return diags
		}
		plan.RepoInclude = repoIncludeSet
	}

	if len(policy.PkgTypesInclude) > 0 {
		pkgTypes := make([]attr.Value, len(policy.PkgTypesInclude))
		for i, pkgType := range policy.PkgTypesInclude {
			pkgTypes[i] = types.StringValue(pkgType)
		}
		pkgTypesSet, diags := types.SetValue(types.StringType, pkgTypes)
		if diags.HasError() {
			return diags
		}
		plan.PkgTypesInclude = pkgTypesSet
	}

	if len(policy.NotifyEmails) > 0 {
		emails := make([]attr.Value, len(policy.NotifyEmails))
		for i, email := range policy.NotifyEmails {
			emails[i] = types.StringValue(email)
		}
		emailsSet, diags := types.SetValue(types.StringType, emails)
		if diags.HasError() {
			return diags
		}
		plan.NotifyEmails = emailsSet
	}

	if len(policy.DecisionOwners) > 0 {
		owners := make([]attr.Value, len(policy.DecisionOwners))
		for i, owner := range policy.DecisionOwners {
			owners[i] = types.StringValue(owner)
		}
		ownersSet, diags := types.SetValue(types.StringType, owners)
		if diags.HasError() {
			return diags
		}
		plan.DecisionOwners = ownersSet
	}

	// Convert waivers from API to Terraform model (only if present)
	if len(policy.Waivers) > 0 {
		waiverAttrs := map[string]attr.Type{
			"pkg_type":      types.StringType,
			"pkg_name":      types.StringType,
			"all_versions":  types.BoolType,
			"pkg_versions":  types.SetType{ElemType: types.StringType},
			"justification": types.StringType,
		}

		waiverValues := make([]attr.Value, len(policy.Waivers))
		for i, waiver := range policy.Waivers {
			// Convert pkg_versions to set or null
			var pkgVersionsSet types.Set
			if waiver.AllVersions {
				// When all_versions is true, pkg_versions should be null
				pkgVersionsSet = types.SetNull(types.StringType)
			} else if len(waiver.PkgVersions) > 0 {
				pkgVersionValues := make([]attr.Value, len(waiver.PkgVersions))
				for j, version := range waiver.PkgVersions {
					pkgVersionValues[j] = types.StringValue(version)
				}
				set, diags := types.SetValue(types.StringType, pkgVersionValues)
				if diags.HasError() {
					return diags
				}
				pkgVersionsSet = set
			} else {
				// When all_versions is false but no versions provided, create empty set
				set, diags := types.SetValue(types.StringType, []attr.Value{})
				if diags.HasError() {
					return diags
				}
				pkgVersionsSet = set
			}

			waiverValue, diags := types.ObjectValue(waiverAttrs, map[string]attr.Value{
				"pkg_type":      types.StringValue(waiver.PkgType),
				"pkg_name":      types.StringValue(waiver.PkgName),
				"all_versions":  types.BoolValue(waiver.AllVersions),
				"pkg_versions":  pkgVersionsSet,
				"justification": types.StringValue(waiver.Justification),
			})
			if diags.HasError() {
				return diags
			}
			waiverValues[i] = waiverValue
		}

		waiversSet, diags := types.SetValue(types.ObjectType{AttrTypes: waiverAttrs}, waiverValues)
		if diags.HasError() {
			return diags
		}
		plan.Waivers = waiversSet
	}
	// If no waivers, leave plan.Waivers as null (don't force empty set)

	// Convert label_waivers from API to Terraform model (only if present)
	if len(policy.LabelWaivers) > 0 {
		labelWaiverAttrs := map[string]attr.Type{
			"label":         types.StringType,
			"justification": types.StringType,
		}

		labelWaiverValues := make([]attr.Value, len(policy.LabelWaivers))
		for i, labelWaiver := range policy.LabelWaivers {
			labelWaiverValue, diags := types.ObjectValue(labelWaiverAttrs, map[string]attr.Value{
				"label":         types.StringValue(labelWaiver.Label),
				"justification": types.StringValue(labelWaiver.Justification),
			})
			if diags.HasError() {
				return diags
			}
			labelWaiverValues[i] = labelWaiverValue
		}

		labelWaiversSet, diags := types.SetValue(types.ObjectType{AttrTypes: labelWaiverAttrs}, labelWaiverValues)
		if diags.HasError() {
			return diags
		}
		plan.LabelWaivers = labelWaiversSet
	}
	// If no label_waivers, leave plan.LabelWaivers as null (don't force empty set)

	return nil
}

func (r *CurationPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan CurationPolicyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policy CurationPolicyAPIModel
	resp.Diagnostics.Append(r.toAPIModel(ctx, plan, &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the curation policy
	response, err := r.ProviderData.Client.R().
		SetBody(policy).
		SetResult(&policy).
		Post(CurationPolicyEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(r.fromAPIModel(ctx, policy, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CurationPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CurationPolicyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the curation policy
	var policy CurationPolicyAPIModel
	response, err := r.ProviderData.Client.R().
		SetResult(&policy).
		Get(fmt.Sprintf("%s/%s", CurationPolicyEndpoint, state.ID.ValueString()))

	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	// Handle 404 - resource no longer exists
	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(r.fromAPIModel(ctx, policy, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CurationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan CurationPolicyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var policy CurationPolicyAPIModel
	resp.Diagnostics.Append(r.toAPIModel(ctx, plan, &policy)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the curation policy
	response, err := r.ProviderData.Client.R().
		SetBody(policy).
		SetResult(&policy).
		Put(fmt.Sprintf("%s/%s", CurationPolicyEndpoint, plan.ID.ValueString()))

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// Convert the response back to the model
	resp.Diagnostics.Append(r.fromAPIModel(ctx, policy, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CurationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state CurationPolicyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the curation policy
	response, err := r.ProviderData.Client.R().
		Delete(fmt.Sprintf("%s/%s", CurationPolicyEndpoint, state.ID.ValueString()))

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	// Ignore 404 errors as the resource may already be deleted
	if response.IsError() && response.StatusCode() != http.StatusNotFound {
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

func (r *CurationPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Set the ID to the imported resource ID
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
