package xray

import (
	"context"
	"fmt"
	"strings"

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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const BinaryManagerReposEndpoint = "xray/api/v1/binMgr/{id}/repos"

var _ resource.Resource = &WebhookResource{}

func NewBinaryManagerReposResource() resource.Resource {
	return &BinaryManagerReposResource{}
}

type BinaryManagerReposResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *BinaryManagerReposResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_binary_manager_repos"
	r.TypeName = resp.TypeName
}

type BinaryManagerReposResourceModel struct {
	ID              types.String `tfsdk:"id"`
	ProjectKey      types.String `tfsdk:"project_key"`
	IndexedRepos    types.Set    `tfsdk:"indexed_repos"`
	NonIndexedRepos types.Set    `tfsdk:"non_indexed_repos"`
}

func (m BinaryManagerReposResourceModel) toAPIModel(apiModel *BinaryManagerReposAPIModel) diag.Diagnostics {
	var mapRepo = func(elem attr.Value, _ int) BinaryManagerRepoAPIModel {
		attrs := elem.(types.Object).Attributes()

		return BinaryManagerRepoAPIModel{
			Name:        attrs["name"].(types.String).ValueString(),
			Type:        attrs["type"].(types.String).ValueString(),
			PackageType: attrs["package_type"].(types.String).ValueString(),
		}
	}

	indexedRepos := lo.Map(
		m.IndexedRepos.Elements(),
		mapRepo,
	)

	*apiModel = BinaryManagerReposAPIModel{
		BinManagerID: m.ID.ValueString(),
		IndexedRepos: indexedRepos,
	}

	return nil
}

var repoResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"name":         types.StringType,
	"type":         types.StringType,
	"package_type": types.StringType,
}

var repoSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: repoResourceModelAttributeTypes,
}

func (m *BinaryManagerReposResourceModel) fromAPIModel(apiModel BinaryManagerReposAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	m.ID = types.StringValue(apiModel.BinManagerID)

	indexedRepos, ds := m.fromRepoAPIModel(apiModel.IndexedRepos)
	if ds != nil {
		diags = append(diags, ds...)
	}
	m.IndexedRepos = indexedRepos

	nonIndexedRepos, ds := m.fromRepoAPIModel(apiModel.NonIndexedRepos)
	if ds != nil {
		diags = append(diags, ds...)
	}
	m.NonIndexedRepos = nonIndexedRepos

	return diags
}

func (m BinaryManagerReposResourceModel) fromRepoAPIModel(repoAPIModels []BinaryManagerRepoAPIModel) (basetypes.SetValue, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	repos := lo.Map(
		repoAPIModels,
		func(property BinaryManagerRepoAPIModel, _ int) attr.Value {
			repo, ds := types.ObjectValue(
				repoResourceModelAttributeTypes,
				map[string]attr.Value{
					"name":         types.StringValue(property.Name),
					"type":         types.StringValue(property.Type),
					"package_type": types.StringValue(property.PackageType),
				},
			)

			if ds != nil {
				diags = append(diags, ds...)
			}

			return repo
		},
	)

	return types.SetValue(
		repoSetResourceModelAttributeTypes,
		repos,
	)
}

type BinaryManagerReposAPIModel struct {
	BinManagerID    string                      `json:"bin_mgr_id"`
	IndexedRepos    []BinaryManagerRepoAPIModel `json:"indexed_repos"`
	NonIndexedRepos []BinaryManagerRepoAPIModel `json:"non_indexed_repos"`
}

type BinaryManagerRepoAPIModel struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	PackageType string `json:"pkg_type"`
}

var validTitledPackageTypes = lo.Map(validPackageTypes, func(packageType string, _ int) string {
	caser := cases.Title(language.AmericanEnglish, cases.NoLower)
	return caser.String(packageType)
})

func (r *BinaryManagerReposResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "ID of the binary manager, e.g. 'default'",
			},
			"project_key": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validatorfw_string.ProjectKey(),
				},
				Description: "For Xray version 3.21.2 and above with Projects, a Project Admin with Index Resources privilege can maintain the indexed and not indexed repositories in a given binary manger using this resource in the scope of a project.",
			},
			"indexed_repos": schema.SetNestedAttribute{
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								validatorfw_string.RepoKey(),
							},
							Description: "Name of the repository",
						},
						"type": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf("local", "remote", "federated"),
							},
							Description: "Repository type. Valid value: local, remote, federated",
						},
						"package_type": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf(validTitledPackageTypes...),
							},
							Description: fmt.Sprintf("Artifactory package type. Valid value: %s", strings.Join(validTitledPackageTypes, ", ")),
						},
					},
				},
				Optional:    true,
				Description: "Repositories to be indexed.",
			},
			"non_indexed_repos": schema.SetNestedAttribute{
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":         schema.StringAttribute{Required: true},
						"type":         schema.StringAttribute{Required: true},
						"package_type": schema.StringAttribute{Required: true},
					},
				},
				Computed:    true,
				Description: "Non-indexed repositories for output.",
			},
		},
		Description: "Provides an Xray Binary Manager Repository Indexing configuration resource. See [Indexing Xray Resources](https://jfrog.com/help/r/jfrog-security-documentation/add-or-remove-resources-from-indexing) " +
			"and [REST API](https://jfrog.com/help/r/xray-rest-apis/update-repos-indexing-configuration) for more details.",
	}
}

func (r *BinaryManagerReposResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *BinaryManagerReposResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerReposResourceModel

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

	var repos BinaryManagerReposAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(&repos)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(repos).
		Put(BinaryManagerReposEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// get the indexed and non-indexed repos list since the PUT
	// doesn't return the list
	response, err = request.
		SetPathParam("id", plan.ID.ValueString()).
		SetResult(&repos).
		Get(BinaryManagerReposEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(repos)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerReposResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state BinaryManagerReposResourceModel

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

	var repos BinaryManagerReposAPIModel

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		SetResult(&repos).
		Get(BinaryManagerReposEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(repos)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *BinaryManagerReposResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerReposResourceModel

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

	var repos BinaryManagerReposAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(&repos)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(repos).
		Put(BinaryManagerReposEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// get the indexed and non-indexed repos list since the PUT
	// doesn't return the list
	response, err = request.
		SetPathParam("id", plan.ID.ValueString()).
		SetResult(&repos).
		Get(BinaryManagerReposEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(repos)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerReposResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	resp.Diagnostics.AddWarning(
		"Repository indexing configuration cannot be deleted",
		"The resource is deleted from Terraform but the repository indexing configuration remains unchanged in Xray.",
	)

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *BinaryManagerReposResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}
