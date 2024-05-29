package xray

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
)

const BinaryManagerBuildsEndpoint = "xray/api/v1/binMgr/{id}/builds"

var _ resource.Resource = &WebhookResource{}

func NewBinaryManagerBuildsResource() resource.Resource {
	return &BinaryManagerBuildsResource{}
}

type BinaryManagerBuildsResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *BinaryManagerBuildsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_binary_manager_builds"
	r.TypeName = resp.TypeName
}

type BinaryManagerBuildsResourceModel struct {
	ID               types.String `tfsdk:"id"`
	ProjectKey       types.String `tfsdk:"project_key"`
	IndexedBuilds    types.Set    `tfsdk:"indexed_builds"`
	NonIndexedBuilds types.Set    `tfsdk:"non_indexed_builds"`
}

func (m BinaryManagerBuildsResourceModel) toAPIModel(ctx context.Context, apiModel *BinaryManagerBuildsAPIModel) (ds diag.Diagnostics) {
	var indexedBuilds []string
	ds.Append(m.IndexedBuilds.ElementsAs(ctx, &indexedBuilds, false)...)

	*apiModel = BinaryManagerBuildsAPIModel{
		BinManagerID:  m.ID.ValueString(),
		IndexedBuilds: indexedBuilds,
	}

	return
}

func (m *BinaryManagerBuildsResourceModel) fromAPIModel(ctx context.Context, apiModel BinaryManagerBuildsAPIModel) (ds diag.Diagnostics) {
	m.ID = types.StringValue(apiModel.BinManagerID)

	indexedBuilds, d := types.SetValueFrom(ctx, types.StringType, apiModel.IndexedBuilds)
	if d != nil {
		ds.Append(d...)
	}
	m.IndexedBuilds = indexedBuilds

	nonIndexedBuilds, d := types.SetValueFrom(ctx, types.StringType, apiModel.NonIndexedBuilds)
	if d != nil {
		ds.Append(d...)
	}
	m.NonIndexedBuilds = nonIndexedBuilds

	return
}

type BinaryManagerBuildsAPIModel struct {
	BinManagerID     string   `json:"bin_mgr_id"`
	IndexedBuilds    []string `json:"indexed_builds"`
	NonIndexedBuilds []string `json:"non_indexed_builds"`
}

func (r *BinaryManagerBuildsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"indexed_builds": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Builds to be indexed.",
			},
			"non_indexed_builds": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Non-indexed builds for output.",
			},
		},
		Description: "Provides an Xray Binary Manager Builds Indexing configuration resource. See [Indexing Xray Resources](https://jfrog.com/help/r/jfrog-security-documentation/add-or-remove-resources-from-indexing) " +
			"and [REST API](https://jfrog.com/help/r/xray-rest-apis/update-builds-indexing-configuration) for more details.",
	}
}

func (r *BinaryManagerBuildsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *BinaryManagerBuildsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerBuildsResourceModel

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

	var builds BinaryManagerBuildsAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &builds)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(builds).
		Put(BinaryManagerBuildsEndpoint)
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
		SetResult(&builds).
		Get(BinaryManagerBuildsEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(ctx, builds)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerBuildsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state BinaryManagerBuildsResourceModel

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

	var builds BinaryManagerBuildsAPIModel

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		SetResult(&builds).
		Get(BinaryManagerBuildsEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, builds)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *BinaryManagerBuildsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerBuildsResourceModel

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

	var builds BinaryManagerBuildsAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &builds)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(builds).
		Put(BinaryManagerBuildsEndpoint)
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
		SetResult(&builds).
		Get(BinaryManagerBuildsEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(ctx, builds)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerBuildsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	resp.Diagnostics.AddWarning(
		"Repository indexing configuration cannot be deleted",
		"The resource is deleted from Terraform but the repository indexing configuration remains unchanged in Xray.",
	)

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *BinaryManagerBuildsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}
