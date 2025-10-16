package xray

import (
	"context"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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

const BinaryManagerReleaseBundleV2Endpoint = "xray/api/v1/binMgr/{id}/release_bundle_v2"

var _ resource.Resource = &BinaryManagerReleaseBundlesV2Resource{}

func NewBinaryManagerReleaseBundlesV2Resource() resource.Resource {
	return &BinaryManagerReleaseBundlesV2Resource{
		TypeName: "xray_binary_manager_release_bundles_v2",
	}
}

type BinaryManagerReleaseBundlesV2Resource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *BinaryManagerReleaseBundlesV2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type BinaryManagerReleaseBundlesV2ResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	ProjectKey                 types.String `tfsdk:"project_key"`
	IndexedReleaseBundlesV2    types.Set    `tfsdk:"indexed_release_bundle_v2"`
	NonIndexedReleaseBundlesV2 types.Set    `tfsdk:"non_indexed_release_bundle_v2"`
}

func (m BinaryManagerReleaseBundlesV2ResourceModel) toAPIModel(ctx context.Context, apiModel *BinaryManagerReleaseBundlesV2APIModel) (ds diag.Diagnostics) {
	var indexedReleaseBundlesV2 []string
	ds.Append(m.IndexedReleaseBundlesV2.ElementsAs(ctx, &indexedReleaseBundlesV2, false)...)

	*apiModel = BinaryManagerReleaseBundlesV2APIModel{
		BinManagerID:            m.ID.ValueString(),
		IndexedReleaseBundlesV2: indexedReleaseBundlesV2,
	}

	return
}

// stripReleaseBundleV2Prefix removes the "[repo-type]/" prefix from release bundle names
// that the API returns. For example: "[release-bundles-v2]/bundle-name" -> "bundle-name"
func stripReleaseBundleV2Prefix(name string) string {
	if idx := strings.Index(name, "]/"); idx != -1 {
		return name[idx+2:]
	}
	return name
}

func (m *BinaryManagerReleaseBundlesV2ResourceModel) fromAPIModel(ctx context.Context, apiModel BinaryManagerReleaseBundlesV2APIModel, preserveIndexed bool) (ds diag.Diagnostics) {
	m.ID = types.StringValue(apiModel.BinManagerID)

	// Only update IndexedReleaseBundlesV2 from API during Read (not Create/Update)
	// This avoids "inconsistent result after apply" errors when API returns
	// different ordering or timing-delayed results
	if !preserveIndexed {
		// Strip the "[repo-type]/" prefix from each release bundle name
		strippedIndexed := make([]string, len(apiModel.IndexedReleaseBundlesV2))
		for i, name := range apiModel.IndexedReleaseBundlesV2 {
			strippedIndexed[i] = stripReleaseBundleV2Prefix(name)
		}
		indexedReleaseBundlesV2, d := types.SetValueFrom(ctx, types.StringType, strippedIndexed)
		if d != nil {
			ds.Append(d...)
		}
		m.IndexedReleaseBundlesV2 = indexedReleaseBundlesV2
	}

	// Strip the "[repo-type]/" prefix from each non-indexed release bundle name
	strippedNonIndexed := make([]string, len(apiModel.NonIndexedReleaseBundlesV2))
	for i, name := range apiModel.NonIndexedReleaseBundlesV2 {
		strippedNonIndexed[i] = stripReleaseBundleV2Prefix(name)
	}
	nonIndexedBuilds, d := types.SetValueFrom(ctx, types.StringType, strippedNonIndexed)
	if d != nil {
		ds.Append(d...)
	}
	m.NonIndexedReleaseBundlesV2 = nonIndexedBuilds

	return
}

type BinaryManagerReleaseBundlesV2APIModel struct {
	BinManagerID               string   `json:"bin_mgr_id"`
	IndexedReleaseBundlesV2    []string `json:"indexed_release_bundle_v2"`
	NonIndexedReleaseBundlesV2 []string `json:"non_indexed_release_bundle_v2"`
}

func (r *BinaryManagerReleaseBundlesV2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"indexed_release_bundle_v2": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						validatorfw_string.RegexNotMatches(regexp.MustCompile(`[\*|\*\*|\?]+`), "cannot contain Ant-style patterns ('*', '**', or '?')"),
					),
				},
				MarkdownDescription: "Release Bundles V2 to be indexed.\n\n~>Currently does not support Ant-style path patterns (`*`, `**`, or `?`) due to API limitation.",
			},
			"non_indexed_release_bundle_v2": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Non-indexed Release Bundles V2 for output.",
			},
		},
		MarkdownDescription: "Provides an Xray Binary Manager Release Bundles V2 Indexing configuration resource. See [Indexing Xray Resources](https://jfrog.com/help/r/jfrog-security-documentation/add-or-remove-resources-from-indexing) " +
			"and [REST API](https://jfrog.com/help/r/xray-rest-apis/add-release-bundles-v2-indexing-configuration) for more details.",
	}
}

func (r *BinaryManagerReleaseBundlesV2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *BinaryManagerReleaseBundlesV2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerReleaseBundlesV2ResourceModel

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

	var releaseBundles BinaryManagerReleaseBundlesV2APIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &releaseBundles)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(releaseBundles).
		Put(BinaryManagerReleaseBundleV2Endpoint)
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
		SetResult(&releaseBundles).
		Get(BinaryManagerReleaseBundleV2Endpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// Pass true to preserve IndexedReleaseBundlesV2 from plan to avoid
	// "inconsistent result after apply" when API returns different data
	resp.Diagnostics.Append(plan.fromAPIModel(ctx, releaseBundles, true)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerReleaseBundlesV2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state BinaryManagerReleaseBundlesV2ResourceModel

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

	var releaseBundles BinaryManagerReleaseBundlesV2APIModel

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		SetResult(&releaseBundles).
		Get(BinaryManagerReleaseBundleV2Endpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	// Pass false to use API response during Read
	resp.Diagnostics.Append(state.fromAPIModel(ctx, releaseBundles, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *BinaryManagerReleaseBundlesV2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan BinaryManagerReleaseBundlesV2ResourceModel

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

	var releaseBundles BinaryManagerReleaseBundlesV2APIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &releaseBundles)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("id", plan.ID.ValueString()).
		SetBody(releaseBundles).
		Put(BinaryManagerReleaseBundleV2Endpoint)
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
		SetResult(&releaseBundles).
		Get(BinaryManagerReleaseBundleV2Endpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// Pass true to preserve IndexedReleaseBundlesV2 from plan to avoid
	// "inconsistent result after apply" when API returns different data
	resp.Diagnostics.Append(plan.fromAPIModel(ctx, releaseBundles, true)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BinaryManagerReleaseBundlesV2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state BinaryManagerReleaseBundlesV2ResourceModel

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

	var nonIndexedReleaseBundlesV2 []string
	resp.Diagnostics.Append(state.IndexedReleaseBundlesV2.ElementsAs(ctx, &nonIndexedReleaseBundlesV2, false)...)
	releaseBundles := BinaryManagerReleaseBundlesV2APIModel{
		BinManagerID:               state.ID.ValueString(),
		NonIndexedReleaseBundlesV2: nonIndexedReleaseBundlesV2,
	}

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		SetBody(releaseBundles).
		Put(BinaryManagerReleaseBundleV2Endpoint)
	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *BinaryManagerReleaseBundlesV2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}
