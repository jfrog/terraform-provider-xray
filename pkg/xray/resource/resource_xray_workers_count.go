package xray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
	"github.com/samber/lo"
)

const WorkersCountEndpoint = "xray/api/v1/configuration/workersCount"

var _ resource.Resource = &WorkersCountResource{}

func NewWorkersCountResource() resource.Resource {
	return &WorkersCountResource{}
}

type WorkersCountResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *WorkersCountResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_workers_count"
	r.TypeName = resp.TypeName
}

type WorkersCountResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Index          types.Set    `tfsdk:"index"`
	Persist        types.Set    `tfsdk:"persist"`
	Alert          types.Set    `tfsdk:"alert"`
	Analysis       types.Set    `tfsdk:"analysis"`
	ImpactAnalysis types.Set    `tfsdk:"impact_analysis"`
	Notification   types.Set    `tfsdk:"notification"`
}

// WorkersCount uses Xray API which returns the follow JSON structure:
//
//	{
//	  "index": {
//	    "new_content": 4,
//	    "existing_content": 2
//	  },
//	  "persist": {
//	    "new_content": 4,
//	    "existing_content": 2
//	  },
//	  "analysis": {
//	    "new_content": 4,
//	    "existing_content": 2
//	  },
//	  "alert": {
//	    "new_content": 4,
//	    "existing_content": 2
//	  },
//	  "impact_analysis": {
//	    "new_content": 2
//	  },
//	  "notification": {
//	    "new_content": 2
//	  }
//	}
type WorkersCountAPIModel struct {
	Index          WorkersCountNewExistingContentAPIModel `json:"index"`
	Persist        WorkersCountNewExistingContentAPIModel `json:"persist"`
	Analysis       WorkersCountNewExistingContentAPIModel `json:"analysis"`
	Alert          WorkersCountNewExistingContentAPIModel `json:"alert"`
	ImpactAnalysis WorkersCountNewContentAPIModel         `json:"impact_analysis"`
	Notification   WorkersCountNewContentAPIModel         `json:"notification"`
}

func toNewExistingAPIModel(setValue types.Set) WorkersCountNewExistingContentAPIModel {
	elems := setValue.Elements()
	attrs := elems[0].(types.Object).Attributes()
	return WorkersCountNewExistingContentAPIModel{
		WorkersCountNewContentAPIModel: WorkersCountNewContentAPIModel{
			New: attrs["new_content"].(types.Int64).ValueInt64(),
		},
		Existing: attrs["existing_content"].(types.Int64).ValueInt64(),
	}
}

func toNewAPIModel(setValue types.Set) WorkersCountNewContentAPIModel {
	elems := setValue.Elements()
	attrs := elems[0].(types.Object).Attributes()
	return WorkersCountNewContentAPIModel{
		New: attrs["new_content"].(types.Int64).ValueInt64(),
	}
}

func (r WorkersCountResourceModel) toAPIModel(workersCount *WorkersCountAPIModel) {
	workersCount.Index = toNewExistingAPIModel(r.Index)
	workersCount.Persist = toNewExistingAPIModel(r.Persist)
	workersCount.Analysis = toNewExistingAPIModel(r.Analysis)
	workersCount.Alert = toNewExistingAPIModel(r.Alert)
	workersCount.ImpactAnalysis = toNewAPIModel(r.ImpactAnalysis)
	workersCount.Notification = toNewAPIModel(r.Notification)
}

var newExistingResourceModelAttributeTypes map[string]attr.Type = lo.Assign(
	newResourceModelAttributeTypes,
	map[string]attr.Type{
		"existing_content": types.Int64Type,
	},
)

var newResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"new_content": types.Int64Type,
}

func newExistingModelToResourceSet(apiModel WorkersCountNewExistingContentAPIModel) (types.Set, diag.Diagnostics) {
	return types.SetValue(
		types.ObjectType{
			AttrTypes: newExistingResourceModelAttributeTypes,
		},
		[]attr.Value{
			basetypes.NewObjectValueMust(
				newExistingResourceModelAttributeTypes,
				map[string]attr.Value{
					"new_content":      types.Int64Value(apiModel.New),
					"existing_content": types.Int64Value(apiModel.Existing),
				},
			),
		},
	)
}

func newModelToResourceSet(apiModel WorkersCountNewContentAPIModel) (types.Set, diag.Diagnostics) {
	return types.SetValue(
		types.ObjectType{
			AttrTypes: newResourceModelAttributeTypes,
		},
		[]attr.Value{
			basetypes.NewObjectValueMust(
				newResourceModelAttributeTypes,
				map[string]attr.Value{
					"new_content": types.Int64Value(apiModel.New),
				},
			),
		},
	)
}

func (m WorkersCountAPIModel) toState(r *WorkersCountResourceModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	set, ds := newExistingModelToResourceSet(m.Index)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Index = set
	}

	set, ds = newExistingModelToResourceSet(m.Alert)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Alert = set
	}

	set, ds = newExistingModelToResourceSet(m.Analysis)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Analysis = set
	}

	set, ds = newExistingModelToResourceSet(m.Persist)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Persist = set
	}

	set, ds = newModelToResourceSet(m.ImpactAnalysis)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.ImpactAnalysis = set
	}

	set, ds = newModelToResourceSet(m.Notification)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Notification = set
	}

	return diags
}

type WorkersCountNewContentAPIModel struct {
	New int64 `json:"new_content"`
}

type WorkersCountNewExistingContentAPIModel struct {
	WorkersCountNewContentAPIModel
	Existing int64 `json:"existing_content"`
}

var newContentAttrs = map[string]schema.Attribute{
	"new_content": schema.Int64Attribute{
		Required:    true,
		Description: "Number of workers for new content",
	},
}

var newExistingContentAttrs = lo.Assign(
	newContentAttrs,
	map[string]schema.Attribute{
		"existing_content": schema.Int64Attribute{
			Required:    true,
			Description: "Number of workers for existing content",
		},
	},
)

func (r *WorkersCountResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"index": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing indexing of artifacts.",
			},
			"persist": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing persistent storage needed to build the artifact relationship graph.",
			},
			"alert": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing alerts.",
			},
			"analysis": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers involved in scanning analysis.",
			},
			"impact_analysis": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers involved in Impact Analysis to determine how a component with a reported issue impacts others in the system.",
			},
			"notification": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing notifications.",
			},
		},
		Description: "Configure the number of workers which enables you to control the number of workers for new content and existing content.\n\n->Only works for self-hosted version!\n\n~>You must restart Xray to apply the changes.",
	}
}

func (r *WorkersCountResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *WorkersCountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var workersCount WorkersCountAPIModel
	plan.toAPIModel(&workersCount)

	response, err := r.ProviderData.Client.R().
		SetBody(workersCount).
		Put(WorkersCountEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	if plan.ID.IsUnknown() {
		v, err := json.Marshal(workersCount)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to marshal request payload",
				err.Error(),
			)
			return
		}
		hash := sha256.Sum256(v)
		plan.ID = types.StringValue(fmt.Sprintf("%x", hash))
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	resp.Diagnostics.AddWarning(
		"Restart required",
		"You must restart Xray to apply the changes.",
	)
}

func (r *WorkersCountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var state WorkersCountResourceModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var workersCount WorkersCountAPIModel

	response, err := r.ProviderData.Client.R().
		SetResult(&workersCount).
		Get(WorkersCountEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	// Convert from the API data model to the Terraform data model
	// and refresh any attribute values.
	resp.Diagnostics.Append(workersCount.toState(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *WorkersCountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var workersCount WorkersCountAPIModel
	plan.toAPIModel(&workersCount)

	response, err := r.ProviderData.Client.R().
		SetBody(workersCount).
		Put(WorkersCountEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	resp.Diagnostics.AddWarning(
		"Restart required",
		"You must restart Xray to apply the changes.",
	)
}

// Delete No delete functionality provided by API for the settings or DB sync call.
// This function will remove the object from the Terraform state
func (r *WorkersCountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	resp.Diagnostics.AddWarning(
		"Workers Count resource does not support delete",
		"Workers Count can only be updated. Terraform state will be deleted but the settings remains on Xray instance.",
	)
}

// ImportState imports the resource into the Terraform state.
func (r *WorkersCountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
