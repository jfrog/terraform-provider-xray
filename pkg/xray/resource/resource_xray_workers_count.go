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
	return &WorkersCountResource{
		TypeName: "xray_workers_count",
	}
}

type WorkersCountResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *WorkersCountResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type WorkersCountResourceModelV0 struct {
	ID             types.String `tfsdk:"id"`
	Index          types.Set    `tfsdk:"index"`
	Persist        types.Set    `tfsdk:"persist"`
	Alert          types.Set    `tfsdk:"alert"`
	Analysis       types.Set    `tfsdk:"analysis"`
	ImpactAnalysis types.Set    `tfsdk:"impact_analysis"`
	Notification   types.Set    `tfsdk:"notification"`
}

type WorkersCountResourceModelV1 struct {
	ID                 types.String `tfsdk:"id"`
	Index              types.Set    `tfsdk:"index"`
	Persist            types.Set    `tfsdk:"persist"`
	Analysis           types.Set    `tfsdk:"analysis"`
	PolicyEnforcer     types.Set    `tfsdk:"policy_enforcer"`
	SBOM               types.Set    `tfsdk:"sbom"`
	UserCatalog        types.Set    `tfsdk:"user_catalog"`
	SBOMImpactAnalysis types.Set    `tfsdk:"sbom_impact_analysis"`
	MigrationSBOM      types.Set    `tfsdk:"migration_sbom"`
	ImpactAnalysis     types.Set    `tfsdk:"impact_analysis"`
	Notification       types.Set    `tfsdk:"notification"`
	Panoramic          types.Set    `tfsdk:"panoramic"`
}

// WorkersCount uses Xray API which returns the follow JSON structure:
//
//	{
//	  "index": {
//	    "new_content": 8,
//	    "existing_content": 4
//	  },
//	  "persist": {
//	    "new_content": 8,
//	    "existing_content": 4
//	  },
//	  "analysis": {
//	    "new_content": 8,
//	    "existing_content": 4
//	  },
//	  "policy_enforcer": {
//	    "new_content": 8,
//	    "existing_content": 8
//	  },
//	  "sbom": {
//	    "new_content": 0,
//	    "existing_content": 0
//	  },
//	  "usercatalog": {
//	    "new_content": 0,
//	    "existing_content": 0
//	  },
//	  "sbomimpactanalysis": {
//	    "new_content": 0,
//	    "existing_content": 0
//	  },
//	  "migrationsbom": {
//	    "new_content": 0,
//	    "existing_content": 0
//	  },
//	  "impact_analysis": {
//	    "new_content": 8
//	  },
//	  "notification": {
//	    "new_content": 8
//	  },
//	  "panoramic": {
//	    "new_content": 0
//	  }
//	}
type WorkersCountAPIModel struct {
	Index              WorkersCountNewExistingContentAPIModel `json:"index"`
	Persist            WorkersCountNewExistingContentAPIModel `json:"persist"`
	Analysis           WorkersCountNewExistingContentAPIModel `json:"analysis"`
	PolicyEnforcer     WorkersCountNewExistingContentAPIModel `json:"policy_enforcer"`
	SBOM               WorkersCountNewExistingContentAPIModel `json:"sbom"`
	UserCatalog        WorkersCountNewExistingContentAPIModel `json:"usercatalog"`
	SBOMImpactAnalysis WorkersCountNewExistingContentAPIModel `json:"sbomimpactanalysis"`
	MigrationSBOM      WorkersCountNewExistingContentAPIModel `json:"migrationsbom"`
	ImpactAnalysis     WorkersCountNewContentAPIModel         `json:"impact_analysis"`
	Notification       WorkersCountNewContentAPIModel         `json:"notification"`
	Panoramic          WorkersCountNewContentAPIModel         `json:"panoramic"`
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

func (r WorkersCountResourceModelV1) toAPIModel(workersCount *WorkersCountAPIModel) {
	workersCount.Index = toNewExistingAPIModel(r.Index)
	workersCount.Persist = toNewExistingAPIModel(r.Persist)
	workersCount.Analysis = toNewExistingAPIModel(r.Analysis)
	workersCount.PolicyEnforcer = toNewExistingAPIModel(r.PolicyEnforcer)
	workersCount.SBOM = toNewExistingAPIModel(r.SBOM)
	workersCount.UserCatalog = toNewExistingAPIModel(r.UserCatalog)
	workersCount.SBOMImpactAnalysis = toNewExistingAPIModel(r.SBOMImpactAnalysis)
	workersCount.MigrationSBOM = toNewExistingAPIModel(r.MigrationSBOM)
	workersCount.ImpactAnalysis = toNewAPIModel(r.ImpactAnalysis)
	workersCount.Notification = toNewAPIModel(r.Notification)
	workersCount.Panoramic = toNewAPIModel(r.Panoramic)
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

func (m WorkersCountAPIModel) toState(r *WorkersCountResourceModelV1) diag.Diagnostics {
	diags := diag.Diagnostics{}

	set, ds := newExistingModelToResourceSet(m.Index)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Index = set
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

	set, ds = newExistingModelToResourceSet(m.PolicyEnforcer)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.PolicyEnforcer = set
	}

	set, ds = newExistingModelToResourceSet(m.SBOM)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.SBOM = set
	}

	set, ds = newExistingModelToResourceSet(m.UserCatalog)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.UserCatalog = set
	}

	set, ds = newExistingModelToResourceSet(m.SBOMImpactAnalysis)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.SBOMImpactAnalysis = set
	}

	set, ds = newExistingModelToResourceSet(m.MigrationSBOM)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.MigrationSBOM = set
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

	set, ds = newModelToResourceSet(m.Panoramic)
	if ds != nil {
		diags = append(diags, ds...)
	} else {
		r.Panoramic = set
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

var workersCountSchemaV0 = schema.Schema{
	Version: 0,
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

var workersCountSchemaV1 = schema.Schema{
	Version:    1,
	Attributes: workersCountSchemaV0.Attributes,
	Blocks: lo.Assign(
		lo.OmitByKeys(workersCountSchemaV0.Blocks, []string{"alert"}),
		map[string]schema.Block{
			"policy_enforcer": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing policy enforcer.",
			},
			"sbom": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM.",
			},
			"user_catalog": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing user catalog.",
			},
			"sbom_impact_analysis": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM impact analysis.",
			},
			"migration_sbom": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM migration.",
			},
			"panoramic": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.IsRequired(),
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing panoramic.",
			},
		},
	),
	Description: workersCountSchemaV0.Description,
}

func (r *WorkersCountResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = workersCountSchemaV1
}

func (r *WorkersCountResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		// State upgrade implementation from 0 (prior state version) to 1 (Schema.Version)
		0: {
			PriorSchema: &workersCountSchemaV0,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var priorStateData WorkersCountResourceModelV0

				resp.Diagnostics.Append(req.State.Get(ctx, &priorStateData)...)
				if resp.Diagnostics.HasError() {
					return
				}

				defaultExistingContent, d := newExistingModelToResourceSet(WorkersCountNewExistingContentAPIModel{
					WorkersCountNewContentAPIModel: WorkersCountNewContentAPIModel{
						New: 0,
					},
					Existing: 0,
				})
				resp.Diagnostics.Append(d...)
				if resp.Diagnostics.HasError() {
					return
				}

				defaultNewContent, d := newModelToResourceSet(
					WorkersCountNewContentAPIModel{
						New: 0,
					},
				)
				resp.Diagnostics.Append(d...)
				if resp.Diagnostics.HasError() {
					return
				}

				upgradedStateData := WorkersCountResourceModelV1{
					ID:                 priorStateData.ID,
					Index:              priorStateData.Index,
					Persist:            priorStateData.Persist,
					Analysis:           priorStateData.Analysis,
					PolicyEnforcer:     priorStateData.Alert,
					SBOM:               defaultExistingContent,
					UserCatalog:        defaultExistingContent,
					SBOMImpactAnalysis: defaultExistingContent,
					MigrationSBOM:      defaultExistingContent,
					ImpactAnalysis:     priorStateData.ImpactAnalysis,
					Notification:       priorStateData.Notification,
					Panoramic:          defaultNewContent,
				}

				resp.Diagnostics.Append(resp.State.Set(ctx, upgradedStateData)...)
			},
		},
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
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModelV1

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
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WorkersCountResourceModelV1
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
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModelV1

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
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	resp.Diagnostics.AddWarning(
		"Workers Count resource does not support delete",
		"Workers Count can only be updated. Terraform state will be deleted but the settings remains on Xray instance.",
	)
}

// ImportState imports the resource into the Terraform state.
func (r *WorkersCountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
