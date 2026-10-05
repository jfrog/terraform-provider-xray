package xray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	SBOMEnricher       types.Set    `tfsdk:"sbom_enricher"`
	SBOMDependencies   types.Set    `tfsdk:"sbom_dependencies"`
	SBOMDeleter        types.Set    `tfsdk:"sbom_deleter"`
	PostScan           types.Set    `tfsdk:"post_scan"`
	SBOMCleanup        types.Set    `tfsdk:"sbom_cleanup"`
	SBOMCdxAPI         types.Set    `tfsdk:"sbom_cdx_api"`
	SBOMMalicious      types.Set    `tfsdk:"sbom_malicious"`
}

type workersCountBlock struct {
	apiKey  string
	newOnly bool
	field   func(*WorkersCountResourceModelV1) *types.Set
}

// Maps each schema block to its key in the Xray workersCount JSON body.
var workersCountBlocks = []workersCountBlock{
	{"index", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.Index }},
	{"persist", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.Persist }},
	{"analysis", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.Analysis }},
	{"policy_enforcer", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.PolicyEnforcer }},
	{"sbom", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOM }},
	{"usercatalog", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.UserCatalog }},
	{"sbomimpactanalysis", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMImpactAnalysis }},
	{"migrationsbom", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.MigrationSBOM }},
	{"impact_analysis", true, func(m *WorkersCountResourceModelV1) *types.Set { return &m.ImpactAnalysis }},
	{"notification", true, func(m *WorkersCountResourceModelV1) *types.Set { return &m.Notification }},
	{"panoramic", true, func(m *WorkersCountResourceModelV1) *types.Set { return &m.Panoramic }},
	{"sbomenricher", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMEnricher }},
	{"sbomdependencies", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMDependencies }},
	{"sbomdeleter", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMDeleter }},
	{"postscan", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.PostScan }},
	{"sbomcleanup", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMCleanup }},
	{"sbomcdxapi", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMCdxAPI }},
	{"sbommalicious", false, func(m *WorkersCountResourceModelV1) *types.Set { return &m.SBOMMalicious }},
}

func isBlockConfigured(s types.Set) bool {
	return !s.IsNull() && !s.IsUnknown() && len(s.Elements()) > 0
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

// toAPIModel overwrites the configured blocks in body, leaving all other worker types as they are.
func (r *WorkersCountResourceModelV1) toAPIModel(body map[string]json.RawMessage) error {
	for _, b := range workersCountBlocks {
		set := *b.field(r)
		if !isBlockConfigured(set) {
			continue
		}

		var v any = toNewExistingAPIModel(set)
		if b.newOnly {
			v = toNewAPIModel(set)
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body[b.apiKey] = raw
	}
	return nil
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

// importPrivateKey marks state written by ImportState, so the next Read populates every block.
const importPrivateKey = "importing"

// toState refreshes the blocks already in state. On import it populates every known block.
func (r *WorkersCountResourceModelV1) toState(body map[string]json.RawMessage, importing bool) diag.Diagnostics {
	diags := diag.Diagnostics{}

	for _, b := range workersCountBlocks {
		field := b.field(r)
		raw, ok := body[b.apiKey]
		if !ok || (!importing && !isBlockConfigured(*field)) {
			continue
		}

		var apiModel WorkersCountNewExistingContentAPIModel
		if err := json.Unmarshal(raw, &apiModel); err != nil {
			diags.AddError("Failed to parse workers count", fmt.Sprintf("%s: %s", b.apiKey, err))
			continue
		}

		var set types.Set
		var ds diag.Diagnostics
		if b.newOnly {
			set, ds = newModelToResourceSet(apiModel.WorkersCountNewContentAPIModel)
		} else {
			set, ds = newExistingModelToResourceSet(apiModel)
		}
		diags.Append(ds...)
		if !ds.HasError() {
			*field = set
		}
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
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing policy enforcer.",
			},
			"sbom": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM.",
			},
			"user_catalog": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing user catalog.",
			},
			"sbom_impact_analysis": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM impact analysis.",
			},
			"migration_sbom": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM migration.",
			},
			"panoramic": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing panoramic.",
			},
			"sbom_enricher": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM enrichment.",
			},
			"sbom_dependencies": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM dependencies.",
			},
			"sbom_deleter": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM deletion.",
			},
			"post_scan": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing post scan.",
			},
			"sbom_cleanup": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM cleanup.",
			},
			"sbom_cdx_api": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM CycloneDX API.",
			},
			"sbom_malicious": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: newExistingContentAttrs,
				},
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 1),
				},
				Description: "The number of workers managing SBOM malicious package detection.",
			},
		},
	),
	Description: workersCountSchemaV0.Description + "\n\nWorker types without a block are left unchanged on Xray.",
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

				newExistingNull := types.SetNull(types.ObjectType{AttrTypes: newExistingResourceModelAttributeTypes})
				newNull := types.SetNull(types.ObjectType{AttrTypes: newResourceModelAttributeTypes})

				upgradedStateData := WorkersCountResourceModelV1{
					ID:                 priorStateData.ID,
					Index:              priorStateData.Index,
					Persist:            priorStateData.Persist,
					Analysis:           priorStateData.Analysis,
					PolicyEnforcer:     priorStateData.Alert,
					SBOM:               newExistingNull,
					UserCatalog:        newExistingNull,
					SBOMImpactAnalysis: newExistingNull,
					MigrationSBOM:      newExistingNull,
					ImpactAnalysis:     priorStateData.ImpactAnalysis,
					Notification:       priorStateData.Notification,
					Panoramic:          newNull,
					SBOMEnricher:       newExistingNull,
					SBOMDependencies:   newExistingNull,
					SBOMDeleter:        newExistingNull,
					PostScan:           newExistingNull,
					SBOMCleanup:        newExistingNull,
					SBOMCdxAPI:         newExistingNull,
					SBOMMalicious:      newExistingNull,
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

// putWorkersCount merges the plan into the current config before the PUT, because Xray resets
// any worker type missing from the PUT body to 0.
func (r *WorkersCountResource) putWorkersCount(plan *WorkersCountResourceModelV1) (map[string]json.RawMessage, error) {
	var workersCount map[string]json.RawMessage

	response, err := r.ProviderData.Client.R().
		SetResult(&workersCount).
		Get(WorkersCountEndpoint)
	if err != nil {
		return nil, err
	}
	if response.IsError() {
		return nil, errors.New(response.String())
	}
	if workersCount == nil {
		return nil, fmt.Errorf("unable to parse current workers count: %s", response.String())
	}

	if err := plan.toAPIModel(workersCount); err != nil {
		return nil, err
	}

	response, err = r.ProviderData.Client.R().
		SetBody(workersCount).
		Put(WorkersCountEndpoint)
	if err != nil {
		return nil, err
	}
	if response.IsError() {
		return nil, errors.New(response.String())
	}

	return workersCount, nil
}

func (r *WorkersCountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModelV1

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	workersCount, err := r.putWorkersCount(&plan)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
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

	var workersCount map[string]json.RawMessage

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
	// Keeps the import flag for a retry instead of importing nothing.
	if workersCount == nil {
		utilfw.UnableToRefreshResourceError(resp, fmt.Sprintf("unable to parse current workers count: %s", response.String()))
		return
	}

	importing, d := req.Private.GetKey(ctx, importPrivateKey)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert from the API data model to the Terraform data model
	// and refresh any attribute values.
	resp.Diagnostics.Append(state.toState(workersCount, importing != nil)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	if importing != nil {
		resp.Diagnostics.Append(resp.Private.SetKey(ctx, importPrivateKey, nil)...)
	}
}

func (r *WorkersCountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WorkersCountResourceModelV1

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.putWorkersCount(&plan); err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
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
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, importPrivateKey, []byte("true"))...)
}
