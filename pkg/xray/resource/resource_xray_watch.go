package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

const (
	WatchesEndpoint = "xray/api/v2/watches"
	WatchEndpoint   = "xray/api/v2/watches/{name}"
)

var supportedResourceTypes = []string{
	"repository",
	"all-repos",
	"build",
	"all-builds",
	"project",
	"all-projects",
	"releaseBundle",
	"all-releaseBundles",
	"releaseBundleV2",
	"all-releaseBundlesV2",
	"gitRepository",
}

var _ resource.Resource = &WatchResource{}

func NewWatchResource() resource.Resource {
	return &WatchResource{
		TypeName: "xray_watch",
	}
}

type WatchResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *WatchResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type WatchResourceModel struct {
	Name                types.String `tfsdk:"name"`
	ProjectKey          types.String `tfsdk:"project_key"`
	Description         types.String `tfsdk:"description"`
	Active              types.Bool   `tfsdk:"active"`
	WatchResource       types.Set    `tfsdk:"watch_resource"`
	AssignedPolicies    types.Set    `tfsdk:"assigned_policy"`
	WatchRecipients     types.Set    `tfsdk:"watch_recipients"`
	CreateTicketEnabled types.Bool   `tfsdk:"create_ticket_enabled"`
	TicketProfile       types.String `tfsdk:"ticket_profile"`
	TicketGeneration    types.Object `tfsdk:"ticket_generation"`
}

func unpackAntFilter(ctx context.Context, filterType string, ds *diag.Diagnostics) func(elem attr.Value, _ int) WatchFilterAPIModel {
	return func(elem attr.Value, _ int) WatchFilterAPIModel {
		attrs := elem.(types.Object).Attributes()

		var includePatterns []string
		ds.Append(attrs["include_patterns"].(types.List).ElementsAs(ctx, &includePatterns, false)...)

		var excludePatterns []string
		ds.Append(attrs["exclude_patterns"].(types.List).ElementsAs(ctx, &excludePatterns, false)...)

		filterValue, err := json.Marshal(
			WatchFilterAntValueAPIModel{
				IncludePatterns: includePatterns,
				ExcludePatterns: excludePatterns,
			},
		)
		if err != nil {
			ds.AddError(
				"failed to marshal ant filter",
				err.Error(),
			)
		}

		return WatchFilterAPIModel{
			Type:  filterType,
			Value: json.RawMessage(filterValue),
		}
	}
}

func unpackKVFilter(_ context.Context, _ *diag.Diagnostics) func(elem attr.Value, _ int) WatchFilterAPIModel {
	return func(elem attr.Value, _ int) WatchFilterAPIModel {
		attrs := elem.(types.Object).Attributes()

		filterValue := fmt.Sprintf(
			`{"key": "%s", "value": "%s"}`,
			attrs["key"].(types.String).ValueString(),
			attrs["value"].(types.String).ValueString(),
		)

		return WatchFilterAPIModel{
			Type:  attrs["type"].(types.String).ValueString(),
			Value: json.RawMessage(filterValue),
		}
	}
}

func (m WatchResourceModel) toAPIModel(ctx context.Context, apiModel *WatchAPIModel) (ds diag.Diagnostics) {
	projectResources := lo.Map(
		m.WatchResource.Elements(),
		func(elem attr.Value, _ int) WatchProjectResourceAPIModel {
			attrs := elem.(types.Object).Attributes()

			var filters []WatchFilterAPIModel

			fs := lo.Map(
				attrs["filter"].(types.Set).Elements(),
				func(elem attr.Value, _ int) WatchFilterAPIModel {
					attrs := elem.(types.Object).Attributes()
					return WatchFilterAPIModel{
						Type:  attrs["type"].(types.String).ValueString(),
						Value: json.RawMessage(strconv.Quote(attrs["value"].(types.String).ValueString())),
					}
				},
			)
			filters = append(filters, fs...)

			antFilters := lo.Map(
				attrs["ant_filter"].(types.Set).Elements(),
				unpackAntFilter(ctx, "ant-patterns", &ds),
			)
			filters = append(filters, antFilters...)

			pathAntFilters := lo.Map(
				attrs["path_ant_filter"].(types.Set).Elements(),
				unpackAntFilter(ctx, "path-ant-patterns", &ds),
			)
			filters = append(filters, pathAntFilters...)

			kvFilters := lo.Map(
				attrs["kv_filter"].(types.Set).Elements(),
				unpackKVFilter(ctx, &ds),
			)
			filters = append(filters, kvFilters...)

			return WatchProjectResourceAPIModel{
				Type:            attrs["type"].(types.String).ValueString(),
				BinaryManagerId: attrs["bin_mgr_id"].(types.String).ValueString(),
				Name:            attrs["name"].(types.String).ValueString(),
				RepoType:        attrs["repo_type"].(types.String).ValueString(),
				Filters:         filters,
			}
		},
	)

	assignedPolicies := lo.Map(
		m.AssignedPolicies.Elements(),
		func(elem attr.Value, _ int) WatchAssignedPolicyAPIModel {
			attrs := elem.(types.Object).Attributes()
			return WatchAssignedPolicyAPIModel{
				Name: attrs["name"].(types.String).ValueString(),
				Type: attrs["type"].(types.String).ValueString(),
			}
		},
	)

	var recipients []string
	ds.Append(m.WatchRecipients.ElementsAs(ctx, &recipients, false)...)

	*apiModel = WatchAPIModel{
		GeneralData: WatchGeneralDataAPIModel{
			Name:        m.Name.ValueString(),
			Description: m.Description.ValueString(),
			Active:      m.Active.ValueBool(),
		},
		ProjectResources: WatchProjectResourcesAPIModel{
			Resources: projectResources,
		},
		AssignedPolicies: assignedPolicies,
		WatchRecipients:  recipients,
	}

	if !m.CreateTicketEnabled.IsNull() && !m.CreateTicketEnabled.IsUnknown() {
		apiModel.CreateTicketEnabled = m.CreateTicketEnabled.ValueBoolPointer()
	}

	if !m.TicketProfile.IsNull() && !m.TicketProfile.IsUnknown() {
		apiModel.TicketProfile = m.TicketProfile.ValueString()
	}

	if !m.TicketGeneration.IsNull() && !m.TicketGeneration.IsUnknown() {
		tgAttrs := m.TicketGeneration.Attributes()
		tg := &TicketGenerationAPIModel{}

		if v, ok := tgAttrs["create_tickets_for_ignored_violation"]; ok && !v.IsNull() && !v.IsUnknown() {
			val := v.(types.Bool).ValueBoolPointer()
			tg.CreateTicketsForIgnoredViolation = val
		}

		if cdtObj, ok := tgAttrs["create_duplicate_tickets"]; ok && !cdtObj.IsNull() && !cdtObj.IsUnknown() {
			cdtAttrs := cdtObj.(types.Object).Attributes()
			if bvObj, ok := cdtAttrs["by_version"]; ok && !bvObj.IsNull() && !bvObj.IsUnknown() {
				bvAttrs := bvObj.(types.Object).Attributes()
				tg.CreateDuplicateTickets = &DuplicateTicketCreationAPIModel{
					ByVersion: VersionTicketSettingsAPIModel{
						Build:         bvAttrs["build"].(types.Bool).ValueBool(),
						Package:       bvAttrs["package"].(types.Bool).ValueBool(),
						ReleaseBundle: bvAttrs["release_bundle"].(types.Bool).ValueBool(),
					},
				}
			}
		}

		if ipmObj, ok := tgAttrs["impact_path_profiles_mapping"]; ok && !ipmObj.IsNull() && !ipmObj.IsUnknown() {
			ipmAttrs := ipmObj.(types.Object).Attributes()
			if includeSet, ok := ipmAttrs["include"]; ok && !includeSet.IsNull() && !includeSet.IsUnknown() {
				entries := lo.Map(
					includeSet.(types.Set).Elements(),
					func(elem attr.Value, _ int) ImpactPathProfileMappingAPIModel {
						attrs := elem.(types.Object).Attributes()
						return ImpactPathProfileMappingAPIModel{
							Profile: attrs["profile"].(types.String).ValueString(),
							Pattern: attrs["pattern"].(types.String).ValueString(),
						}
					},
				)
				tg.ImpactPathProfilesMapping = &ImpactPathProfilesMappingAPIModel{
					Include: entries,
				}
			}
		}

		apiModel.TicketGeneration = tg
	}

	return
}

var filterResourceModelAttributeTypes = map[string]attr.Type{
	"type":  types.StringType,
	"value": types.StringType,
}

var filterObjectResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: filterResourceModelAttributeTypes,
}

var antFilterResourceModelAttributeTypes = map[string]attr.Type{
	"include_patterns": types.ListType{ElemType: types.StringType},
	"exclude_patterns": types.ListType{ElemType: types.StringType},
}

var antFilterObjectResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: antFilterResourceModelAttributeTypes,
}

var kvFilterResourceModelAttributeTypes = map[string]attr.Type{
	"type":  types.StringType,
	"key":   types.StringType,
	"value": types.StringType,
}

var kvFilterObjectResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: kvFilterResourceModelAttributeTypes,
}

var watchResourceResourceModelAttributeTypes = map[string]attr.Type{
	"type":       types.StringType,
	"name":       types.StringType,
	"bin_mgr_id": types.StringType,
	"repo_type":  types.StringType,
	"filter": types.SetType{
		ElemType: filterObjectResourceModelAttributeTypes,
	},
	"ant_filter": types.SetType{
		ElemType: antFilterObjectResourceModelAttributeTypes,
	},
	"path_ant_filter": types.SetType{
		ElemType: antFilterObjectResourceModelAttributeTypes,
	},
	"kv_filter": types.SetType{
		ElemType: kvFilterObjectResourceModelAttributeTypes,
	},
}

var watchResourceObjectResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: watchResourceResourceModelAttributeTypes,
}

var assignedPolicyResourceModelAttributeTypes = map[string]attr.Type{
	"name": types.StringType,
	"type": types.StringType,
}

var assignedPolicyObjectResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: assignedPolicyResourceModelAttributeTypes,
}

var impactPathMappingEntryAttributeTypes = map[string]attr.Type{
	"profile": types.StringType,
	"pattern": types.StringType,
}

var impactPathMappingEntryObjectType = types.ObjectType{
	AttrTypes: impactPathMappingEntryAttributeTypes,
}

var impactPathProfilesMappingAttributeTypes = map[string]attr.Type{
	"include": types.SetType{ElemType: impactPathMappingEntryObjectType},
}

var byVersionAttributeTypes = map[string]attr.Type{
	"build":          types.BoolType,
	"package":        types.BoolType,
	"release_bundle": types.BoolType,
}

var createDuplicateTicketsAttributeTypes = map[string]attr.Type{
	"by_version": types.ObjectType{AttrTypes: byVersionAttributeTypes},
}

var ticketGenerationAttributeTypes = map[string]attr.Type{
	"create_duplicate_tickets":             types.ObjectType{AttrTypes: createDuplicateTicketsAttributeTypes},
	"impact_path_profiles_mapping":         types.ObjectType{AttrTypes: impactPathProfilesMappingAttributeTypes},
	"create_tickets_for_ignored_violation": types.BoolType,
}

func packStringFilter(ctx context.Context, filter WatchFilterAPIModel) (attr.Value, diag.Diagnostics) {
	var value string
	err := json.Unmarshal(filter.Value, &value)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to pack KV filter", err.Error()),
		}
	}

	return types.ObjectValue(
		filterResourceModelAttributeTypes,
		map[string]attr.Value{
			"type":  types.StringValue(filter.Type),
			"value": types.StringValue(value),
		},
	)
}

func packAntFilter(ctx context.Context, filter WatchFilterAPIModel) (attr.Value, diag.Diagnostics) {
	var value WatchFilterAntValueAPIModel
	err := json.Unmarshal(filter.Value, &value)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to pack Ant filter", err.Error()),
		}
	}

	diags := diag.Diagnostics{}
	excludedPatterns := types.ListNull(types.StringType)
	if len(value.ExcludePatterns) > 0 {
		ps, d := types.ListValueFrom(ctx, types.StringType, value.ExcludePatterns)
		if d != nil {
			diags.Append(d...)
		}
		excludedPatterns = ps
	}

	includedPatterns := types.ListNull(types.StringType)
	if len(value.IncludePatterns) > 0 {
		ps, d := types.ListValueFrom(ctx, types.StringType, value.IncludePatterns)
		if d != nil {
			diags.Append(d...)
		}
		includedPatterns = ps
	}

	antFilter, d := types.ObjectValue(
		antFilterResourceModelAttributeTypes,
		map[string]attr.Value{
			"exclude_patterns": excludedPatterns,
			"include_patterns": includedPatterns,
		},
	)
	if d != nil {
		diags.Append(d...)
	}

	return antFilter, diags
}

func packKvFilter(ctx context.Context, filter WatchFilterAPIModel) (attr.Value, diag.Diagnostics) {
	var kvValue WatchFilterKvValueAPIModel
	err := json.Unmarshal(filter.Value, &kvValue)
	if err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("failed to pack KV filter", err.Error()),
		}
	}

	return types.ObjectValue(
		kvFilterResourceModelAttributeTypes,
		map[string]attr.Value{
			"type":  types.StringValue(filter.Type),
			"key":   types.StringValue(kvValue.Key),
			"value": types.StringValue(kvValue.Value),
		},
	)
}

var packFilterMap = map[string]map[string]interface{}{
	"regex": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"path-regex": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"package-type": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"mime-type": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"ant-patterns": {
		"func":          packAntFilter,
		"attributeName": "ant_filter",
	},
	"path-ant-patterns": {
		"func":          packAntFilter,
		"attributeName": "path_ant_filter",
	},
	"property": {
		"func":          packKvFilter,
		"attributeName": "kv_filter",
	},
}

var allTypes = []string{"all-repos", "all-builds", "all-projects", "all-releaseBundles", "all-releaseBundlesV2"}

func (m *WatchResourceModel) fromAPIModel(ctx context.Context, apiModel WatchAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	m.Name = types.StringValue(apiModel.GeneralData.Name)
	m.Description = types.StringNull()
	if len(apiModel.GeneralData.Description) > 0 {
		m.Description = types.StringValue(apiModel.GeneralData.Description)
	}
	m.Active = types.BoolValue(apiModel.GeneralData.Active)

	watchResources := lo.Map(
		apiModel.ProjectResources.Resources,
		func(property WatchProjectResourceAPIModel, _ int) attr.Value {
			resources := make(map[string][]attr.Value)

			for _, filter := range property.Filters {
				packFilterAttribute, ok := packFilterMap[filter.Type]
				if !ok {
					diags.AddError(
						"invalid filter.Type",
						filter.Type,
					)
				}

				packedFilter, d := packFilterAttribute["func"].(func(ctx context.Context, filter WatchFilterAPIModel) (attr.Value, diag.Diagnostics))(ctx, filter)
				if d != nil && d.HasError() {
					diags.Append(d...)
				} else {
					attributeName := packFilterAttribute["attributeName"].(string)
					resources[attributeName] = append(resources[attributeName], packedFilter)
				}
			}

			name := types.StringNull()
			if len(property.Name) > 0 && !slices.Contains(allTypes, property.Type) {
				name = types.StringValue(property.Name)
			}

			repoType := types.StringNull()
			if len(property.RepoType) > 0 {
				repoType = types.StringValue(property.RepoType)
			}

			watchResource, ds := types.ObjectValue(
				watchResourceResourceModelAttributeTypes,
				map[string]attr.Value{
					"type":            types.StringValue(property.Type),
					"name":            name,
					"bin_mgr_id":      types.StringValue(property.BinaryManagerId),
					"repo_type":       repoType,
					"filter":          types.SetValueMust(filterObjectResourceModelAttributeTypes, resources["filter"]),
					"ant_filter":      types.SetValueMust(antFilterObjectResourceModelAttributeTypes, resources["ant_filter"]),
					"path_ant_filter": types.SetValueMust(antFilterObjectResourceModelAttributeTypes, resources["path_ant_filter"]),
					"kv_filter":       types.SetValueMust(kvFilterObjectResourceModelAttributeTypes, resources["kv_filter"]),
				},
			)

			if ds != nil {
				diags.Append(ds...)
			}

			return watchResource
		},
	)
	watchResourceSet, d := types.SetValue(
		watchResourceObjectResourceModelAttributeTypes,
		watchResources,
	)
	if d != nil {
		diags.Append(d...)
	}
	m.WatchResource = watchResourceSet

	assignedPolicies := lo.Map(
		apiModel.AssignedPolicies,
		func(property WatchAssignedPolicyAPIModel, _ int) attr.Value {
			assignedPolicy, ds := types.ObjectValue(
				assignedPolicyResourceModelAttributeTypes,
				map[string]attr.Value{
					"name": types.StringValue(property.Name),
					"type": types.StringValue(property.Type),
				},
			)

			if ds != nil {
				diags.Append(ds...)
			}

			return assignedPolicy
		},
	)
	assignedPoliciesSet, d := types.SetValue(
		assignedPolicyObjectResourceModelAttributeTypes,
		assignedPolicies,
	)
	if d != nil {
		diags.Append(d...)
	}
	m.AssignedPolicies = assignedPoliciesSet

	watchRecipients, d := types.SetValueFrom(ctx, types.StringType, apiModel.WatchRecipients)
	if d != nil {
		diags.Append(d...)
	}
	m.WatchRecipients = watchRecipients

	if apiModel.CreateTicketEnabled != nil {
		m.CreateTicketEnabled = types.BoolValue(*apiModel.CreateTicketEnabled)
	} else {
		m.CreateTicketEnabled = types.BoolNull()
	}

	if apiModel.TicketProfile != "" {
		m.TicketProfile = types.StringValue(apiModel.TicketProfile)
	} else {
		m.TicketProfile = types.StringNull()
	}

	hasTicketProfile := apiModel.TicketProfile != ""

	if hasTicketProfile && apiModel.TicketGeneration != nil {
		tg := apiModel.TicketGeneration

		ignoredViolation := types.BoolNull()
		if tg.CreateTicketsForIgnoredViolation != nil {
			ignoredViolation = types.BoolValue(*tg.CreateTicketsForIgnoredViolation)
		}

		cdtVal := types.ObjectNull(createDuplicateTicketsAttributeTypes)
		if tg.CreateDuplicateTickets != nil {
			byVersion, ds := types.ObjectValue(
				byVersionAttributeTypes,
				map[string]attr.Value{
					"build":          types.BoolValue(tg.CreateDuplicateTickets.ByVersion.Build),
					"package":        types.BoolValue(tg.CreateDuplicateTickets.ByVersion.Package),
					"release_bundle": types.BoolValue(tg.CreateDuplicateTickets.ByVersion.ReleaseBundle),
				},
			)
			diags.Append(ds...)

			cdtVal, ds = types.ObjectValue(
				createDuplicateTicketsAttributeTypes,
				map[string]attr.Value{
					"by_version": byVersion,
				},
			)
			diags.Append(ds...)
		}

		ipmVal := types.ObjectNull(impactPathProfilesMappingAttributeTypes)
		if tg.ImpactPathProfilesMapping != nil && len(tg.ImpactPathProfilesMapping.Include) > 0 {
			includeEntries := lo.Map(
				tg.ImpactPathProfilesMapping.Include,
				func(entry ImpactPathProfileMappingAPIModel, _ int) attr.Value {
					obj, ds := types.ObjectValue(
						impactPathMappingEntryAttributeTypes,
						map[string]attr.Value{
							"profile": types.StringValue(entry.Profile),
							"pattern": types.StringValue(entry.Pattern),
						},
					)
					diags.Append(ds...)
					return obj
				},
			)
			includeSet, ds := types.SetValue(impactPathMappingEntryObjectType, includeEntries)
			diags.Append(ds...)

			ipmVal, ds = types.ObjectValue(
				impactPathProfilesMappingAttributeTypes,
				map[string]attr.Value{
					"include": includeSet,
				},
			)
			diags.Append(ds...)
		}

		tgObj, ds := types.ObjectValue(
			ticketGenerationAttributeTypes,
			map[string]attr.Value{
				"create_duplicate_tickets":             cdtVal,
				"impact_path_profiles_mapping":         ipmVal,
				"create_tickets_for_ignored_violation": ignoredViolation,
			},
		)
		diags.Append(ds...)
		m.TicketGeneration = tgObj
	} else {
		m.TicketGeneration = types.ObjectNull(ticketGenerationAttributeTypes)
	}

	return diags
}

type WatchGeneralDataAPIModel struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

type WatchFilterAPIModel struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type WatchFilterAntValueAPIModel struct {
	ExcludePatterns []string `json:"ExcludePatterns,omitempty"`
	IncludePatterns []string `json:"IncludePatterns,omitempty"`
}

type WatchFilterKvValueAPIModel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type WatchProjectResourceAPIModel struct {
	Type            string                `json:"type"`
	BinaryManagerId string                `json:"bin_mgr_id"`
	Filters         []WatchFilterAPIModel `json:"filters,omitempty"`
	Name            string                `json:"name,omitempty"`
	BuildRepo       string                `json:"build_repo,omitempty"`
	RepoType        string                `json:"repo_type,omitempty"`
}

type WatchProjectResourcesAPIModel struct {
	Resources []WatchProjectResourceAPIModel `json:"resources"`
}

type WatchAssignedPolicyAPIModel struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type VersionTicketSettingsAPIModel struct {
	Build         bool `json:"build"`
	Package       bool `json:"package"`
	ReleaseBundle bool `json:"release_bundle"`
}

type DuplicateTicketCreationAPIModel struct {
	ByVersion VersionTicketSettingsAPIModel `json:"by_version"`
}

type ImpactPathProfileMappingAPIModel struct {
	Profile string `json:"profile"`
	Pattern string `json:"pattern"`
}

type ImpactPathProfilesMappingAPIModel struct {
	Include []ImpactPathProfileMappingAPIModel `json:"include"`
}

type TicketGenerationAPIModel struct {
	CreateDuplicateTickets           *DuplicateTicketCreationAPIModel   `json:"create_duplicate_tickets,omitempty"`
	ImpactPathProfilesMapping        *ImpactPathProfilesMappingAPIModel `json:"impact_path_profiles_mapping,omitempty"`
	CreateTicketsForIgnoredViolation *bool                              `json:"create_tickets_for_ignored_violation,omitempty"`
}

type WatchAPIModel struct {
	GeneralData         WatchGeneralDataAPIModel      `json:"general_data"`
	ProjectResources    WatchProjectResourcesAPIModel `json:"project_resources"`
	AssignedPolicies    []WatchAssignedPolicyAPIModel `json:"assigned_policies"`
	WatchRecipients     []string                      `json:"watch_recipients"`
	CreateTicketEnabled *bool                         `json:"create_ticket_enabled,omitempty"`
	TicketProfile       string                        `json:"ticket_profile,omitempty"`
	TicketGeneration    *TicketGenerationAPIModel     `json:"ticket_generation,omitempty"`
}

func (r *WatchResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the watch",
			},
			"project_key": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validatorfw_string.ProjectKey(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters. Support repository and build watch resource types. When specifying individual repository or build they must be already assigned to the project. Build must be added as indexed resources.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the watch",
			},
			"active": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether or not the watch is active",
			},
			"watch_recipients": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						validatorfw_string.IsEmail(),
					),
				},
				Description: "A list of email addressed that will get emailed when a violation is triggered.",
			},
			"create_ticket_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether Jira ticket creation is enabled for this watch. Requires a Jira integration to be configured.",
			},
			"ticket_profile": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "The Jira profile name for ticket generation. Must match an existing Jira ticket profile.",
			},
		},
		Blocks: map[string]schema.Block{
			"watch_resource": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf(supportedResourceTypes...),
							},
							Description: fmt.Sprintf("Type of resource to be watched. Options: %s.", strings.Join(supportedResourceTypes, ", ")),
						},
						"bin_mgr_id": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString("default"),
							Description: "The ID number of a binary manager resource. Default value is `default`. To check the list of available binary managers, use the API call `${JFROG_URL}/xray/api/v1/binMgr` as an admin user, use `binMgrId` value. More info [here](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-GetBinaryManager)",
						},
						"name": schema.StringAttribute{
							Optional:    true,
							Description: "The name of the build, repository, project, or release bundle. Xray indexing must be enabled on the repository, build, or release bundle.",
						},
						"repo_type": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.OneOf("local", "remote"),
							},
							Description: "Type of repository. Only applicable when `type` is `repository`. Options: `local` or `remote`.",
						},
					},
					Blocks: map[string]schema.Block{
						"filter": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.OneOf("regex", "path-regex", "package-type", "mime-type"),
										},
										Description: "The type of filter, such as `regex`, `path-regex`, `package-type`, or `mime-type`",
									},
									"value": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
										Description: "The value of the filter, such as the text of the regex, name of the package type, or mime type.",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Description: "Filter for `regex`, `package-type` and `mime-type` type. Works for `repository` and `all-repos` watch_resource.type",
						},
						"ant_filter": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"include_patterns": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "Use Ant-style wildcard patterns to specify build names (i.e. artifact paths) in the build info repository (without a leading slash) that will be included in this watch. Projects are supported too. Ant-style path expressions are supported (*, **, ?). For example, an 'apache/**' pattern will include the 'apache' build info in the watch.",
									},
									"exclude_patterns": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "Use Ant-style wildcard patterns to specify build names (i.e. artifact paths) in the build info repository (without a leading slash) that will be excluded in this watch. Projects are supported too. Ant-style path expressions are supported (*, **, ?). For example, an 'apache/**' pattern will exclude the 'apache' build info in the watch.",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Description: "`ant-patterns` filter for `all-builds` and `all-projects` watch_resource.type",
						},
						"path_ant_filter": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"include_patterns": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "The pattern will apply to the selected repositories. Simple comma separated wildcard patterns for repository artifact paths (with no leading slash). Ant-style path expressions are supported (*, **, ?). For example: 'org/apache/**'",
									},
									"exclude_patterns": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "The pattern will apply to the selected repositories. Simple comma separated wildcard patterns for repository artifact paths (with no leading slash). Ant-style path expressions are supported (*, **, ?). For example: 'org/apache/**'",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Description: "`path-ant-patterns` filter for `repository` and `all-repos` watch_resource.type",
						},
						"kv_filter": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.OneOf("property"),
										},
										Description: "The type of filter. Currently only support `property`",
									},
									"key": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
										Description: "The value of the filter, such as the property name of the artifact.",
									},
									"value": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
										Description: "The value of the filter, such as the property value of the artifact.",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Description: "Filter for `property` type. Works for `repository` and `all-repos` watch_resource.type.",
						},
					},
				},
			},
			"ticket_generation": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"create_tickets_for_ignored_violation": schema.BoolAttribute{
						Optional:    true,
						Description: "Specifies whether Jira tickets should also be created for policy violations that have been marked as ignored in Xray.",
					},
				},
				Blocks: map[string]schema.Block{
					"create_duplicate_tickets": schema.SingleNestedBlock{
						Blocks: map[string]schema.Block{
							"by_version": schema.SingleNestedBlock{
								Attributes: map[string]schema.Attribute{
									"build": schema.BoolAttribute{
										Optional:    true,
										Description: "Indicates whether duplicate tickets are created for builds.",
									},
									"package": schema.BoolAttribute{
										Optional:    true,
										Description: "Indicates whether duplicate tickets are created for packages.",
									},
									"release_bundle": schema.BoolAttribute{
										Optional:    true,
										Description: "Indicates whether duplicate tickets are created for release bundles.",
									},
								},
								Description: "Settings for creating duplicate tickets by version.",
							},
						},
						Description: "Settings for creating duplicate tickets.",
					},
					"impact_path_profiles_mapping": schema.SingleNestedBlock{
						Blocks: map[string]schema.Block{
							"include": schema.SetNestedBlock{
								NestedObject: schema.NestedBlockObject{
									Attributes: map[string]schema.Attribute{
										"profile": schema.StringAttribute{
											Required:    true,
											Description: "The Jira profile name for this impact path mapping.",
										},
										"pattern": schema.StringAttribute{
											Required:    true,
											Description: "The pattern for the impact path corresponding to the profile.",
										},
									},
								},
								Description: "List of impact path profile mappings.",
							},
						},
						Description: "Mapping of impact path profiles to Jira profiles.",
					},
				},
				Description: "Ticket generation settings for the watch. Requires `create_ticket_enabled` to be `true`.",
			},
			"assigned_policy": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:    true,
							Description: "The name of the policy that will be applied",
						},
						"type": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.OneOf("security", "license", "operational_risk"),
							},

							Description: "The type of the policy - security, license or operational risk",
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
				Description: "Nested argument describing policies that will be applied. Defined below.",
			},
		},
	}
}

func (r *WatchResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *WatchResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WatchResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectKey := plan.ProjectKey.ValueString()
	request, err := getRestyRequest(r.ProviderData.Client, projectKey)
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var watch WatchAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &watch)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// add 'build_repo' to resource if project_key is specified.
	// undocumented Xray API structure that is required!
	if len(plan.ProjectKey.ValueString()) > 0 {
		for idx, resource := range watch.ProjectResources.Resources {
			if resource.Type == "build" {
				watch.ProjectResources.Resources[idx].BuildRepo = fmt.Sprintf("%s-build-info", projectKey)
			}
		}
	}

	response, err := request.
		SetBody(watch).
		Post(WatchesEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WatchResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WatchResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectKey := plan.ProjectKey.ValueString()
	request, err := getRestyRequest(r.ProviderData.Client, projectKey)
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var watch WatchAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &watch)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// add 'build_repo' to resource if project_key is specified.
	// undocumented Xray API structure that is required!
	if len(plan.ProjectKey.ValueString()) > 0 {
		for idx, resource := range watch.ProjectResources.Resources {
			if resource.Type == "build" {
				watch.ProjectResources.Resources[idx].BuildRepo = fmt.Sprintf("%s-build-info", projectKey)
			}
		}
	}

	response, err := request.
		SetPathParam("name", plan.Name.ValueString()).
		SetBody(watch).
		Put(WatchEndpoint)
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
}

func (r *WatchResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WatchResourceModel

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

	var watch WatchAPIModel

	response, err := request.
		SetPathParam("name", state.Name.ValueString()).
		SetResult(&watch).
		Get(WatchEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, watch)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *WatchResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WatchResourceModel

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

	response, err := request.
		SetPathParam("name", state.Name.ValueString()).
		Delete(WatchEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
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
func (r *WatchResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) > 0 && parts[0] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[0])...)
	}

	if len(parts) == 2 && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[1])...)
	}
}

func (r WatchResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config WatchResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If watch_resource is not configured, return without warning.
	if config.WatchResource.IsNull() || config.WatchResource.IsUnknown() {
		return
	}

	repositoryResourceTypes := []string{"repository", "all-repos"}

	for idx, elem := range config.WatchResource.Elements() {
		attrs := elem.(types.Object).Attributes()

		resourceType := attrs["type"].(types.String).ValueString()

		// validate repo_type
		repoType := attrs["repo_type"].(types.String).ValueString()
		if resourceType == "repository" && len(repoType) == 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("watch_resources").AtListIndex(idx).AtName("repo_type"),
				"Invalid attribute values combination",
				"Attribute 'repo_type' not set when 'watch_resource.type' is set to 'repository'",
			)
			return
		}

		// validate type with filter and ant_filter
		antFilters := attrs["ant_filter"].(types.Set).Elements()
		antPatternsResourceTypes := []string{"all-builds", "all-projects", "all-releaseBundles", "all-releaseBundlesV2", "gitRepository"}
		if !slices.Contains(antPatternsResourceTypes, resourceType) && len(antFilters) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("watch_resources").AtListIndex(idx).AtName("ant_filter"),
				"Invalid attribute values combination",
				"attribute 'ant_filter' is set when 'watch_resource.type' is not set to 'all-builds', 'all-projects', 'all-releaseBundles', 'all-releaseBundlesV2', or 'gitRepository'",
			)
			return
		}

		pathAntFilters := attrs["path_ant_filter"].(types.Set).Elements()
		if !slices.Contains(repositoryResourceTypes, resourceType) && len(pathAntFilters) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("watch_resources").AtListIndex(idx).AtName("path_ant_filter"),
				"Invalid attribute values combination",
				"attribute 'path_ant_filter' is set when 'watch_resource.type' is not set to 'repository' or 'all-repos'",
			)
			return
		}

		kvFilters := attrs["kv_filter"].(types.Set).Elements()
		if !slices.Contains(repositoryResourceTypes, resourceType) && len(kvFilters) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("watch_resources").AtListIndex(idx).AtName("kv_filter"),
				"Invalid attribute values combination",
				"attribute 'kv_filter' is set when 'watch_resource.type' is not set to 'repository' or 'all-repos'",
			)
			return
		}
	}
}
