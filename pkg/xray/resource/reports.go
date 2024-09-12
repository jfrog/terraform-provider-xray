package xray

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkv2_diag "github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	sdkv2_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	sdkv2_validator "github.com/jfrog/terraform-provider-shared/validator"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

const (
	ReportsEndpoint = "xray/api/v1/reports/{reportType}"
	ReportEndpoint  = "xray/api/v1/reports/{reportId}"
)

type ReportResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type ReportResourceModel struct {
	ID         types.String `tfsdk:"id"`
	ReportID   types.Int64  `tfsdk:"report_id"`
	Name       types.String `tfsdk:"name"`
	ProjectKey types.String `tfsdk:"project_key"`
	Resources  types.Set    `tfsdk:"resources"`
	Filters    types.Set    `tfsdk:"filters"`
}

func (m ReportResourceModel) toAPIModel(
	ctx context.Context,
	apiModel *ReportAPIModel,
	toFiltersAPIModel func(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics),
) diag.Diagnostics {
	diags := diag.Diagnostics{}

	var resources *ResourcesAPIModel

	if len(m.Resources.Elements()) > 0 {
		attrs := m.Resources.Elements()[0].(types.Object).Attributes()

		var repositories *[]RepositoryAPIModel
		if v, ok := attrs["repository"]; ok {
			if len(v.(types.Set).Elements()) > 0 {
				rs := lo.Map(
					v.(types.Set).Elements(),
					func(elem attr.Value, _ int) RepositoryAPIModel {
						attrs := elem.(types.Object).Attributes()

						var includePathPatterns []string
						d := attrs["include_path_patterns"].(types.Set).ElementsAs(ctx, &includePathPatterns, false)
						if d.HasError() {
							diags.Append(d...)
						}

						var excludePathPatterns []string
						d = attrs["exclude_path_patterns"].(types.Set).ElementsAs(ctx, &excludePathPatterns, false)
						if d.HasError() {
							diags.Append(d...)
						}

						return RepositoryAPIModel{
							Name:                attrs["name"].(types.String).ValueString(),
							IncludePathPatterns: includePathPatterns,
							ExcludePathPatterns: excludePathPatterns,
						}
					},
				)

				repositories = &rs
			}
		}

		var builds *BuildsAPIModel
		if v, ok := attrs["builds"]; ok {
			if len(v.(types.Set).Elements()) > 0 {
				attrs := v.(types.Set).Elements()[0].(types.Object).Attributes()

				var names []string
				d := attrs["names"].(types.Set).ElementsAs(ctx, &names, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var includePatterns []string
				d = attrs["include_patterns"].(types.Set).ElementsAs(ctx, &includePatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var excludePatterns []string
				d = attrs["exclude_patterns"].(types.Set).ElementsAs(ctx, &excludePatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				builds = &BuildsAPIModel{
					Names:                  names,
					IncludePatterns:        includePatterns,
					ExcludePatterns:        excludePatterns,
					NumberOfLatestVersions: attrs["number_of_latest_versions"].(types.Int64).ValueInt64(),
				}
			}
		}

		var releaseBundles *ReleaseBundlesAPIModel
		if v, ok := attrs["release_bundles"]; ok {
			if len(v.(types.Set).Elements()) > 0 {
				attrs := v.(types.Set).Elements()[0].(types.Object).Attributes()

				var names []string
				d := attrs["names"].(types.Set).ElementsAs(ctx, &names, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var includePatterns []string
				d = attrs["include_patterns"].(types.Set).ElementsAs(ctx, &includePatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var excludePatterns []string
				d = attrs["exclude_patterns"].(types.Set).ElementsAs(ctx, &excludePatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				releaseBundles = &ReleaseBundlesAPIModel{
					Names:                  names,
					IncludePatterns:        includePatterns,
					ExcludePatterns:        excludePatterns,
					NumberOfLatestVersions: attrs["number_of_latest_versions"].(types.Int64).ValueInt64(),
				}
			}
		}

		var projects *ProjectsAPIModel
		if v, ok := attrs["projects"]; ok {
			if len(v.(types.Set).Elements()) > 0 {
				attrs := v.(types.Set).Elements()[0].(types.Object).Attributes()

				var names []string
				d := attrs["names"].(types.Set).ElementsAs(ctx, &names, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var includeKeyPatterns []string
				d = attrs["include_key_patterns"].(types.Set).ElementsAs(ctx, &includeKeyPatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				projects = &ProjectsAPIModel{
					Names:                  names,
					IncludeKeyPatterns:     includeKeyPatterns,
					NumberOfLatestVersions: attrs["number_of_latest_versions"].(types.Int64).ValueInt64(),
				}
			}
		}

		resources = &ResourcesAPIModel{
			Repositories:   repositories,
			Builds:         builds,
			ReleaseBundles: releaseBundles,
			Projects:       projects,
		}
	}

	filters, ds := toFiltersAPIModel(ctx, m.Filters.Elements())
	if ds.HasError() {
		diags.Append(ds...)
	}

	*apiModel = ReportAPIModel{
		Name:      m.Name.ValueString(),
		Resources: resources,
		Filters:   filters,
	}

	return diags
}

var reportsSchemaAttrs = lo.Assign(
	projectKeySchemaAttrs(false, ""),
	map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		"report_id": schema.Int64Attribute{
			Computed: true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.UseStateForUnknown(),
			},
			Description: "Report ID",
		},
		"name": schema.StringAttribute{
			Required: true,
			Validators: []validator.String{
				stringvalidator.LengthAtLeast(1),
			},
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
			Description: "Name of the report.",
		},
	},
)

var reportsBlocks = func(filtersAttrs map[string]schema.Attribute, filtersBlocks map[string]schema.Block) map[string]schema.Block {
	return map[string]schema.Block{
		"resources": schema.SetNestedBlock{
			NestedObject: schema.NestedBlockObject{
				Blocks: map[string]schema.Block{
					"repository": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"name": schema.StringAttribute{
									Required: true,
									Validators: []validator.String{
										stringvalidator.LengthAtLeast(1),
									},
									Description: "Repository name.",
								},
								"include_path_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Description: "Include path patterns.",
								},
								"exclude_path_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Description: "Exclude path patterns.",
								},
							},
						},
						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
							setvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("builds"),
								path.MatchRelative().AtParent().AtName("release_bundles"),
								path.MatchRelative().AtParent().AtName("projects"),
							),
						},
						Description: "The list of repositories for the report. Only one type of resource can be set per report.",
					},
					"builds": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"names": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("include_patterns"),
											path.MatchRelative().AtParent().AtName("exclude_patterns"),
										),
									},
									Description: "The list of build names. Only one of 'names' or '*_patterns' can be set.",
								},
								"include_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of include patterns. Only one of 'names' or '*_patterns' can be set.",
								},
								"exclude_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of exclude patterns. Only one of 'names' or '*_patterns' can be set.",
								},
								"number_of_latest_versions": schema.Int64Attribute{
									Optional: true,
									Computed: true,
									Default:  int64default.StaticInt64(1),
									Validators: []validator.Int64{
										int64validator.AtLeast(1),
									},
									Description: "The number of latest build versions to include to the report.",
								},
							},
						},
						Validators: []validator.Set{
							setvalidator.SizeAtMost(1),
							setvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("repository"),
								path.MatchRelative().AtParent().AtName("release_bundles"),
								path.MatchRelative().AtParent().AtName("projects"),
							),
						},
						Description: "The builds to include into the report. Only one type of resource can be set per report.",
					},
					"release_bundles": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"names": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("include_patterns"),
											path.MatchRelative().AtParent().AtName("exclude_patterns"),
										),
									},
									Description: "The list of release bundles names.",
								},
								"include_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of include patterns",
								},
								"exclude_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of exclude patterns",
								},
								"number_of_latest_versions": schema.Int64Attribute{
									Optional: true,
									Computed: true,
									Default:  int64default.StaticInt64(1),
									Validators: []validator.Int64{
										int64validator.AtLeast(0),
									},
									Description: "The number of latest release bundle versions to include to the report.",
								},
							},
						},
						Validators: []validator.Set{
							setvalidator.SizeAtMost(1),
							setvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("repository"),
								path.MatchRelative().AtParent().AtName("builds"),
								path.MatchRelative().AtParent().AtName("projects"),
							),
						},
						Description: "The release bundles to include into the report. Only one type of resource can be set per report.",
					},
					"projects": schema.SetNestedBlock{
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"names": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("include_key_patterns"),
										),
									},
									Description: "The list of project names.",
								},
								"include_key_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of include patterns",
								},
								"number_of_latest_versions": schema.Int64Attribute{
									Optional: true,
									Computed: true,
									Default:  int64default.StaticInt64(1),
									Validators: []validator.Int64{
										int64validator.AtLeast(0),
									},
									Description: "The number of latest release bundle versions to include to the report.",
								},
							},
						},
						Validators: []validator.Set{
							setvalidator.SizeAtMost(1),
							setvalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("repository"),
								path.MatchRelative().AtParent().AtName("builds"),
								path.MatchRelative().AtParent().AtName("release_bundles"),
							),
						},
						Description: "The projects to include into the report. Only one type of resource can be set per report.",
					},
				},
			},
			Validators: []validator.Set{
				setvalidator.IsRequired(),
				setvalidator.SizeAtMost(1),
			},
			Description: "The list of resources to include into the report.",
		},
		"filters": schema.SetNestedBlock{
			NestedObject: schema.NestedBlockObject{
				Attributes: filtersAttrs,
				Blocks:     filtersBlocks,
			},
			Validators: []validator.Set{
				setvalidator.IsRequired(),
				setvalidator.SizeAtMost(1),
			},
			Description: "Advanced filters.",
		},
	}
}

var getReportSchema = func(filtersSchema map[string]*sdkv2_schema.Schema) map[string]*sdkv2_schema.Schema {
	return sdk.MergeMaps(
		getProjectKeySchema(false, ""),
		map[string]*sdkv2_schema.Schema{
			"report_id": {
				Type:        sdkv2_schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Report ID",
			},
			"name": {
				Type:             sdkv2_schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
				Description:      "Name of the report.",
			},
			"resources": {
				Type:        sdkv2_schema.TypeSet,
				Required:    true,
				MaxItems:    1,
				Description: "The list of resources to include into the report.",
				Elem: &sdkv2_schema.Resource{
					Schema: map[string]*sdkv2_schema.Schema{
						"repository": {
							Type:        sdkv2_schema.TypeSet,
							Optional:    true,
							MinItems:    1,
							Description: "The list of repositories for the report. Only one type of resource can be set per report.",
							Elem: &sdkv2_schema.Resource{
								Schema: map[string]*sdkv2_schema.Schema{
									"name": {
										Type:             sdkv2_schema.TypeString,
										Required:         true,
										ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
										Description:      "Repository name.",
									},
									"include_path_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "Include path patterns.",
									},
									"exclude_path_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "Exclude path patterns.",
									},
								},
							},
						},
						"builds": {
							Type:        sdkv2_schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The builds to include into the report. Only one type of resource can be set per report.",
							Elem: &sdkv2_schema.Resource{
								Schema: map[string]*sdkv2_schema.Schema{
									"names": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of build names. Only one of 'names' or '*_patterns' can be set.",
									},
									"include_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of include patterns. Only one of 'names' or '*_patterns' can be set.",
									},
									"exclude_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of exclude patterns. Only one of 'names' or '*_patterns' can be set.",
									},
									"number_of_latest_versions": {
										Type:         sdkv2_schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(1),
										Description:  "The number of latest build versions to include to the report.",
									},
								},
							},
						},
						"release_bundles": {
							Type:        sdkv2_schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The release bundles to include into the report. Only one type of resource can be set per report.",
							Elem: &sdkv2_schema.Resource{
								Schema: map[string]*sdkv2_schema.Schema{
									"names": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of release bundles names.",
									},
									"include_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of include patterns",
									},
									"exclude_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of exclude patterns",
									},
									"number_of_latest_versions": {
										Type:         sdkv2_schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(0),
										Description:  "The number of latest release bundle versions to include to the report.",
									},
								},
							},
						},
						"projects": {
							Type:        sdkv2_schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The projects to include into the report. Only one type of resource can be set per report.",
							Elem: &sdkv2_schema.Resource{
								Schema: map[string]*sdkv2_schema.Schema{
									"names": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of project names.",
									},
									"include_key_patterns": {
										Type:        sdkv2_schema.TypeSet,
										Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
										Set:         sdkv2_schema.HashString,
										Optional:    true,
										Description: "The list of include patterns.",
									},
									"number_of_latest_versions": {
										Type:         sdkv2_schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(0),
										Description:  "The number of latest release bundle versions to include to the report.",
									},
								},
							},
						},
					},
				},
			},
			"filters": {
				Type:        sdkv2_schema.TypeSet,
				Required:    true,
				Description: "Advanced filters.",
				Elem: &sdkv2_schema.Resource{
					Schema: filtersSchema,
				},
			},
		},
	)
}

type ReportAPIModel struct {
	ReportId   int64              `json:"report_id,omitempty"`
	Name       string             `json:"name"`
	ProjectKey string             `json:"-"`
	Resources  *ResourcesAPIModel `json:"resources,omitempty"`
	Filters    *FiltersAPIModel   `json:"filters"`
}

type ResourcesAPIModel struct {
	Repositories   *[]RepositoryAPIModel   `json:"repositories,omitempty"`
	Builds         *BuildsAPIModel         `json:"builds,omitempty"`
	ReleaseBundles *ReleaseBundlesAPIModel `json:"release_bundles,omitempty"`
	Projects       *ProjectsAPIModel       `json:"projects,omitempty"`
}

type RepositoryAPIModel struct {
	Name                string   `json:"name,omitempty"`
	IncludePathPatterns []string `json:"include_path_patterns,omitempty"`
	ExcludePathPatterns []string `json:"exclude_path_patterns,omitempty"`
}

type BuildsAPIModel struct {
	Names                  []string `json:"names,omitempty"`
	IncludePatterns        []string `json:"include_patterns,omitempty"`
	ExcludePatterns        []string `json:"exclude_patterns,omitempty"`
	NumberOfLatestVersions int64    `json:"number_of_latest_versions,omitempty"`
}

type ReleaseBundlesAPIModel struct {
	Names                  []string `json:"names,omitempty"`
	IncludePatterns        []string `json:"include_patterns,omitempty"`
	ExcludePatterns        []string `json:"exclude_patterns,omitempty"`
	NumberOfLatestVersions int64    `json:"number_of_latest_versions,omitempty"`
}

type ProjectsAPIModel struct {
	Names                  []string `json:"names,omitempty"`
	IncludeKeyPatterns     []string `json:"include_key_patterns,omitempty"`
	NumberOfLatestVersions int64    `json:"number_of_latest_versions,omitempty"`
}

type FiltersAPIModel struct {
	VulnerableComponent string                   `json:"vulnerable_component,omitempty"` // Vulnerability report filter
	ImpactedArtifact    string                   `json:"impacted_artifact,omitempty"`
	HasRemediation      bool                     `json:"has_remediation,omitempty"`
	CVE                 string                   `json:"cve,omitempty"`
	IssueId             string                   `json:"issue_id,omitempty"`
	CVSSScore           *CVSSScoreAPIModel       `json:"cvss_score,omitempty"`
	Published           *StartAndEndDateAPIModel `json:"published,omitempty"`
	Unknown             bool                     `json:"unknown"` // Licenses report filter
	Unrecognized        bool                     `json:"unrecognized"`
	LicenseNames        []string                 `json:"license_names,omitempty"`
	LicensePatterns     []string                 `json:"license_patterns,omitempty"`
	Type                string                   `json:"type,omitempty"` // Violations report filter
	WatchNames          []string                 `json:"watch_names,omitempty"`
	WatchPatterns       []string                 `json:"watch_patterns,omitempty"`
	PolicyNames         []string                 `json:"policy_names,omitempty"`
	Updated             *StartAndEndDateAPIModel `json:"updated"`
	SecurityFilters     *SecurityFilterAPIModel  `json:"security_filters,omitempty"`
	LicenseFilters      *LicenseFilterAPIModel   `json:"license_filters,omitempty"`
	Risks               []string                 `json:"risks,omitempty"`     // Operational risks filter
	ScanDate            *StartAndEndDateAPIModel `json:"scan_date,omitempty"` // Common attributes
	Component           string                   `json:"component,omitempty"`
	Artifact            string                   `json:"artifact,omitempty"`
	Severities          []string                 `json:"severities,omitempty"`
}

type CVSSScoreAPIModel struct {
	MinScore float64 `json:"min_score,omitempty"`
	MaxScore float64 `json:"max_score,omitempty"`
}

type StartAndEndDateAPIModel struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type SecurityFilterAPIModel struct {
	Cve             string                   `json:"cve,omitempty"`
	IssueId         string                   `json:"issue_id,omitempty"`
	CVSSScore       *CVSSScoreAPIModel       `json:"cvss_score,omitempty"`
	SummaryContains string                   `json:"summary_contains"`
	HasRemediation  bool                     `json:"has_remediation,omitempty"`
	Published       *StartAndEndDateAPIModel `json:"published,omitempty"`
}

type LicenseFilterAPIModel struct {
	Unknown         bool     `json:"unknown"`
	Unrecognized    bool     `json:"unrecognized"`
	LicenseNames    []string `json:"license_names,omitempty"`
	LicensePatterns []string `json:"license_patterns,omitempty"`
}

func unpackReport(d *sdkv2_schema.ResourceData, reportType string) *ReportAPIModel {
	report := ReportAPIModel{}

	if v, ok := d.GetOk("project_key"); ok {
		report.ProjectKey = v.(string)
	}
	report.Name = d.Get("name").(string)

	report.Resources = unpackResources(d.Get("resources").(*sdkv2_schema.Set))

	if reportType == "vulnerabilities" {
		report.Filters = unpackVulnerabilitiesFilters(d.Get("filters").(*sdkv2_schema.Set))
	}

	if reportType == "licenses" {
		report.Filters = unpackLicensesFilters(d.Get("filters").(*sdkv2_schema.Set))
	}

	if reportType == "violations" {
		report.Filters = unpackViolationsFilters(d.Get("filters").(*sdkv2_schema.Set))
	}

	if reportType == "operationalRisks" {
		report.Filters = unpackOperationalRisksFilters(d.Get("filters").(*sdkv2_schema.Set))
	}

	return &report
}

func (r *ReportResource) Create(
	ctx context.Context,
	reportType string,
	toAPIModel func(context.Context, ReportResourceModel, *ReportAPIModel) diag.Diagnostics,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan ReportResourceModel

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

	var report ReportAPIModel
	resp.Diagnostics.Append(toAPIModel(ctx, plan, &report)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("reportType", reportType).
		SetBody(report).
		SetResult(&report).
		Post(ReportsEndpoint)

	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%d", report.ReportId))
	plan.ReportID = types.Int64Null()

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state ReportResourceModel

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

	response, err := request.
		SetPathParam("reportId", state.ID.ValueString()).
		Get(ReportEndpoint)

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

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ReportResource) Update(
	ctx context.Context,
	reportType string,
	toAPIModel func(context.Context, ReportResourceModel, *ReportAPIModel) diag.Diagnostics,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan ReportResourceModel

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

	var report ReportAPIModel
	resp.Diagnostics.Append(toAPIModel(ctx, plan, &report)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := request.
		SetPathParam("reportType", reportType).
		SetBody(report).
		SetResult(&report).
		Post(ReportsEndpoint)

	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%d", report.ReportId))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state ReportResourceModel

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
		SetPathParam("reportId", state.ID.ValueString()).
		Delete(ReportEndpoint)

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

func unpackResources(configured *sdkv2_schema.Set) *ResourcesAPIModel {
	var resources ResourcesAPIModel
	m := configured.List()[0].(map[string]interface{})

	if m["repository"] != nil {
		resources.Repositories = unpackRepository(m["repository"].(*sdkv2_schema.Set))
	}

	if m["builds"] != nil {
		resources.Builds = unpackBuilds(m["builds"].(*sdkv2_schema.Set))
	}

	if m["release_bundles"] != nil {
		resources.ReleaseBundles = unpackReleaseBundles(m["release_bundles"].(*sdkv2_schema.Set))
	}

	if m["release_bundles"] != nil {
		resources.Projects = unpackProjects(m["projects"].(*sdkv2_schema.Set))
	}

	return &resources
}

func unpackRepository(d *sdkv2_schema.Set) *[]RepositoryAPIModel {
	repos := d.List()

	if len(d.List()) > 0 {
		var repositories []RepositoryAPIModel
		for _, raw := range repos {
			f := raw.(map[string]interface{})
			repository := RepositoryAPIModel{
				Name:                f["name"].(string),
				IncludePathPatterns: sdk.CastToStringArr(f["include_path_patterns"].(*sdkv2_schema.Set).List()),
				ExcludePathPatterns: sdk.CastToStringArr(f["exclude_path_patterns"].(*sdkv2_schema.Set).List()),
			}
			repositories = append(repositories, repository)
		}
		return &repositories
	}

	return nil
}

func unpackBuilds(d *sdkv2_schema.Set) *BuildsAPIModel {
	if len(d.List()) > 0 {
		var builds BuildsAPIModel
		f := d.List()[0].(map[string]interface{})
		builds = BuildsAPIModel{
			Names:                  sdk.CastToStringArr(f["names"].(*sdkv2_schema.Set).List()),
			IncludePatterns:        sdk.CastToStringArr(f["include_patterns"].(*sdkv2_schema.Set).List()),
			ExcludePatterns:        sdk.CastToStringArr(f["exclude_patterns"].(*sdkv2_schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int64),
		}
		return &builds
	}

	return nil
}

func unpackReleaseBundles(d *sdkv2_schema.Set) *ReleaseBundlesAPIModel {
	if len(d.List()) > 0 {
		var releaseBundles ReleaseBundlesAPIModel
		f := d.List()[0].(map[string]interface{})
		releaseBundles = ReleaseBundlesAPIModel{
			Names:                  sdk.CastToStringArr(f["names"].(*sdkv2_schema.Set).List()),
			IncludePatterns:        sdk.CastToStringArr(f["include_patterns"].(*sdkv2_schema.Set).List()),
			ExcludePatterns:        sdk.CastToStringArr(f["exclude_patterns"].(*sdkv2_schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int64),
		}
		return &releaseBundles
	}

	return nil
}

func unpackProjects(d *sdkv2_schema.Set) *ProjectsAPIModel {
	if len(d.List()) > 0 {
		var projects ProjectsAPIModel
		f := d.List()[0].(map[string]interface{})
		projects = ProjectsAPIModel{
			Names:                  sdk.CastToStringArr(f["names"].(*sdkv2_schema.Set).List()),
			IncludeKeyPatterns:     sdk.CastToStringArr(f["include_key_patterns"].(*sdkv2_schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int64),
		}
		return &projects
	}

	return nil
}

func unpackVulnerabilitiesFilters(filter *sdkv2_schema.Set) *FiltersAPIModel {
	var filters FiltersAPIModel
	m := filter.List()[0].(map[string]interface{})

	if m["vulnerable_component"] != nil {
		filters.VulnerableComponent = m["vulnerable_component"].(string)
	}

	if m["impacted_artifact"] != nil {
		filters.ImpactedArtifact = m["impacted_artifact"].(string)
	}

	filters.HasRemediation = m["has_remediation"].(bool)

	if m["cve"] != nil {
		filters.CVE = m["cve"].(string)
	}

	if m["issue_id"] != nil {
		filters.IssueId = m["issue_id"].(string)
	}

	filters.Severities = sdk.CastToStringArr(m["severities"].(*sdkv2_schema.Set).List())

	if m["cvss_score"] != nil {
		filters.CVSSScore = unpackCvssScore(m["cvss_score"].(*sdkv2_schema.Set))
	}

	if m["published"] != nil {
		filters.Published = unpackStartAndEndDate(m["published"].(*sdkv2_schema.Set))
	}

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*sdkv2_schema.Set))
	}

	return &filters
}

func unpackLicensesFilters(filter *sdkv2_schema.Set) *FiltersAPIModel {
	var filters FiltersAPIModel
	m := filter.List()[0].(map[string]interface{})

	if m["component"] != nil {
		filters.Component = m["component"].(string)
	}

	if m["artifact"] != nil {
		filters.Artifact = m["artifact"].(string)
	}

	filters.Unknown = m["unknown"].(bool)
	filters.Unrecognized = m["unrecognized"].(bool)

	filters.LicenseNames = sdk.CastToStringArr(m["license_names"].(*sdkv2_schema.Set).List())
	filters.LicensePatterns = sdk.CastToStringArr(m["license_patterns"].(*sdkv2_schema.Set).List())

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*sdkv2_schema.Set))
	}

	return &filters
}

func unpackViolationsSecurityFilters(filter *sdkv2_schema.Set) *SecurityFilterAPIModel {
	var securityFilter SecurityFilterAPIModel
	m := filter.List()[0].(map[string]interface{})

	if m["cve"] != nil {
		securityFilter.Cve = m["cve"].(string)
	}

	if m["issue_id"] != nil {
		securityFilter.IssueId = m["issue_id"].(string)
	}

	if m["cvss_score"] != nil {
		securityFilter.CVSSScore = unpackCvssScore(m["cvss_score"].(*sdkv2_schema.Set))
	}

	if m["summary_contains"] != nil {
		securityFilter.IssueId = m["summary_contains"].(string)
	}

	securityFilter.HasRemediation = m["has_remediation"].(bool)

	if m["updated"] != nil {
		securityFilter.Published = unpackStartAndEndDate(m["published"].(*sdkv2_schema.Set))
	}

	return &securityFilter
}

func unpackViolationsFilters(filter *sdkv2_schema.Set) *FiltersAPIModel {
	var filters FiltersAPIModel
	m := filter.List()[0].(map[string]interface{})

	if len(m) > 0 {

		if m["type"] != nil {
			filters.Type = m["type"].(string)
		}

		filters.WatchNames = sdk.CastToStringArr(m["watch_names"].(*sdkv2_schema.Set).List())
		filters.WatchPatterns = sdk.CastToStringArr(m["watch_patterns"].(*sdkv2_schema.Set).List())

		if m["component"] != nil {
			filters.Component = m["component"].(string)
		}

		if m["artifact"] != nil {
			filters.Artifact = m["artifact"].(string)
		}

		filters.PolicyNames = sdk.CastToStringArr(m["policy_names"].(*sdkv2_schema.Set).List())
		filters.Severities = sdk.CastToStringArr(m["severities"].(*sdkv2_schema.Set).List())

		if m["updated"].(*sdkv2_schema.Set).Len() > 0 {
			filters.Updated = unpackStartAndEndDate(m["updated"].(*sdkv2_schema.Set))
		}

		if m["security_filters"].(*sdkv2_schema.Set).Len() > 0 {
			filters.SecurityFilters = unpackViolationsSecurityFilters(m["security_filters"].(*sdkv2_schema.Set))
		}

		if m["license_filters"].(*sdkv2_schema.Set).Len() > 0 {
			filters.LicenseFilters = unpackViolationsLicensesFilters(m["license_filters"].(*sdkv2_schema.Set))
		}

		return &filters
	}
	return nil
}

func unpackViolationsLicensesFilters(filter *sdkv2_schema.Set) *LicenseFilterAPIModel {
	var filters LicenseFilterAPIModel
	m := filter.List()[0].(map[string]interface{})

	filters.Unknown = m["unknown"].(bool)
	filters.Unrecognized = m["unrecognized"].(bool)

	filters.LicenseNames = sdk.CastToStringArr(m["license_names"].(*sdkv2_schema.Set).List())
	filters.LicensePatterns = sdk.CastToStringArr(m["license_patterns"].(*sdkv2_schema.Set).List())

	return &filters
}

func unpackOperationalRisksFilters(filter *sdkv2_schema.Set) *FiltersAPIModel {
	var filters FiltersAPIModel
	m := filter.List()[0].(map[string]interface{})

	if m["component"] != nil {
		filters.Component = m["component"].(string)
	}
	if m["artifact"] != nil {
		filters.Artifact = m["artifact"].(string)
	}

	filters.Risks = sdk.CastToStringArr(m["risks"].(*sdkv2_schema.Set).List())

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*sdkv2_schema.Set))
	}

	return &filters
}

func unpackCvssScore(d *sdkv2_schema.Set) *CVSSScoreAPIModel {
	var cvssScore CVSSScoreAPIModel

	if len(d.List()) > 0 {
		f := d.List()[0].(map[string]interface{})
		cvssScore = CVSSScoreAPIModel{
			MinScore: f["min_score"].(float64),
			MaxScore: f["max_score"].(float64),
		}
		return &cvssScore
	}

	return nil
}

func unpackStartAndEndDate(d *sdkv2_schema.Set) *StartAndEndDateAPIModel {
	var dates StartAndEndDateAPIModel

	if len(d.List()) > 0 {
		f := d.List()[0].(map[string]interface{})
		dates = StartAndEndDateAPIModel{
			Start: f["start"].(string),
			End:   f["end"].(string),
		}
		return &dates
	}

	return nil
}

func resourceXrayVulnerabilitiesReportCreate(ctx context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	return createReport("vulnerabilities", d, m)
}

func resourceXrayLicensesReportCreate(ctx context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	return createReport("licenses", d, m)
}

func resourceXrayViolationsReportCreate(ctx context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	return createReport("violations", d, m)
}

func resourceXrayOperationalRisksReportCreate(ctx context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	return createReport("operationalRisks", d, m)
}

func resourceXrayReportRead(ctx context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	report := ReportAPIModel{}

	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, projectKey)
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}

	resp, err := req.
		SetResult(&report).
		SetPathParam("reportId", d.Id()).
		Get("xray/api/v1/reports/{reportId}")
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return sdkv2_diag.Errorf("report (%s) not found, removing from state", d.Id())
	}
	if resp.IsError() {
		return sdkv2_diag.Errorf("%s", resp.String())
	}

	return nil
}

func resourceXrayReportDelete(_ context.Context, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, projectKey)
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}

	resp, err := req.
		SetPathParam("reportId", d.Id()).
		Delete("xray/api/v1/reports/{reportId}")
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}
	if resp.IsError() {
		return sdkv2_diag.Errorf("%s", resp.String())
	}

	d.SetId("")

	return nil
}

func createReport(reportType string, d *sdkv2_schema.ResourceData, m interface{}) sdkv2_diag.Diagnostics {
	report := unpackReport(d, reportType)
	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, report.ProjectKey)
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}

	resp, err := req.
		SetBody(report).
		SetResult(&report).
		SetPathParam("reportType", reportType).
		Post("xray/api/v1/reports/{reportType}")
	if err != nil {
		return sdkv2_diag.FromErr(err)
	}
	if resp.IsError() {
		return sdkv2_diag.Errorf("%s", resp.String())
	}

	d.SetId(fmt.Sprintf("%d", report.ReportId))

	return nil
}

func reportResourceDiff(_ context.Context, diff *sdkv2_schema.ResourceDiff, v interface{}) error {
	reportResources := diff.Get("resources").(*sdkv2_schema.Set).List()
	if len(reportResources) == 0 {
		return nil
	}

	// Verify only one resource attribute is set.
	for _, reportResource := range reportResources {
		r := reportResource.(map[string]interface{})

		var resourceCounter int

		if r["repository"].(*sdkv2_schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if r["builds"].(*sdkv2_schema.Set).Len() > 0 {
			resourceCounter += 1
		}
		if r["release_bundles"].(*sdkv2_schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if r["projects"].(*sdkv2_schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if resourceCounter > 1 {
			return fmt.Errorf("request payload is invalid as only one resource per report is allowed")
		}
	}
	// Verify filter fields
	reportFilters := diff.Get("filters").(*sdkv2_schema.Set).List()
	for _, reportFilter := range reportFilters {
		r := reportFilter.(map[string]interface{})

		if len(reportFilters) == 0 {
			return nil
		}
		// Check violations filter
		var watchCounter int
		if r["watch_names"] != nil && r["watch_names"].(*sdkv2_schema.Set).Len() > 0 {
			watchCounter += 1
		}

		if r["watch_patterns"] != nil && r["watch_patterns"].(*sdkv2_schema.Set).Len() > 0 {
			watchCounter += 1
		}

		if watchCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'watch_names' or 'watch_patterns' is allowed in the violations filter")
		}
		// Check vulnerabilities filter
		var secFilterCounter int
		if r["cve"] != nil && r["cve"] != "" {
			secFilterCounter += 1
		}

		if r["issue_id"] != nil && r["issue_id"] != "" {
			secFilterCounter += 1
		}

		if secFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'cve' or 'issue_id' is allowed in the vulnerabilities filter")
		}

		var severitiesFilterCounter int
		if r["severities"] != nil && r["severities"].(*sdkv2_schema.Set).Len() > 0 {
			severitiesFilterCounter += 1
		}

		if r["cvss_score"] != nil && r["cvss_score"].(*sdkv2_schema.Set).Len() > 0 {
			severitiesFilterCounter += 1
		}

		if severitiesFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'severities' or 'cvss_score' is allowed in the vulnerabilities filter")
		}

		// Check license filter in violations report
		var nestedLicenseFilterCounter int
		if r["license_filters"] != nil && r["license_filters"].(*sdkv2_schema.Set).Len() > 0 {
			m := r["license_filters"].(*sdkv2_schema.Set).List()[0].(map[string]interface{})
			if m["license_names"] != nil && m["license_names"].(*sdkv2_schema.Set).Len() > 0 {
				nestedLicenseFilterCounter += 1
			}
			if m["license_patterns"] != nil && m["license_patterns"].(*sdkv2_schema.Set).Len() > 0 {
				nestedLicenseFilterCounter += 1
			}
		}

		if nestedLicenseFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'license_names' or 'license_patterns' is allowed in the license filter")
		}

		// Check license filter in license report
		var licenseFilterCounter int
		if r["license_names"] != nil && r["license_names"].(*sdkv2_schema.Set).Len() > 0 {
			licenseFilterCounter += 1
		}

		if r["license_patterns"] != nil && r["license_patterns"].(*sdkv2_schema.Set).Len() > 0 {
			licenseFilterCounter += 1
		}

		if licenseFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'license_names' or 'license_patterns' is allowed in the license filter")
		}

		// Verify severities in Vulnerabilities and Violations filters
		if r["severities"] != nil && r["severities"].(*sdkv2_schema.Set).Len() > 0 {
			for _, severity := range r["severities"].(*sdkv2_schema.Set).List() {
				if !slices.Contains([]string{"Low", "Medium", "High", "Critical"}, severity.(string)) {
					return fmt.Errorf("'severity' attribute value must be one or several of 'Low', 'Medium', 'High', 'Critical'")
				}
			}
		}

		// Verify risks in Operational Risks filter
		if r["risks"] != nil && r["risks"].(*sdkv2_schema.Set).Len() > 0 {
			for _, severity := range r["risks"].(*sdkv2_schema.Set).List() {
				if !slices.Contains([]string{"None", "Low", "Medium", "High"}, severity.(string)) {
					return fmt.Errorf("'risks' attribute value must be one or several of 'None', 'Low', 'Medium', 'High'")
				}
			}
		}
	}
	return nil
}
