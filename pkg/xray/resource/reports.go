package xray

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
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
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
)

type timezoneDefaultModifier struct{}

func (m timezoneDefaultModifier) Description(ctx context.Context) string {
	return "Sets the default timezone to UTC when cron_schedule is set"
}

func (m timezoneDefaultModifier) MarkdownDescription(ctx context.Context) string {
	return "Sets the default timezone to UTC when cron_schedule is set"
}

func (m timezoneDefaultModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If cron_schedule is not set, explicitly set timezone to null
	var plan ReportResourceModel
	diags := req.Plan.Get(ctx, &plan)
	if diags.HasError() {
		return
	}

	if plan.CronSchedule.IsNull() || plan.CronSchedule.IsUnknown() {
		resp.PlanValue = types.StringNull()
		return
	}

	// If cron_schedule is set and timezone is not set, default to UTC
	if req.PlanValue.IsNull() {
		resp.PlanValue = types.StringValue("UTC")
	}
}

const (
	ReportsEndpoint                  = "xray/api/v1/reports/{reportType}"
	ReportEndpoint                   = "xray/api/v1/reports/{reportId}"
	MinVersionForCronAndNotify       = "3.130.0"
	FixVersionForProjectScopeKey     = "3.130.0"
	MinVersionForCAAndRuntimeFilters = "3.130.0"
)

type ReportResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type ReportResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	ReportID             types.Int64  `tfsdk:"report_id"`
	Name                 types.String `tfsdk:"name"`
	ProjectKey           types.String `tfsdk:"project_key"`
	Resources            types.Set    `tfsdk:"resources"`
	Filters              types.Set    `tfsdk:"filters"`
	CronSchedule         types.String `tfsdk:"cron_schedule"`
	CronScheduleTimezone types.String `tfsdk:"cron_schedule_timezone"`
	Emails               types.Set    `tfsdk:"emails"`
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

		var releaseBundlesv2 *ReleaseBundlesv2APIModel
		if v, ok := attrs["release_bundles_v2"]; ok {
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

				releaseBundlesv2 = &ReleaseBundlesv2APIModel{
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

				var keys []string
				d = attrs["keys"].(types.Set).ElementsAs(ctx, &keys, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var includeKeyPatterns []string
				d = attrs["include_key_patterns"].(types.Set).ElementsAs(ctx, &includeKeyPatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				var excludeKeyPatterns []string
				d = attrs["exclude_key_patterns"].(types.Set).ElementsAs(ctx, &excludeKeyPatterns, false)
				if d.HasError() {
					diags.Append(d...)
				}

				projects = &ProjectsAPIModel{
					Names:                  names,
					Keys:                   keys,
					IncludeKeyPatterns:     includeKeyPatterns,
					ExcludeKeyPatterns:     excludeKeyPatterns,
					NumberOfLatestVersions: attrs["number_of_latest_versions"].(types.Int64).ValueInt64(),
				}
			}
		}

		resources = &ResourcesAPIModel{
			Repositories:     repositories,
			Builds:           builds,
			ReleaseBundles:   releaseBundles,
			ReleaseBundlesv2: releaseBundlesv2,
			Projects:         projects,
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

	// Only set cron_schedule and timezone if schedule is present
	if !m.CronSchedule.IsNull() {
		apiModel.CronSchedule = m.CronSchedule.ValueString()
		// Set timezone to UTC if not specified
		if m.CronScheduleTimezone.IsNull() {
			apiModel.CronScheduleTimezone = "UTC"
		} else {
			apiModel.CronScheduleTimezone = m.CronScheduleTimezone.ValueString()
		}
	}

	// Convert emails to notify structure
	if !m.Emails.IsNull() && len(m.Emails.Elements()) > 0 {
		var emails []string
		if diags := m.Emails.ElementsAs(ctx, &emails, false); diags.HasError() {
			return diags
		}
		apiModel.Notify = &NotifyAPIModel{
			Emails: emails,
		}
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
			Description: "Name of the report.",
		},
		"cron_schedule": schema.StringAttribute{
			Optional: true,
			Validators: []validator.String{
				validatorfw_string.IsCronSchedule(),
			},
			Description: "Schedule for automated report generation. Format: 'minute hour day-of-month month day-of-week' where:\n" +
				"  - minute: must be 00, 15, 30, or 45 (quarter-hourly)\n" +
				"  - hour: must be 00-23 (2-digit format, e.g., 03 not 3)\n" +
				"  - day-of-month: 1-31, * (any), or ? (unspecified)\n" +
				"  - month: 1-12 or JAN-DEC\n" +
				"  - day-of-week: 0-6 (0=Sunday) or SUN-SAT\n" +
				"Examples:\n" +
				"  - '45 03 * * MON' = Every Monday at 03:45 AM\n" +
				"  - '00 00 1 * ?' = At midnight (00:00) on the first day of every month\n" +
				"  - '30 12 ? * MON-FRI' = At 12:30 PM every weekday\n" +
				"Note: Requires Xray " + MinVersionForCronAndNotify + " or higher.",
		},
		"cron_schedule_timezone": schema.StringAttribute{
			Optional: true,
			Computed: true,
			Validators: []validator.String{
				validatorfw_string.IsCronScheduleTimezone(),
				stringvalidator.AlsoRequires(path.MatchRoot("cron_schedule")),
			},
			PlanModifiers: []planmodifier.String{
				timezoneDefaultModifier{},
			},
			Description: "Timezone for cron schedule. For valid timezone formats, see: [iana-timezones](https://timeapi.io/documentation/iana-timezones). Note: Requires Xray " + MinVersionForCronAndNotify + " or higher. Only used when cron_schedule is set.",
		},
		"emails": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
			},
			Description: "List of email addresses to notify when report generation is complete. Note: Requires Xray " + MinVersionForCronAndNotify + " or higher.",
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
								path.MatchRelative().AtParent().AtName("release_bundles_v2"),
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
								path.MatchRelative().AtParent().AtName("release_bundles_v2"),
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
										int64validator.AtLeast(1),
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
								path.MatchRelative().AtParent().AtName("release_bundles_v2"),
								path.MatchRelative().AtParent().AtName("projects"),
							),
						},
						Description: "The release bundles to include into the report. Only one type of resource can be set per report.",
					},
					"release_bundles_v2": schema.SetNestedBlock{
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
										int64validator.AtLeast(1),
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
								path.MatchRelative().AtParent().AtName("projects"),
							),
						},
						Description: "The release bundles v2 to include into the report. Only one type of resource can be set per report.",
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
											path.MatchRelative().AtParent().AtName("keys"),
										),
									},
									Description:        "The list of project names.",
									DeprecationMessage: "Use `keys` instead. Note: For Xray version " + FixVersionForProjectScopeKey + " and above, It will be removed in the next minor version release.",
								},
								"keys": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("include_key_patterns"),
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
									Description: "The list of project keys. Note: Available from Xray version " + FixVersionForProjectScopeKey + " and higher.",
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
								"exclude_key_patterns": schema.SetAttribute{
									ElementType: types.StringType,
									Optional:    true,
									Computed:    true,
									Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
									Description: "The list of exclude patterns",
									Validators: []validator.Set{
										setvalidator.ConflictsWith(
											path.MatchRelative().AtParent().AtName("names"),
										),
									},
								},
								"number_of_latest_versions": schema.Int64Attribute{
									Optional: true,
									Computed: true,
									Default:  int64default.StaticInt64(1),
									Validators: []validator.Int64{
										int64validator.AtLeast(1),
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
								path.MatchRelative().AtParent().AtName("release_bundles_v2"),
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

type ReportAPIModel struct {
	ReportId             int64              `json:"report_id,omitempty"`
	Name                 string             `json:"name"`
	ProjectKey           string             `json:"-"`
	Resources            *ResourcesAPIModel `json:"resources,omitempty"`
	Filters              *FiltersAPIModel   `json:"filters"`
	CronSchedule         string             `json:"cron_schedule,omitempty"`
	CronScheduleTimezone string             `json:"cron_schedule_timezone,omitempty"`
	Notify               *NotifyAPIModel    `json:"notify,omitempty"`
}

type NotifyAPIModel struct {
	Emails []string `json:"emails,omitempty"`
}

type ResourcesAPIModel struct {
	Repositories     *[]RepositoryAPIModel     `json:"repositories,omitempty"`
	Builds           *BuildsAPIModel           `json:"builds,omitempty"`
	ReleaseBundles   *ReleaseBundlesAPIModel   `json:"release_bundles,omitempty"`
	ReleaseBundlesv2 *ReleaseBundlesv2APIModel `json:"release_bundles_v2,omitempty"`
	Projects         *ProjectsAPIModel         `json:"projects,omitempty"`
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

type ReleaseBundlesv2APIModel struct {
	Names                  []string `json:"names,omitempty"`
	IncludePatterns        []string `json:"include_patterns,omitempty"`
	ExcludePatterns        []string `json:"exclude_patterns,omitempty"`
	NumberOfLatestVersions int64    `json:"number_of_latest_versions,omitempty"`
}

type ProjectsAPIModel struct {
	Names                  []string `json:"names,omitempty"`
	Keys                   []string `json:"keys,omitempty"`
	IncludeKeyPatterns     []string `json:"include_key_patterns,omitempty"`
	ExcludeKeyPatterns     []string `json:"exclude_key_patterns,omitempty"`
	NumberOfLatestVersions int64    `json:"number_of_latest_versions,omitempty"`
}

type FiltersAPIModel struct {
	// Vulnerability report filter
	VulnerableComponent string `json:"vulnerable_component,omitempty"`
	HasRemediation      *bool  `json:"has_remediation,omitempty"`
	CVE                 string `json:"cve,omitempty"`
	IssueId             string `json:"issue_id,omitempty"`

	// Licenses report filter
	Unknown         *bool    `json:"unknown,omitempty"`
	Unrecognized    *bool    `json:"unrecognized,omitempty"`
	LicenseNames    []string `json:"license_names,omitempty"`
	LicensePatterns []string `json:"license_patterns,omitempty"`

	// Violations report filter
	Type                     string                           `json:"type,omitempty"`
	ViolationStatus          string                           `json:"violation_status,omitempty"`
	WatchNames               []string                         `json:"watch_names,omitempty"`
	WatchPatterns            []string                         `json:"watch_patterns,omitempty"`
	PolicyNames              []string                         `json:"policy_names,omitempty"`
	Updated                  *StartAndEndDateAPIModel         `json:"updated,omitempty"`
	SecurityViolationFilters *SecurityViolationFilterAPIModel `json:"security_filters,omitempty"`
	LicenseViolationFilters  *LicenseViolationFilterAPIModel  `json:"license_filters,omitempty"`
	RuntimeFilter            *RuntimeFilterAPIModel           `json:"runtime_filter,omitempty"`
	CAFilter                 *CAFilterAPIModel                `json:"ca_filter,omitempty"`

	// Exposures report filter
	Category string `json:"category,omitempty"`

	// Operational risks filter
	Risks []string `json:"risks,omitempty"`

	// Common attributes
	Component        string                   `json:"component,omitempty"`
	Artifact         string                   `json:"artifact,omitempty"`
	ImpactedArtifact string                   `json:"impacted_artifact,omitempty"`
	CVSSScore        *CVSSScoreAPIModel       `json:"cvss_score,omitempty"`
	Severities       []string                 `json:"severities,omitempty"`
	ScanDate         *StartAndEndDateAPIModel `json:"scan_date,omitempty"`
	Published        *StartAndEndDateAPIModel `json:"published,omitempty"`
}

type CVSSScoreAPIModel struct {
	MinScore float64 `json:"min_score,omitempty"`
	MaxScore float64 `json:"max_score,omitempty"`
}

type StartAndEndDateAPIModel struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type SecurityViolationFilterAPIModel struct {
	Cve             string                   `json:"cve,omitempty"`
	IssueId         string                   `json:"issue_id,omitempty"`
	CVSSScore       *CVSSScoreAPIModel       `json:"cvss_score,omitempty"`
	SummaryContains string                   `json:"summary_contains"`
	HasRemediation  *bool                    `json:"has_remediation,omitempty"`
	Published       *StartAndEndDateAPIModel `json:"published,omitempty"`
}

type LicenseViolationFilterAPIModel struct {
	Unknown         *bool    `json:"unknown"`
	LicenseNames    []string `json:"license_names,omitempty"`
	LicensePatterns []string `json:"license_patterns,omitempty"`
}
type RuntimeFilterAPIModel struct {
	TimePeriod string `json:"time_period,omitempty"`
}

type CAFilterAPIModel struct {
	AllowedCAStatuses []string `json:"allowed_ca_statuses,omitempty"`
}

func validateCronAndNotify(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse, client *resty.Client) {
	// Skip version check if provider is not configured yet
	if client == nil {
		return
	}

	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check cron_schedule version requirement
	if !config.CronSchedule.IsNull() {
		if _, err := util.CheckXrayVersion(client, MinVersionForCronAndNotify, "Cron scheduling is available from Xray version %s and higher. Current version: %s"); err != nil {
			resp.Diagnostics.AddError(
				"Feature Not Available",
				err.Error(),
			)
			return
		}
	}

	// Check cron_schedule_timezone version requirement
	if !config.CronScheduleTimezone.IsNull() {
		if _, err := util.CheckXrayVersion(client, MinVersionForCronAndNotify, "Cron schedule timezone is available from Xray version %s and higher. Current version: %s"); err != nil {
			resp.Diagnostics.AddError(
				"Feature Not Available",
				err.Error(),
			)
			return
		}
	}

	// Check emails version requirement
	if !config.Emails.IsNull() && len(config.Emails.Elements()) > 0 {
		if _, err := util.CheckXrayVersion(client, MinVersionForCronAndNotify, "Email notifications are available from Xray version %s and higher. Current version: %s"); err != nil {
			resp.Diagnostics.AddError(
				"Feature Not Available",
				err.Error(),
			)
			return
		}
	}
}

func validateProjectsScope(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse, client *resty.Client) {
	// Skip version check if provider is not configured yet
	if client == nil {
		return
	}

	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Resources.IsNull() && !config.Resources.IsUnknown() {
		resourcesElems := config.Resources.Elements()
		if len(resourcesElems) > 0 {
			if resourcesObj, ok := resourcesElems[0].(types.Object); ok {
				attrs := resourcesObj.Attributes()
				if projectsSet, ok := attrs["projects"].(types.Set); ok && !projectsSet.IsNull() && len(projectsSet.Elements()) > 0 {
					projectsAttrs := projectsSet.Elements()[0].(types.Object).Attributes()
					names := projectsAttrs["names"].(types.Set)
					keys := projectsAttrs["keys"].(types.Set)

					// Check if names is used with Xray >= 3.130.0
					if !names.IsNull() && len(names.Elements()) > 0 {
						if _, err := util.CheckXrayVersion(client, FixVersionForProjectScopeKey, "Project names are deprecated from Xray version %s and higher. Use project keys instead. Current version: %s"); err == nil {
							resp.Diagnostics.AddWarning(
								"Deprecated Attribute",
								"Project names are deprecated. Please use project keys instead.",
							)
						}
					}

					// Check if keys is used with Xray < 3.130.0
					if !keys.IsNull() && len(keys.Elements()) > 0 {
						if _, err := util.CheckXrayVersion(client, FixVersionForProjectScopeKey, "Project keys are available from Xray version %s and higher. Current version: %s"); err != nil {
							resp.Diagnostics.AddError(
								"Feature Not Available",
								err.Error(),
							)
							return
						}
					}
				}
			}
		}
	}
}

func validateSingleResourceType(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Resources.IsNull() && !config.Resources.IsUnknown() {
		resourcesElems := config.Resources.Elements()
		if len(resourcesElems) > 0 {
			if resourcesObj, ok := resourcesElems[0].(types.Object); ok {
				attrs := resourcesObj.Attributes()
				resourceCount := 0
				resourceTypes := []string{"repository", "builds", "release_bundles", "release_bundles_v2", "projects"}
				for _, resourceType := range resourceTypes {
					if v, ok := attrs[resourceType].(types.Set); ok && !v.IsNull() && len(v.Elements()) > 0 {
						resourceCount++
					}
				}
				if resourceCount > 1 {
					resp.Diagnostics.AddError(
						"Invalid Resource Configuration",
						"Only one type of resource (repository, builds, release_bundles, release_bundles_v2, or projects) can be specified per report.",
					)
				}
			}
		}
	}
}

func validateSecurityFilterCveAndIssueId(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
		filtersElems := config.Filters.Elements()
		if len(filtersElems) > 0 {
			attrs := filtersElems[0].(types.Object).Attributes()

			// Check cve and issue_id mutual exclusivity
			cve := attrs["cve"].(types.String)
			issueId := attrs["issue_id"].(types.String)
			if !cve.IsNull() && !issueId.IsNull() {
				resp.Diagnostics.AddError(
					"Invalid Attribute Combination",
					"Only one of 'cve' or 'issue_id' can be specified in filters block",
				)
			}
		}
	}
}

func validateSecurityFilterSeveritiesAndCvssScore(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
		filtersElems := config.Filters.Elements()
		if len(filtersElems) > 0 {
			attrs := filtersElems[0].(types.Object).Attributes()

			// Check severities and cvss_score mutual exclusivity
			severities := attrs["severities"].(types.Set)
			cvssScore := attrs["cvss_score"].(types.Set)
			if !severities.IsNull() && !cvssScore.IsNull() && len(severities.Elements()) > 0 && len(cvssScore.Elements()) > 0 {
				resp.Diagnostics.AddError(
					"Invalid Attribute Combination",
					"Only one of 'severities' or 'cvss_score' can be specified in filters block",
				)
			}
		}
	}
}

func validateCaAndRuntimeFilters(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse, client *resty.Client) {
	// Skip version check if provider is not configured yet
	if client == nil {
		return
	}

	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
		filtersElems := config.Filters.Elements()
		if len(filtersElems) > 0 {
			attrs := filtersElems[0].(types.Object).Attributes()

			caFilterSet := attrs["ca_filter"].(types.Set)
			runtimeFilterSet := attrs["runtime_filter"].(types.Set)

			// Check CA filter version requirement
			if !caFilterSet.IsNull() && len(caFilterSet.Elements()) > 0 {
				if _, err := util.CheckXrayVersion(client, MinVersionForCAAndRuntimeFilters, "Contextual analysis filter is available from Xray version %s and higher. Current version: %s"); err != nil {
					resp.Diagnostics.AddError(
						"Feature Not Available",
						err.Error(),
					)
					return
				}
			}

			// Check runtime filter version requirement
			if !runtimeFilterSet.IsNull() && len(runtimeFilterSet.Elements()) > 0 {
				if _, err := util.CheckXrayVersion(client, MinVersionForCAAndRuntimeFilters, "Runtime filter is available from Xray version %s and higher. Current version: %s"); err != nil {
					resp.Diagnostics.AddError(
						"Feature Not Available",
						err.Error(),
					)
					return
				}
			}
		}
	}
}

func validateDateRange(attrs map[string]attr.Value, blockName string, resp *resource.ValidateConfigResponse) {
	if dateSet, ok := attrs[blockName].(types.Set); ok && !dateSet.IsNull() {
		dateElems := dateSet.Elements()
		if len(dateElems) > 0 {
			if dateObj, ok := dateElems[0].(types.Object); ok {
				dateAttrs := dateObj.Attributes()
				if start, ok := dateAttrs["start"].(types.String); ok {
					if end, ok := dateAttrs["end"].(types.String); ok {
						if !start.IsNull() && !end.IsNull() {
							startTime, _ := time.Parse(time.RFC3339, start.ValueString())
							endTime, _ := time.Parse(time.RFC3339, end.ValueString())
							if endTime.Before(startTime) {
								resp.Diagnostics.AddError(
									fmt.Sprintf("Invalid %s range", blockName),
									"End date must be after start date",
								)
							}
						}
					}
				}
			}
		}
	}
}

func validateDateRanges(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse, blocks ...string) {
	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
		filtersElems := config.Filters.Elements()
		if len(filtersElems) > 0 {
			if filtersObj, ok := filtersElems[0].(types.Object); ok {
				attrs := filtersObj.Attributes()
				for _, block := range blocks {
					validateDateRange(attrs, block, resp)
				}
			}
		}
	}
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

	// Set timezone in state based on what was sent to API
	if !plan.CronSchedule.IsNull() {
		if plan.CronScheduleTimezone.IsNull() {
			plan.CronScheduleTimezone = types.StringValue("UTC")
		}
	} else {
		plan.CronScheduleTimezone = types.StringNull()
	}

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

	// Add error about API limitations
	resp.Diagnostics.AddError(
		"Report Update Not Supported",
		"Direct updates to Xray Reports are not supported by the public API. The resource needs to be destroyed and recreated to apply changes.",
	)
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
		// If the report doesn't exist, consider the delete successful
		if response.StatusCode() == http.StatusNotFound || response.String() == `{"error":"failed to get report details"}` {
			return
		}
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}
