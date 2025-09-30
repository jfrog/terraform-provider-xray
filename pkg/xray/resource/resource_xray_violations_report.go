package xray

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

var _ resource.Resource = &ViolationsReportResource{}

func NewViolationsReportResource() resource.Resource {
	return &ViolationsReportResource{
		ReportResource: ReportResource{
			TypeName: "xray_violations_report",
		},
	}
}

type ViolationsReportResource struct {
	ReportResource
}

func (r *ViolationsReportResource) toFiltersAPIModel(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var filters *FiltersAPIModel
	if len(filtersElems) > 0 {
		attrs := filtersElems[0].(types.Object).Attributes()

		// Check version for CA and Runtime filters during apply
		caFilterSet := attrs["ca_filter"].(types.Set)
		runtimeFilterSet := attrs["runtime_filter"].(types.Set)

		// Check CA filter version requirement
		if !caFilterSet.IsNull() && len(caFilterSet.Elements()) > 0 {
			if _, err := util.CheckXrayVersion(r.ProviderData.Client, MinVersionForCAAndRuntimeFilters, "Contextual analysis filter is available from Xray version %s and higher. Current version: %s"); err != nil {
				diags.AddError(
					"Feature Not Available",
					err.Error(),
				)
				return nil, diags
			}
		}

		// Check runtime filter version requirement
		if !runtimeFilterSet.IsNull() && len(runtimeFilterSet.Elements()) > 0 {
			if _, err := util.CheckXrayVersion(r.ProviderData.Client, MinVersionForCAAndRuntimeFilters, "Runtime filter is available from Xray version %s and higher. Current version: %s"); err != nil {
				diags.AddError(
					"Feature Not Available",
					err.Error(),
				)
				return nil, diags
			}
		}

		var watchNames []string
		d := attrs["watch_names"].(types.Set).ElementsAs(ctx, &watchNames, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var watchPatterns []string
		f := attrs["watch_patterns"].(types.Set).ElementsAs(ctx, &watchPatterns, false)
		if f.HasError() {
			diags.Append(f...)
		}

		var policyNames []string
		g := attrs["policy_names"].(types.Set).ElementsAs(ctx, &policyNames, false)
		if g.HasError() {
			diags.Append(g...)
		}

		var severities []string
		h := attrs["severities"].(types.Set).ElementsAs(ctx, &severities, false)
		if h.HasError() {
			diags.Append(h...)
		}

		var updated *StartAndEndDateAPIModel
		updatedElems := attrs["updated"].(types.Set).Elements()
		if len(updatedElems) > 0 {
			attrs := updatedElems[0].(types.Object).Attributes()
			updated = &StartAndEndDateAPIModel{
				Start: attrs["start"].(types.String).ValueString(),
				End:   attrs["end"].(types.String).ValueString(),
			}
		}

		var securityViolationFilters *SecurityViolationFilterAPIModel
		securityFiltersElems := attrs["security_filters"].(types.Set).Elements()
		if len(securityFiltersElems) > 0 {
			attrs := securityFiltersElems[0].(types.Object).Attributes()

			var cvssScore *CVSSScoreAPIModel
			cvssScoreElems := attrs["cvss_score"].(types.Set).Elements()
			if len(cvssScoreElems) > 0 {
				attrs := cvssScoreElems[0].(types.Object).Attributes()

				cvssScore = &CVSSScoreAPIModel{
					MinScore: attrs["min_score"].(types.Float64).ValueFloat64(),
					MaxScore: attrs["max_score"].(types.Float64).ValueFloat64(),
				}
			}

			var published *StartAndEndDateAPIModel
			publishedElems := attrs["published"].(types.Set).Elements()
			if len(publishedElems) > 0 {
				attrs := publishedElems[0].(types.Object).Attributes()
				published = &StartAndEndDateAPIModel{
					Start: attrs["start"].(types.String).ValueString(),
					End:   attrs["end"].(types.String).ValueString(),
				}
			}

			securityViolationFilters = &SecurityViolationFilterAPIModel{
				Cve:             attrs["cve"].(types.String).ValueString(),
				IssueId:         attrs["issue_id"].(types.String).ValueString(),
				SummaryContains: attrs["summary_contains"].(types.String).ValueString(),
				Published:       published,
				CVSSScore:       cvssScore,
			}

			// Only set has_remediation if it's explicitly set in config
			if v := attrs["has_remediation"].(types.Bool); !v.IsNull() {
				val := v.ValueBool()
				securityViolationFilters.HasRemediation = &val
			}
		}

		var runtimeFilter *RuntimeFilterAPIModel
		runtimeFilterElems := attrs["runtime_filter"].(types.Set).Elements()
		if len(runtimeFilterElems) > 0 {
			runtimeFilterAttrs := runtimeFilterElems[0].(types.Object).Attributes()
			runtimeFilter = &RuntimeFilterAPIModel{
				TimePeriod: runtimeFilterAttrs["time_period"].(types.String).ValueString(),
			}
		}

		var caFilter *CAFilterAPIModel
		caFilterElems := attrs["ca_filter"].(types.Set).Elements()
		if len(caFilterElems) > 0 {
			caFilterAttrs := caFilterElems[0].(types.Object).Attributes()
			var allowedCAStatuses []string
			d := caFilterAttrs["allowed_ca_statuses"].(types.Set).ElementsAs(ctx, &allowedCAStatuses, false)
			if d.HasError() {
				diags.Append(d...)
			}
			caFilter = &CAFilterAPIModel{
				AllowedCAStatuses: allowedCAStatuses,
			}
		}

		var licenseViolationFilters *LicenseViolationFilterAPIModel
		licenseFiltersElems := attrs["license_filters"].(types.Set).Elements()
		if len(licenseFiltersElems) > 0 {
			attrs := licenseFiltersElems[0].(types.Object).Attributes()

			var licenseNames []string
			d := attrs["license_names"].(types.Set).ElementsAs(ctx, &licenseNames, false)
			if d.HasError() {
				diags.Append(d...)
			}

			var licensePatterns []string
			f := attrs["license_patterns"].(types.Set).ElementsAs(ctx, &licensePatterns, false)
			if f.HasError() {
				diags.Append(d...)
			}

			licenseViolationFilters = &LicenseViolationFilterAPIModel{
				LicenseNames:    licenseNames,
				LicensePatterns: licensePatterns,
			}

			// Only set unknown if it's explicitly set in config
			if v := attrs["unknown"].(types.Bool); !v.IsNull() {
				val := v.ValueBool()
				licenseViolationFilters.Unknown = &val
			}
		}

		filters = &FiltersAPIModel{
			Type:                     attrs["type"].(types.String).ValueString(),
			ViolationStatus:          attrs["violation_status"].(types.String).ValueString(),
			Component:                attrs["component"].(types.String).ValueString(),
			Artifact:                 attrs["artifact"].(types.String).ValueString(),
			WatchNames:               watchNames,
			WatchPatterns:            watchPatterns,
			PolicyNames:              policyNames,
			Severities:               severities,
			Updated:                  updated,
			SecurityViolationFilters: securityViolationFilters,
			LicenseViolationFilters:  licenseViolationFilters,
			RuntimeFilter:            runtimeFilter,
			CAFilter:                 caFilter,
		}
	}

	return filters, diags
}

func (r ViolationsReportResource) toAPIModel(ctx context.Context, plan ReportResourceModel, report *ReportAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, report, r.toFiltersAPIModel)
}

func (r *ViolationsReportResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var violationsFiltersAttrs = map[string]schema.Attribute{
	"type": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
			stringvalidator.OneOf("security", "license", "malicious", "operational_risk"),
		},
		Description: "Violation type.",
	},
	"watch_names": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("watch_patterns"),
			),
		},
		Description: "Select Xray watch by names. Only one attribute - 'watch_names' or 'watch_patterns' can be set.",
	},
	"watch_patterns": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("watch_names"),
			),
		},
		Description: "Select Xray watch name by patterns. Only one attribute - 'watch_names' or 'watch_patterns' can be set..",
	},
	"policy_names": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
		},
		Description: "Select Xray policies by name.",
	},
	"component": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Filter by component name, you can use (*) at the beginning or end of a substring as a wildcard.",
	},
	"artifact": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Filter by artifact name, you can use (*) at the beginning or end of a substring as a wildcard.",
	},
	"severities": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
			setvalidator.ValueStringsAre(
				stringvalidator.OneOf("Low", "Medium", "High", "Critical"),
			),
		},
		Description: "Risk/Severites levels. Allowed values: 'Low', 'Medium', 'High', 'Critical'.",
	},
	"violation_status": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
			stringvalidator.OneOf("All", "Active", "Ignored"),
		},
		Description: "Violation status.",
	},
}

var violationsFiltersBlocks = map[string]schema.Block{
	"updated": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"start": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Created from date.",
				},
				"end": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Created to date.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
	},
	"security_filters": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"cve": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString(""), // backward compatibility with SDKv2 version
					Validators: []validator.String{
						stringvalidator.LengthAtLeast(1),
						stringvalidator.RegexMatches(regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`), "invalid Vulnerability, must be a valid CVE, example CVE-2021-12345"),
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName("issue_id"),
						),
					},
					Description: "CVE.",
				},
				"issue_id": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString(""), // backward compatibility with SDKv2 version
					Validators: []validator.String{
						stringvalidator.LengthAtLeast(1),
						stringvalidator.RegexMatches(regexp.MustCompile(`^XRAY-\d{4,6}$`), "invalid Issue ID, must be a valid Issue ID, example XRAY-123456"),
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName("cve"),
						),
					},
					Description: "Issue ID.",
				},
				"summary_contains": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						stringvalidator.LengthAtLeast(1),
					},
					Description: "Vulnerability Summary.",
				},
				"has_remediation": schema.BoolAttribute{
					Optional:    true,
					Description: "Whether the issue has a fix or not.",
				},
			},
			Blocks: map[string]schema.Block{
				"published": schema.SetNestedBlock{
					NestedObject: schema.NestedBlockObject{
						Attributes: map[string]schema.Attribute{
							"start": schema.StringAttribute{
								Optional: true,
								Validators: []validator.String{
									IsRFC3339Time(),
								},
								Description: "Published from date.",
							},
							"end": schema.StringAttribute{
								Optional: true,
								Validators: []validator.String{
									IsRFC3339Time(),
								},
								Description: "Published to date.",
							},
						},
					},
					Validators: []validator.Set{
						setvalidator.SizeAtMost(1),
					},
				},
				"cvss_score": schema.SetNestedBlock{
					NestedObject: schema.NestedBlockObject{
						Attributes: map[string]schema.Attribute{
							"min_score": schema.Float64Attribute{
								Optional: true,
								Validators: []validator.Float64{
									float64validator.Between(0, 10),
								},
								Description: "Minimum CVSS score.",
							},
							"max_score": schema.Float64Attribute{
								Optional: true,
								Validators: []validator.Float64{
									float64validator.Between(0, 10),
								},
								Description: "Maximum CVSS score.",
							},
						},
					},
					Validators: []validator.Set{
						setvalidator.SizeAtMost(1),
					},
					Description: "CVSS score.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
		Description: "Security Filters.",
	},
	"license_filters": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"unknown": schema.BoolAttribute{
					Optional:    true,
					Description: "Unknown displays the components that Xray could not discover any licenses for.",
				},
				"license_names": schema.SetAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Computed:    true,
					Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
					Validators: []validator.Set{
						setvalidator.SizeAtLeast(1),
						setvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName("license_patterns"),
						),
					},
					Description: "Filter licenses by names.",
				},
				"license_patterns": schema.SetAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Computed:    true,
					Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
					Validators: []validator.Set{
						setvalidator.SizeAtLeast(1),
						setvalidator.ConflictsWith(
							path.MatchRelative().AtParent().AtName("license_names"),
						),
					},
					Description: "Filter licenses by patterns.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
		Description: "Licenses Filters.",
	},
	"ca_filter": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"allowed_ca_statuses": schema.SetAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Validators: []validator.Set{
						setvalidator.ValueStringsAre(
							stringvalidator.OneOf(
								"applicable",
								"not_applicable",
								"undetermined",
								"not_scanned",
								"not_covered",
								"rescan_required",
								"upgrade_required",
								"technology_unsupported",
							),
						),
						setvalidator.SizeAtLeast(1),
					},
					Description: "Allowed CA statuses.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
		Description: "Contextual Analysis Filter. Note: Requires Xray " + MinVersionForCAAndRuntimeFilters + " or higher.",
	},
	"runtime_filter": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"time_period": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						stringvalidator.OneOf("now", "1 hour", "24 hours", "3 days", "7 days", "10 days", "30 days"),
					},
					Description: "Time period to filter by.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
		Description: "Runtime Filter. Note: Requires Xray " + MinVersionForCAAndRuntimeFilters + " or higher.",
	},
}

func (r *ViolationsReportResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: reportsSchemaAttrs,
		Blocks:     reportsBlocks(violationsFiltersAttrs, violationsFiltersBlocks),
		Description: "Creates Xray Violations report. The Violations report provides you with information on security " +
			"and license violations for each component in the selected scope. Violations information includes " +
			"information such as type of violation, impacted artifacts, and severity.",
	}
}

func validateSecurityViolationFilterCveAndIssueId(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config ReportResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.Filters.IsNull() && !config.Filters.IsUnknown() {
		filtersElems := config.Filters.Elements()
		if len(filtersElems) > 0 {
			attrs := filtersElems[0].(types.Object).Attributes()
			securityFilters := attrs["security_filters"].(types.Set)
			if !securityFilters.IsNull() && len(securityFilters.Elements()) > 0 {
				securityFilterAttrs := securityFilters.Elements()[0].(types.Object).Attributes()
				cve := securityFilterAttrs["cve"].(types.String)
				issueId := securityFilterAttrs["issue_id"].(types.String)
				if !cve.IsNull() && !issueId.IsNull() {
					resp.Diagnostics.AddError(
						"Invalid Attribute Combination",
						"Only one of 'cve' or 'issue_id' can be specified in security_filters block",
					)
				}
			}
		}
	}
}

func (r *ViolationsReportResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	validateSingleResourceType(ctx, req, resp)
	validateDateRanges(ctx, req, resp, "updated", "published")
	validateSecurityViolationFilterCveAndIssueId(ctx, req, resp)
	validateCaAndRuntimeFilters(ctx, req, resp, r.ProviderData.Client)
	validateCronAndNotify(ctx, req, resp, r.ProviderData.Client)
	validateProjectsScope(ctx, req, resp, r.ProviderData.Client)
}

func (r *ViolationsReportResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *ViolationsReportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.ReportResource.Create(ctx, "violations", r.toAPIModel, req, resp)
}

func (r *ViolationsReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.ReportResource.Read(ctx, req, resp)
}

func (r *ViolationsReportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Add error about API limitations
	resp.Diagnostics.AddError(
		"Violations Report Update Not Supported",
		"Direct updates to Violations Report are not supported by the public API. The resource needs to be destroyed and recreated to apply changes.",
	)
}

func (r *ViolationsReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
