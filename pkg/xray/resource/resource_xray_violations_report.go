package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
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

		var watchNames []string
		d := attrs["watch_names"].(types.Set).ElementsAs(ctx, &watchNames, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var watchPatterns []string
		d = attrs["watch_patterns"].(types.Set).ElementsAs(ctx, &watchPatterns, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var policyNames []string
		d = attrs["policy_names"].(types.Set).ElementsAs(ctx, &policyNames, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var severities []string
		d = attrs["severities"].(types.Set).ElementsAs(ctx, &severities, false)
		if d.HasError() {
			diags.Append(d...)
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

		var securityFilters *SecurityFilterAPIModel
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

			securityFilters = &SecurityFilterAPIModel{
				Cve:             attrs["cve"].(types.String).ValueString(),
				IssueId:         attrs["issue_id"].(types.String).ValueString(),
				SummaryContains: attrs["summary_contains"].(types.String).ValueString(),
				HasRemediation:  attrs["has_remediation"].(types.Bool).ValueBool(),
				CVSSScore:       cvssScore,
			}
		}

		var licenseFilters *LicenseFilterAPIModel
		licenseFiltersElems := attrs["license_filters"].(types.Set).Elements()
		if len(licenseFiltersElems) > 0 {
			attrs := licenseFiltersElems[0].(types.Object).Attributes()

			var licenseNames []string
			d := attrs["license_names"].(types.Set).ElementsAs(ctx, &licenseNames, false)
			if d.HasError() {
				diags.Append(d...)
			}

			var licensePatterns []string
			d = attrs["license_patterns"].(types.Set).ElementsAs(ctx, &licensePatterns, false)
			if d.HasError() {
				diags.Append(d...)
			}

			licenseFilters = &LicenseFilterAPIModel{
				Unknown:         attrs["unknown"].(types.Bool).ValueBool(),
				Unrecognized:    attrs["unrecognized"].(types.Bool).ValueBool(),
				LicenseNames:    licenseNames,
				LicensePatterns: licensePatterns,
			}
		}

		filters = &FiltersAPIModel{
			Type:            attrs["type"].(types.String).ValueString(),
			Component:       attrs["component"].(types.String).ValueString(),
			Artifact:        attrs["artifact"].(types.String).ValueString(),
			WatchNames:      watchNames,
			WatchPatterns:   watchPatterns,
			PolicyNames:     policyNames,
			Severities:      severities,
			Updated:         updated,
			SecurityFilters: securityFilters,
			LicenseFilters:  licenseFilters,
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
			stringvalidator.OneOfCaseInsensitive("security", "license", "operational_risk"),
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
	"severities": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.SizeAtLeast(1),
			setvalidator.ValueStringsAre(
				stringvalidator.OneOf("None", "Low", "Medium", "High"),
			),
		},
		Description: "Risk/severity levels. Allowed values: 'None', 'Low', 'Medium', 'High'.",
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
					},
					Description: "CVE.",
				},
				"issue_id": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString(""), // backward compatibility with SDKv2 version
					Validators: []validator.String{
						stringvalidator.LengthAtLeast(1),
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
					Computed:    true,
					Default:     booldefault.StaticBool(false),
					Description: "Unknown displays the components that Xray could not discover any licenses for.",
				},
				"unrecognized": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(false),
					Description: "Unrecognized displays the components that Xray found licenses for, but these licenses are not Xray recognized licenses.",
				},
				"license_names": schema.SetAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Computed:    true,
					Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
					Validators: []validator.Set{
						setvalidator.SizeAtLeast(1),
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
	r.ReportResource.Update(ctx, "violations", r.toAPIModel, req, resp)
}

func (r *ViolationsReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
