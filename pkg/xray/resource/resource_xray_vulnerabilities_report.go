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

var _ resource.Resource = &VulnerabilitiesReportResource{}

func NewVulnerabilitiesReportResource() resource.Resource {
	return &VulnerabilitiesReportResource{
		ReportResource: ReportResource{
			TypeName: "xray_vulnerabilities_report",
		},
	}
}

type VulnerabilitiesReportResource struct {
	ReportResource
}

func (r *VulnerabilitiesReportResource) toFiltersAPIModel(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var filters *FiltersAPIModel
	if len(filtersElems) > 0 {
		attrs := filtersElems[0].(types.Object).Attributes()

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

		var scanDate *StartAndEndDateAPIModel
		scanDateElems := attrs["scan_date"].(types.Set).Elements()
		if len(scanDateElems) > 0 {
			attrs := scanDateElems[0].(types.Object).Attributes()
			scanDate = &StartAndEndDateAPIModel{
				Start: attrs["start"].(types.String).ValueString(),
				End:   attrs["end"].(types.String).ValueString(),
			}
		}

		var severities []string
		d := attrs["severities"].(types.Set).ElementsAs(ctx, &severities, false)
		if d.HasError() {
			diags.Append(d...)
		}

		// Create filters without has_remediation first
		filters = &FiltersAPIModel{
			VulnerableComponent: attrs["vulnerable_component"].(types.String).ValueString(),
			ImpactedArtifact:    attrs["impacted_artifact"].(types.String).ValueString(),
			CVE:                 attrs["cve"].(types.String).ValueString(),
			IssueId:             attrs["issue_id"].(types.String).ValueString(),
			Published:           published,
			ScanDate:            scanDate,
			Severities:          severities,
			CVSSScore:           cvssScore,
		}

		// Only set has_remediation if it's explicitly set in config
		if v := attrs["has_remediation"].(types.Bool); !v.IsNull() {
			val := v.ValueBool()
			filters.HasRemediation = &val
		}
	}

	return filters, diags
}

func (r VulnerabilitiesReportResource) toAPIModel(ctx context.Context, plan ReportResourceModel, report *ReportAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, report, r.toFiltersAPIModel)
}

func (r *VulnerabilitiesReportResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var vulnerabilitiesFiltersAttrs = map[string]schema.Attribute{
	"vulnerable_component": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Filter by component name, you can use (*) at the beginning or end of a substring as a wildcard.",
	},
	"impacted_artifact": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Filter by artifact name, you can use (*) at the beginning or end of a substring as a wildcard.",
	},
	"has_remediation": schema.BoolAttribute{
		Optional:    true,
		Description: "Whether the issue has a fix or not.",
	},
	"cve": schema.StringAttribute{
		Optional: true,
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
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cve"),
			),
		},
		Description: "Issue ID.",
	},
	"severities": schema.SetAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Computed:    true,
		Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), // backward compatibility with SDKv2 version
		Validators: []validator.Set{
			setvalidator.ValueStringsAre(
				stringvalidator.OneOf("Low", "Medium", "High", "Critical"),
			),
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_score"),
			),
		},
		Description: "Severity levels. Allowed values: 'Low', 'Medium', 'High', 'Critical'",
	},
}

var vulnerabilitiesFiltersBlocks = map[string]schema.Block{
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
			setvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("severities"),
			),
		},
		Description: "CVSS score.",
	},
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
	"scan_date": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"start": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scanned from date.",
				},
				"end": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scanned to date.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
	},
}

func (r *VulnerabilitiesReportResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: reportsSchemaAttrs,
		Blocks:     reportsBlocks(vulnerabilitiesFiltersAttrs, vulnerabilitiesFiltersBlocks),
		Description: "Creates Xray Vulnerabilities report. The Vulnerabilities report provides information about " +
			"vulnerabilities in your artifacts, builds, and release bundles. In addition to the information provided in " +
			"the JFrog Platform on each of these entities, the report gives you a wider range of information such as " +
			"vulnerabilities in multiple repositories, builds and release bundles. Criteria such as vulnerable component," +
			" CVE, cvss score, and severity are available in the report.",
	}
}

func (r *VulnerabilitiesReportResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	validateSingleResourceType(ctx, req, resp)
	validateDateRanges(ctx, req, resp, "scan_date", "published")
	validateSecurityFilterSeveritiesAndCvssScore(ctx, req, resp)
	validateSecurityFilterCveAndIssueId(ctx, req, resp)
	validateProjectsScope(ctx, req, resp, r.ProviderData.Client)
}

func (r *VulnerabilitiesReportResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *VulnerabilitiesReportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.ReportResource.Create(ctx, "vulnerabilities", r.toAPIModel, req, resp)
}

func (r *VulnerabilitiesReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.ReportResource.Read(ctx, req, resp)
}

func (r *VulnerabilitiesReportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Add error about API limitations
	resp.Diagnostics.AddError(
		"Vulnerabilities Report Update Not Supported",
		"Direct updates to Vulnerabilities Report are not supported by the public API. The resource needs to be destroyed and recreated to apply changes.",
	)
}

func (r *VulnerabilitiesReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
