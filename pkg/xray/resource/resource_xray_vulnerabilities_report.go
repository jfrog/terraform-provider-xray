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

		var severities []string
		d := attrs["severities"].(types.Set).ElementsAs(ctx, &severities, false)
		if d.HasError() {
			diags.Append(d...)
		}

		filters = &FiltersAPIModel{
			VulnerableComponent: attrs["vulnerable_component"].(types.String).ValueString(),
			ImpactedArtifact:    attrs["impacted_artifact"].(types.String).ValueString(),
			HasRemediation:      attrs["has_remediation"].(types.Bool).ValueBool(),
			CVE:                 attrs["cve"].(types.String).ValueString(),
			IssueId:             attrs["issue_id"].(types.String).ValueString(),
			Severities:          severities,
			CVSSScore:           cvssScore,
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
		Description: "Filter by artifact name, you can use (*) at the eginning or end of a substring as a wildcard.",
	},
	"has_remediation": schema.BoolAttribute{
		Optional:    true,
		Computed:    true,
		Default:     booldefault.StaticBool(false),
		Description: "Whether the issue has a fix or not.",
	},
	"cve": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
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
	r.ReportResource.Update(ctx, "vulnerabilities", r.toAPIModel, req, resp)
}

func (r *VulnerabilitiesReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}

//
// func ResourceXrayVulnerabilitiesReport() *sdkv2_schema.Resource {
// 	var vulnerabilitiesFilterSchema = map[string]*sdkv2_schema.Schema{
// 		"vulnerable_component": {
// 			Type:             sdkv2_schema.TypeString,
// 			Optional:         true,
// 			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
// 			Description:      "Filter by component name, you can use (*) at the beginning or end of a substring as a wildcard.",
// 		},
// 		"impacted_artifact": {
// 			Type:             sdkv2_schema.TypeString,
// 			Optional:         true,
// 			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
// 			Description:      "Filter by artifact name, you can use (*) at the eginning or end of a substring as a wildcard.",
// 		},
// 		"has_remediation": {
// 			Type:        sdkv2_schema.TypeBool,
// 			Optional:    true,
// 			Default:     false,
// 			Description: "Whether the issue has a fix or not.", // UI has an option 'All', when the field is empty. Not clear how to make it work with bool.
// 		},
// 		"cve": {
// 			Type:             sdkv2_schema.TypeString,
// 			Optional:         true,
// 			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
// 			Description:      "CVE.",
// 		},
// 		"issue_id": {
// 			Type:             sdkv2_schema.TypeString,
// 			Optional:         true,
// 			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
// 			Description:      "Issue ID.",
// 		},
// 		"severities": {
// 			Type:        sdkv2_schema.TypeSet,
// 			Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
// 			Set:         sdkv2_schema.HashString,
// 			Optional:    true,
// 			Description: "Severity levels. Allowed values: 'Low', 'Medium', 'High', 'Critical'",
// 		},
// 		"cvss_score": {
// 			Type:        sdkv2_schema.TypeSet,
// 			Optional:    true,
// 			MaxItems:    1,
// 			Description: "CVSS score.",
// 			Elem: &sdkv2_schema.Resource{
// 				Schema: map[string]*sdkv2_schema.Schema{
// 					"min_score": {
// 						Type:         sdkv2_schema.TypeFloat,
// 						Optional:     true,
// 						ValidateFunc: validation.FloatBetween(0, 10),
// 						Description:  "Minimum CVSS score.",
// 					},
// 					"max_score": {
// 						Type:         sdkv2_schema.TypeFloat,
// 						Optional:     true,
// 						ValidateFunc: validation.FloatBetween(0, 10),
// 						Description:  "Maximum CVSS score.",
// 					},
// 				},
// 			},
// 		},
// 		"published": {
// 			Type:        sdkv2_schema.TypeSet,
// 			Optional:    true,
// 			MaxItems:    1,
// 			Description: "",
// 			Elem: &sdkv2_schema.Resource{
// 				Schema: map[string]*sdkv2_schema.Schema{
// 					"start": {
// 						Type:             sdkv2_schema.TypeString,
// 						Optional:         true,
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
// 						Description:      "Published from date.",
// 					},
// 					"end": {
// 						Type:             sdkv2_schema.TypeString,
// 						Optional:         true,
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
// 						Description:      "Published to date.",
// 					},
// 				},
// 			},
// 		},
// 		"scan_date": {
// 			Type:        sdkv2_schema.TypeSet,
// 			Optional:    true,
// 			MaxItems:    1,
// 			Description: "",
// 			Elem: &sdkv2_schema.Resource{
// 				Schema: map[string]*sdkv2_schema.Schema{
// 					"start": {
// 						Type:             sdkv2_schema.TypeString,
// 						Optional:         true,
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
// 						Description:      "Scanned from date.",
// 					},
// 					"end": {
// 						Type:             sdkv2_schema.TypeString,
// 						Optional:         true,
// 						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
// 						Description:      "Scanned to date.",
// 					},
// 				},
// 			},
// 		},
// 	}
//
// 	return &sdkv2_schema.Resource{
// 		SchemaVersion: 1,
// 		CreateContext: resourceXrayVulnerabilitiesReportCreate,
// 		ReadContext:   resourceXrayReportRead,
// 		UpdateContext: resourceXrayVulnerabilitiesReportCreate,
// 		DeleteContext: resourceXrayReportDelete,
// 		Description: "Creates Xray Vulnerabilities report. The Vulnerabilities report provides information about " +
// 			"vulnerabilities in your artifacts, builds, and release bundles. In addition to the information provided in " +
// 			"the JFrog Platform on each of these entities, the report gives you a wider range of information such as " +
// 			"vulnerabilities in multiple repositories, builds and release bundles. Criteria such as vulnerable component," +
// 			" CVE, cvss score, and severity are available in the report.",
//
// 		CustomizeDiff: reportResourceDiff,
//
// 		Schema: getReportSchema(vulnerabilitiesFilterSchema),
// 	}
// }
