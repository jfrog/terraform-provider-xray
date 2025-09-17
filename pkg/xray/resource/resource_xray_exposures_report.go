package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

var _ resource.Resource = &ExposuresReportResource{}

func NewExposuresReportResource() resource.Resource {
	return &ExposuresReportResource{
		ReportResource: ReportResource{
			TypeName: "xray_exposures_report",
		},
	}
}

type ExposuresReportResource struct {
	ReportResource
}

func (r *ExposuresReportResource) toFiltersAPIModel(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var filters *FiltersAPIModel
	if len(filtersElems) > 0 {
		attrs := filtersElems[0].(types.Object).Attributes()

		var scanDate *StartAndEndDateAPIModel
		scanDateElems := attrs["scan_date"].(types.Set).Elements()
		if len(scanDateElems) > 0 {
			attrs := scanDateElems[0].(types.Object).Attributes()

			scanDate = &StartAndEndDateAPIModel{
				Start: attrs["start"].(types.String).ValueString(),
				End:   attrs["end"].(types.String).ValueString(),
			}
		}

		filters = &FiltersAPIModel{
			Category:         attrs["category"].(types.String).ValueString(),
			ImpactedArtifact: attrs["impacted_artifact"].(types.String).ValueString(),
			ScanDate:         scanDate,
		}
	}
	return filters, diags
}

func (r ExposuresReportResource) toAPIModel(ctx context.Context, plan ReportResourceModel, report *ReportAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, report, r.toFiltersAPIModel)
}

func (r *ExposuresReportResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var exposuresFiltersAttrs = map[string]schema.Attribute{
	"category": schema.StringAttribute{
		Required: true,
		Validators: []validator.String{
			stringvalidator.OneOf("secrets", "services", "applications", "iac"),
		},
		Description: "The exposure category. Must be one of: 'secrets', 'services', 'applications', 'iac'.",
	},
	"impacted_artifact": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Filter by impacted artifact name.",
	},
}

var exposuresFiltersBlocks = map[string]schema.Block{
	"scan_date": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"start": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scan from date.",
				},
				"end": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scan to date.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
		Description: "Scan date range.",
	},
}

func (r *ExposuresReportResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: reportsSchemaAttrs,
		Blocks:     reportsBlocks(exposuresFiltersAttrs, exposuresFiltersBlocks),
		Description: "Creates Xray Exposures report. The Exposures report provides you with information about " +
			"potential security exposures in your artifacts, such as secrets, services, applications, and IaC configurations.",
	}
}

func (r *ExposuresReportResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	validateSingleResourceType(ctx, req, resp)
	validateDateRanges(ctx, req, resp, "scan_date")
	validateProjectsScope(ctx, req, resp, r.ProviderData.Client)
}

func (r *ExposuresReportResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *ExposuresReportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.ReportResource.Create(ctx, "exposures", r.toAPIModel, req, resp)
}

func (r *ExposuresReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.ReportResource.Read(ctx, req, resp)
}

func (r *ExposuresReportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Add error about API limitations
	resp.Diagnostics.AddError(
		"Exposures Report Update Not Supported",
		"Direct updates to Exposures Report are not supported by the public API. The resource needs to be destroyed and recreated to apply changes.",
	)
}

func (r *ExposuresReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
