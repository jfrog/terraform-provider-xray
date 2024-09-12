package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

var _ resource.Resource = &OperationalRisksReportResource{}

func NewOperationalRisksReportResource() resource.Resource {
	return &OperationalRisksReportResource{
		ReportResource: ReportResource{
			TypeName: "xray_operational_risks_report",
		},
	}
}

type OperationalRisksReportResource struct {
	ReportResource
}

func (r *OperationalRisksReportResource) toFiltersAPIModel(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var filters *FiltersAPIModel
	if len(filtersElems) > 0 {
		attrs := filtersElems[0].(types.Object).Attributes()

		var risks []string
		d := attrs["risks"].(types.Set).ElementsAs(ctx, &risks, false)
		if d.HasError() {
			diags.Append(d...)
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

		filters = &FiltersAPIModel{
			Component: attrs["component"].(types.String).ValueString(),
			Artifact:  attrs["artifact"].(types.String).ValueString(),
			Risks:     risks,
			ScanDate:  scanDate,
		}
	}

	return filters, diags
}

func (r OperationalRisksReportResource) toAPIModel(ctx context.Context, plan ReportResourceModel, report *ReportAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, report, r.toFiltersAPIModel)
}

func (r *OperationalRisksReportResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var opRisksFiltersAttrs = map[string]schema.Attribute{
	"component": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Artifact's component.",
	},
	"artifact": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Artifact name.",
	},
	"risks": schema.SetAttribute{
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
		Description: "Operational risk level. Allowed values: 'None', 'Low', 'Medium', 'High'.",
	},
}

var opRisksFiltersBlocks = map[string]schema.Block{
	"scan_date": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"start": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scan start date.",
				},
				"end": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scan end date.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
	},
}

func (r *OperationalRisksReportResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: reportsSchemaAttrs,
		Blocks:     reportsBlocks(opRisksFiltersAttrs, opRisksFiltersBlocks),
		Description: "Creates Xray Operational Risks report. The Operational Risk report provides you with additional " +
			"data on OSS components that will help you gain insights into the risk level of the components in use, " +
			"such as; EOL, Version Age, Number of New Versions, and so on.  For more information, see " +
			"[Components Operational Risk](https://www.jfrog.com/confluence/display/JFROG/Components+Operational+Risk)",
	}
}

func (r *OperationalRisksReportResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *OperationalRisksReportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.ReportResource.Create(ctx, "violations", r.toAPIModel, req, resp)
}

func (r *OperationalRisksReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.ReportResource.Read(ctx, req, resp)
}

func (r *OperationalRisksReportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.ReportResource.Update(ctx, "violations", r.toAPIModel, req, resp)
}

func (r *OperationalRisksReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
