package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

var _ resource.Resource = &LicensesReportResource{}

func NewLicensesReportResource() resource.Resource {
	return &LicensesReportResource{
		ReportResource: ReportResource{
			TypeName: "xray_licenses_report",
		},
	}
}

type LicensesReportResource struct {
	ReportResource
}

func (r *LicensesReportResource) toFiltersAPIModel(ctx context.Context, filtersElems []attr.Value) (*FiltersAPIModel, diag.Diagnostics) {
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

		var licenseNames []string
		d := attrs["license_names"].(types.Set).ElementsAs(ctx, &licenseNames, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var licensePatterns []string
		f := attrs["license_patterns"].(types.Set).ElementsAs(ctx, &licensePatterns, false)
		if f.HasError() {
			diags.Append(f...)
		}

		filters = &FiltersAPIModel{
			Component:       attrs["component"].(types.String).ValueString(),
			Artifact:        attrs["artifact"].(types.String).ValueString(),
			LicenseNames:    licenseNames,
			LicensePatterns: licensePatterns,
			ScanDate:        scanDate,
		}

		// Only set unknown if it's explicitly set in config
		if v := attrs["unknown"].(types.Bool); !v.IsNull() {
			val := v.ValueBool()
			filters.Unknown = &val
		}

		// Only set unrecognized if it's explicitly set in config
		if v := attrs["unrecognized"].(types.Bool); !v.IsNull() {
			val := v.ValueBool()
			filters.Unrecognized = &val
		}
	}

	return filters, diags
}

func (r LicensesReportResource) toAPIModel(ctx context.Context, plan ReportResourceModel, report *ReportAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, report, r.toFiltersAPIModel)
}

func (r *LicensesReportResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

var licensesFiltersAttrs = map[string]schema.Attribute{
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
		Description: "Filter by artifact name, you can use (*) at thebeginning or end of a substring as a wildcard.",
	},
	"unknown": schema.BoolAttribute{
		Optional:    true,
		Description: "Unknown displays the components that Xray could not discover any licenses for.",
	},
	"unrecognized": schema.BoolAttribute{
		Optional:    true,
		Description: "Unrecognized displays the components that Xray found licenses for, but these licenses are not Xray recognized licenses.",
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
		Description: "Filter licenses by names. Only one of 'license_names' or 'license_patterns' can be set.",
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
		Description: "Filter licenses by patterns. Only one of 'license_names' or 'license_patterns' can be set.",
	},
}

var licensesFiltersBlocks = map[string]schema.Block{
	"scan_date": schema.SetNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"start": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scanned start date.",
				},
				"end": schema.StringAttribute{
					Optional: true,
					Validators: []validator.String{
						IsRFC3339Time(),
					},
					Description: "Scanned end date.",
				},
			},
		},
		Validators: []validator.Set{
			setvalidator.SizeAtMost(1),
		},
	},
}

func (r *LicensesReportResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	validateSingleResourceType(ctx, req, resp)
	validateDateRanges(ctx, req, resp, "scan_date")
	validateProjectsScope(ctx, req, resp, r.ProviderData.Client)
}

func (r *LicensesReportResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: reportsSchemaAttrs,
		Blocks:     reportsBlocks(licensesFiltersAttrs, licensesFiltersBlocks),
		Description: "Creates Xray License Due Diligence report. The License Due Diligence report provides you with a " +
			"list of components and artifacts and their relevant licenses. This enables you to review and verify that " +
			"the components and artifacts comply with the license requirements. This report provides due diligence " +
			"license related information on each component for a selected scope. Due diligence license information " +
			"includes information such as unknown licenses and unrecognized licenses found in your components.",
	}
}

func (r *LicensesReportResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *LicensesReportResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.ReportResource.Create(ctx, "licenses", r.toAPIModel, req, resp)
}

func (r *LicensesReportResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.ReportResource.Read(ctx, req, resp)
}

func (r *LicensesReportResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Add error about API limitations
	resp.Diagnostics.AddError(
		"Licenses Report Update Not Supported",
		"Direct updates to Licenses Risks Report are not supported by the public API. The resource needs to be destroyed and recreated to apply changes.",
	)
}

func (r *LicensesReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}
