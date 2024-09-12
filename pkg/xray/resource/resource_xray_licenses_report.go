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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkv2_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
	sdkv2_validator "github.com/jfrog/terraform-provider-shared/validator"
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
		d = attrs["license_patterns"].(types.Set).ElementsAs(ctx, &licensePatterns, false)
		if d.HasError() {
			diags.Append(d...)
		}

		filters = &FiltersAPIModel{
			Component:       attrs["component"].(types.String).ValueString(),
			Artifact:        attrs["artifact"].(types.String).ValueString(),
			Unknown:         attrs["unknown"].(types.Bool).ValueBool(),
			Unrecognized:    attrs["unrecognized"].(types.Bool).ValueBool(),
			LicenseNames:    licenseNames,
			LicensePatterns: licensePatterns,
			ScanDate:        scanDate,
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
		Description: "Artifact's component.",
	},
	"artifact": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.LengthAtLeast(1),
		},
		Description: "Artifact name.",
	},
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
	r.ReportResource.Update(ctx, "licenses", r.toAPIModel, req, resp)
}

func (r *LicensesReportResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.ReportResource.Delete(ctx, req, resp)
}

func ResourceXrayLicensesReport() *sdkv2_schema.Resource {
	var licensesFilterSchema = map[string]*sdkv2_schema.Schema{
		"component": {
			Type:             sdkv2_schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
			Description:      "Artifact's component.",
		},
		"artifact": {
			Type:             sdkv2_schema.TypeString,
			Optional:         true,
			ValidateDiagFunc: sdkv2_validator.StringIsNotEmpty,
			Description:      "Artifact name.",
		},
		"unknown": {
			Type:        sdkv2_schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Unknown displays the components that Xray could not discover any licenses for.",
		},
		"unrecognized": {
			Type:        sdkv2_schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Unrecognized displays the components that Xray found licenses for, but these licenses are not Xray recognized licenses.",
		},
		"license_names": {
			Type:        sdkv2_schema.TypeSet,
			Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
			Set:         sdkv2_schema.HashString,
			Optional:    true,
			Description: "Filter licenses by names. Only one of 'license_names' or 'license_patterns' can be set.",
		},
		"license_patterns": {
			Type:        sdkv2_schema.TypeSet,
			Elem:        &sdkv2_schema.Schema{Type: sdkv2_schema.TypeString},
			Set:         sdkv2_schema.HashString,
			Optional:    true,
			Description: "Filter licenses by patterns. Only one of 'license_names' or 'license_patterns' can be set.",
		},
		"scan_date": {
			Type:        sdkv2_schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: "",
			Elem: &sdkv2_schema.Resource{
				Schema: map[string]*sdkv2_schema.Schema{
					"start": {
						Type:             sdkv2_schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Scan start date.",
					},
					"end": {
						Type:             sdkv2_schema.TypeString,
						Optional:         true,
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsRFC3339Time),
						Description:      "Scan end date.",
					},
				},
			},
		},
	}

	return &sdkv2_schema.Resource{
		SchemaVersion: 1,
		CreateContext: resourceXrayLicensesReportCreate,
		ReadContext:   resourceXrayReportRead,
		UpdateContext: resourceXrayLicensesReportCreate,
		DeleteContext: resourceXrayReportDelete,
		Description: "Creates Xray License Due Diligence report. The License Due Diligence report provides you with a " +
			"list of components and artifacts and their relevant licenses. This enables you to review and verify that " +
			"the components and artifacts comply with the license requirements. This report provides due diligence " +
			"license related information on each component for a selected scope. Due diligence license information " +
			"includes information such as unknown licenses and unrecognized licenses found in your components.",

		CustomizeDiff: reportResourceDiff,

		Schema: getReportSchema(licensesFilterSchema),
	}
}
