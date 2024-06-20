package xray

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
)

const (
	CustomIssuesEndpoint  = "xray/api/v1/events"
	CustomIssueEndpoint   = "xray/api/v1/events/{id}"
	CustomIssueEndpointV2 = "xray/api/v2/events/{id}"
)

var validPackageTypes = []string{
	"alpine",
	"bower",
	"cargo",
	"composer",
	"conan",
	"conda",
	"cran",
	"debian",
	"docker",
	"generic",
	"go",
	"gradle",
	"huggingface",
	"ivy",
	"maven",
	"npm",
	"nuget",
	"oci",
	"pypi",
	"rpm",
	"rubygems",
	"sbt",
	"terraformbe",
}

var _ resource.Resource = &CustomIssueResource{}

func NewCustomIssueResource() resource.Resource {
	return &CustomIssueResource{}
}

type CustomIssueResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *CustomIssueResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_issue"
	r.TypeName = resp.TypeName
}

type CustomIssueResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	Summary      types.String `tfsdk:"summary"`
	Type         types.String `tfsdk:"type"`
	ProviderName types.String `tfsdk:"provider_name"`
	PackageType  types.String `tfsdk:"package_type"`
	Severity     types.String `tfsdk:"severity"`
	Component    types.Set    `tfsdk:"component"`
	CVE          types.Set    `tfsdk:"cve"`
	Source       types.Set    `tfsdk:"source"`
}

func (m CustomIssueResourceModel) toAPIModel(ctx context.Context, apiModel *CustomIssueAPIModel) (ds diag.Diagnostics) {
	components := lo.Map(
		m.Component.Elements(),
		func(elem attr.Value, _ int) ComponentAPIModel {
			attrs := elem.(types.Object).Attributes()

			var vulnerableVersions []string
			ds.Append(attrs["vulnerable_versions"].(types.Set).ElementsAs(ctx, &vulnerableVersions, false)...)

			var fixedVersions []string
			ds.Append(attrs["fixed_versions"].(types.Set).ElementsAs(ctx, &fixedVersions, false)...)

			vulnerableRanges := lo.Map(
				attrs["vulnerable_ranges"].(types.Set).Elements(),
				func(elem attr.Value, _ int) VulnerableRangeAPIModel {
					attrs := elem.(types.Object).Attributes()

					var vulnerableVersions []string
					if v, ok := attrs["vulnerable_versions"]; ok {
						ds.Append(v.(types.Set).ElementsAs(ctx, &vulnerableVersions, false)...)
					}

					var fixedVersions []string
					if v, ok := attrs["fixed_versions"]; ok {
						ds.Append(v.(types.Set).ElementsAs(ctx, &fixedVersions, false)...)
					}

					return VulnerableRangeAPIModel{
						VulnerableVersions: vulnerableVersions,
						FixedVersions:      fixedVersions,
					}
				},
			)

			return ComponentAPIModel{
				ID:                 attrs["id"].(types.String).ValueString(),
				VulnerableVersions: vulnerableVersions,
				FixedVersions:      fixedVersions,
				VulnerableRanges:   vulnerableRanges,
			}
		},
	)

	cves := lo.Map(
		m.CVE.Elements(),
		func(elem attr.Value, _ int) CVEAPIModel {
			attrs := elem.(types.Object).Attributes()

			cve := CVEAPIModel{}

			if v, ok := attrs["cve"]; ok {
				cve.CVE = v.(types.String).ValueString()
			}

			if v, ok := attrs["cvss_v2"]; ok {
				cve.CVSSv2 = v.(types.String).ValueString()
			}

			if v, ok := attrs["cvss_v3"]; ok {
				cve.CVSSv3 = v.(types.String).ValueString()
			}

			return cve
		},
	)

	sources := lo.Map(
		m.Source.Elements(),
		func(elem attr.Value, _ int) SourceAPIModel {
			attrs := elem.(types.Object).Attributes()

			source := SourceAPIModel{}

			if v, ok := attrs["id"]; ok {
				source.ID = v.(types.String).ValueString()
			}

			if v, ok := attrs["name"]; ok {
				source.Name = v.(types.String).ValueString()
			}

			if v, ok := attrs["url"]; ok {
				source.URL = v.(types.String).ValueString()
			}

			return source
		},
	)

	*apiModel = CustomIssueAPIModel{
		ID:          m.Name.ValueString(),
		Summary:     m.Summary.ValueString(),
		Description: m.Description.ValueString(),
		PackageType: m.PackageType.ValueString(),
		Type:        m.Type.ValueString(),
		Provider:    m.ProviderName.ValueString(),
		Severity:    m.Severity.ValueString(),
		Components:  components,
		CVEs:        cves,
		Sources:     sources,
	}

	return
}

var vulnerableRangesResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"vulnerable_versions": types.SetType{ElemType: types.StringType},
	"fixed_versions":      types.SetType{ElemType: types.StringType},
}

var vulnerableRangesSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: vulnerableRangesResourceModelAttributeTypes,
}

var componentResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"id":                  types.StringType,
	"vulnerable_versions": types.SetType{ElemType: types.StringType},
	"fixed_versions":      types.SetType{ElemType: types.StringType},
	"vulnerable_ranges":   types.SetType{ElemType: vulnerableRangesSetResourceModelAttributeTypes},
}

var componentSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: componentResourceModelAttributeTypes,
}

var cveResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"cve":     types.StringType,
	"cvss_v2": types.StringType,
	"cvss_v3": types.StringType,
}

var cveSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: cveResourceModelAttributeTypes,
}

var sourceResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"id":   types.StringType,
	"name": types.StringType,
	"url":  types.StringType,
}

var sourceSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: sourceResourceModelAttributeTypes,
}

func (m *CustomIssueResourceModel) fromAPIModel(ctx context.Context, apiModel CustomIssueAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.ID)
	m.Description = types.StringValue(apiModel.Description)
	m.Summary = types.StringValue(apiModel.Summary)
	m.Type = types.StringValue(apiModel.Type)
	m.ProviderName = types.StringValue(apiModel.Provider)
	m.PackageType = types.StringValue(apiModel.PackageType)
	m.Severity = types.StringValue(apiModel.Severity)

	components := lo.Map(
		apiModel.Components,
		func(property ComponentAPIModel, _ int) attr.Value {
			vulnerableVersions, ds := types.SetValueFrom(ctx, types.StringType, property.VulnerableVersions)
			if ds != nil {
				diags.Append(ds...)
			}

			fixedVersions, ds := types.SetValueFrom(ctx, types.StringType, property.FixedVersions)
			if ds != nil {
				diags.Append(ds...)
			}

			vulnerableRanges := lo.Map(
				property.VulnerableRanges,
				func(property VulnerableRangeAPIModel, _ int) attr.Value {
					vulnerableVersions, ds := types.SetValueFrom(ctx, types.StringType, property.VulnerableVersions)
					if ds != nil {
						diags.Append(ds...)
					}

					fixedVersions, ds := types.SetValueFrom(ctx, types.StringType, property.FixedVersions)
					if ds != nil {
						diags.Append(ds...)
					}

					vulnerableRange, ds := types.ObjectValue(
						vulnerableRangesResourceModelAttributeTypes,
						map[string]attr.Value{
							"vulnerable_versions": vulnerableVersions,
							"fixed_versions":      fixedVersions,
						},
					)

					if ds != nil {
						diags.Append(ds...)
					}

					return vulnerableRange
				},
			)
			vulnerableRangesSet, ds := types.SetValue(
				vulnerableRangesSetResourceModelAttributeTypes,
				vulnerableRanges,
			)
			if ds != nil {
				diags.Append(ds...)
			}

			component, ds := types.ObjectValue(
				componentResourceModelAttributeTypes,
				map[string]attr.Value{
					"id":                  types.StringValue(property.ID),
					"vulnerable_versions": vulnerableVersions,
					"fixed_versions":      fixedVersions,
					"vulnerable_ranges":   vulnerableRangesSet,
				},
			)

			if ds != nil {
				diags.Append(ds...)
			}

			return component
		},
	)
	componentsSet, d := types.SetValue(
		componentSetResourceModelAttributeTypes,
		components,
	)
	if d != nil {
		diags.Append(d...)
	}
	m.Component = componentsSet

	cves := lo.Map(
		apiModel.CVEs,
		func(property CVEAPIModel, _ int) attr.Value {
			cveMap := map[string]attr.Value{
				"cve":     types.StringNull(),
				"cvss_v2": types.StringNull(),
				"cvss_v3": types.StringNull(),
			}

			if property.CVE != "" {
				cveMap["cve"] = types.StringValue(property.CVE)
			}

			if property.CVSSv2 != "" {
				cveMap["cvss_v2"] = types.StringValue(property.CVSSv2)
			}

			if property.CVSSv3 != "" {
				cveMap["cvss_v3"] = types.StringValue(property.CVSSv3)
			}

			cve, ds := types.ObjectValue(
				cveResourceModelAttributeTypes,
				cveMap,
			)

			if ds != nil {
				diags.Append(ds...)
			}

			return cve
		},
	)
	cvesSet, d := types.SetValue(
		cveSetResourceModelAttributeTypes,
		cves,
	)
	if d != nil {
		diags.Append(d...)
	}
	m.CVE = cvesSet

	sources := lo.Map(
		apiModel.Sources,
		func(property SourceAPIModel, _ int) attr.Value {
			sourceMap := map[string]attr.Value{
				"id":   types.StringValue(property.ID),
				"name": types.StringNull(),
				"url":  types.StringNull(),
			}

			if property.Name != "" {
				sourceMap["name"] = types.StringValue(property.Name)
			}

			if property.URL != "" {
				sourceMap["url"] = types.StringValue(property.URL)
			}

			source, ds := types.ObjectValue(
				sourceResourceModelAttributeTypes,
				sourceMap,
			)

			if ds != nil {
				diags.Append(ds...)
			}

			return source
		},
	)
	sourceSet, d := types.SetValue(
		sourceSetResourceModelAttributeTypes,
		sources,
	)
	if d != nil {
		diags.Append(d...)
	}
	m.Source = sourceSet

	return diags
}

type VulnerableRangeAPIModel struct {
	VulnerableVersions []string `json:"vulnerable_versions"`
	FixedVersions      []string `json:"fixed_versions"`
}

type ComponentAPIModel struct {
	ID                 string                    `json:"id"`
	VulnerableVersions []string                  `json:"vulnerable_versions"`
	FixedVersions      []string                  `json:"fixed_versions"`
	VulnerableRanges   []VulnerableRangeAPIModel `json:"vulnerable_ranges"`
}

type CVEAPIModel struct {
	CVE    string `json:"cve"`
	CVSSv2 string `json:"cvss_v2"`
	CVSSv3 string `json:"cvss_v3"`
}

type SourceAPIModel struct {
	ID   string `json:"source_id"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type CustomIssueAPIModel struct {
	ID          string              `json:"id"`
	Description string              `json:"description"`
	Summary     string              `json:"summary"`
	Type        string              `json:"type"`
	Provider    string              `json:"provider"`
	PackageType string              `json:"package_type"`
	Severity    string              `json:"severity"`
	Components  []ComponentAPIModel `json:"components"`
	CVEs        []CVEAPIModel       `json:"cves"`
	Sources     []SourceAPIModel    `json:"sources"`
}

func (r *CustomIssueResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					validatorfw_string.RegexNotMatches(
						regexp.MustCompile(`(?i)^xray`),
						"must not begin with 'xray' (case insensitive)",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the custom issue. It must not begin with 'xray' (case insensitive)",
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of custom issue",
			},
			"summary": schema.StringAttribute{
				Required:    true,
				Description: "Summary of custom issue",
			},
			"type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("other", "performance", "security", "versions"),
				},
				Description: "Type of custom issue. Valid values: other, performance, security, versions",
			},
			"provider_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					validatorfw_string.RegexNotMatches(
						regexp.MustCompile(`(?i)^jfrog$`),
						"must not be 'jfrog' (case insensitive)",
					),
				},
				Description: "Provider of custom issue. It must not be 'jfrog' (case insensitive)",
			},
			"package_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(validPackageTypes...),
				},
				Description: fmt.Sprintf("Package Type of custom issue. Valid values are: %s", strings.Join(validPackageTypes, ", ")),
			},
			"severity": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("Critical", "High", "Medium", "Low", "Information"),
				},
				Description: "Severity of custom issue. Valid values: Critical, High, Medium, Low, Information",
			},
		},
		Blocks: map[string]schema.Block{
			"component": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Required:    true,
							Description: "ID of the component",
						},
						"vulnerable_versions": schema.SetAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Description: "List of vulnerable versions",
						},
						"fixed_versions": schema.SetAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Description: "List of fixed versions",
						},
					},
					Blocks: map[string]schema.Block{
						"vulnerable_ranges": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"vulnerable_versions": schema.SetAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "List of vulnerable versions",
									},
									"fixed_versions": schema.SetAttribute{
										ElementType: types.StringType,
										Optional:    true,
										Description: "List of fixed versions",
									},
								},
							},
							Description: "List of the vulnerable ranges",
						},
					},
				},
				Description: "Component of custom issue",
			},
			"cve": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"cve": schema.StringAttribute{
							Optional:    true,
							Description: "CVE ID",
						},
						"cvss_v2": schema.StringAttribute{
							Optional:    true,
							Description: "CVSS v2 score",
						},
						"cvss_v3": schema.StringAttribute{
							Optional:    true,
							Description: "CVSS v3 score",
						},
					},
				},
				Description: "CVE of the custom issue",
			},
			"source": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Required:    true,
							Description: "ID of the source, e.g. CVE",
						},
						"name": schema.StringAttribute{
							Optional:    true,
							Description: "Name of the source",
						},
						"url": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								validatorfw_string.IsURLHttpOrHttps(),
							},
							Description: "URL of the source",
						},
					},
				},
				Description: "List of sources",
			},
		},
		Description: "Provides an Xray custom issue event resource. See [Xray Custom Issue](https://jfrog.com/help/r/xray-how-to-formally-raise-an-issue-regarding-an-indexed-artifact) " +
			"and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/issues) for more details.\n\n" +
			"~>Due to JFrog Xray REST API behavior, when `component.vulnerable_versions` or `component.fixed_versions` are " +
			"set, their values are mirrored in the `component.vulnerable_ranges` attribute, and vice versa. We recommend " +
			"setting all the `component` attribute values to match to avoid state drift.",
	}
}

func (r *CustomIssueResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *CustomIssueResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan CustomIssueResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var customIssue CustomIssueAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &customIssue)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.ProviderData.Client.R().
		SetBody(customIssue).
		Post(CustomIssuesEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	plan.ID = types.StringValue(customIssue.ID)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CustomIssueResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state CustomIssueResourceModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var customIssue CustomIssueAPIModel

	response, err := r.ProviderData.Client.R().
		SetPathParam("id", state.Name.ValueString()).
		SetResult(&customIssue).
		Get(CustomIssueEndpointV2)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, customIssue)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CustomIssueResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan CustomIssueResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var customIssue CustomIssueAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &customIssue)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.ProviderData.Client.R().
		SetPathParam("id", plan.Name.ValueString()).
		SetBody(customIssue).
		Put(CustomIssueEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	plan.ID = types.StringValue(customIssue.ID)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CustomIssueResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state CustomIssueResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	response, err := r.ProviderData.Client.R().
		SetPathParam("id", state.Name.ValueString()).
		Delete(CustomIssueEndpoint)

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

// ImportState imports the resource into the Terraform state.
func (r *CustomIssueResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
