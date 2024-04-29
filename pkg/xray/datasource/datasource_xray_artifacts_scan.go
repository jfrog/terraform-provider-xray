package datasource

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

var _ datasource.DataSource = &XrayArtifactsScanDataSource{}

func NewArtifactsScanDataSource() datasource.DataSource {
	return &XrayArtifactsScanDataSource{}
}

type XrayArtifactsScanDataSource struct {
	ProviderData util.ProviderMetadata
}

type XrayArtifactsScanDataSourceModel struct {
	Repo         types.String   `tfsdk:"repo"`
	OrderBy      types.String   `tfsdk:"order_by"`
	RepoPath     types.String   `tfsdk:"repo_path"`
	CreatedStart types.String   `tfsdk:"created_start"`
	CreatedEnd   types.String   `tfsdk:"created_end"`
	Direction    types.String   `tfsdk:"direction"`
	NumOfRows    types.Int64    `tfsdk:"num_of_rows"`
	Offset       types.Int64    `tfsdk:"offset"`
	Results      []types.Object `tfsdk:"results"`
}

type XrayArtifactsScanResultSeverityModel struct {
	Critical    types.Int64 `tfsdk:"critical"`
	High        types.Int64 `tfsdk:"high"`
	Information types.Int64 `tfsdk:"information"`
	Low         types.Int64 `tfsdk:"low"`
	Medium      types.Int64 `tfsdk:"medium"`
	Total       types.Int64 `tfsdk:"total"`
	Unknown     types.Int64 `tfsdk:"unknown"`
}

var severitiesAttributeTypes = map[string]attr.Type{
	"critical":    types.Int64Type,
	"high":        types.Int64Type,
	"information": types.Int64Type,
	"low":         types.Int64Type,
	"medium":      types.Int64Type,
	"total":       types.Int64Type,
	"unknown":     types.Int64Type,
}

func (m XrayArtifactsScanResultSeverityModel) AttributeTypes() map[string]attr.Type {
	return severitiesAttributeTypes
}

type XrayArtifactsScanResultExposuresIssuesCategoriesModel struct {
	Applications types.Object `tfsdk:"applications"`
	Secrets      types.Object `tfsdk:"secrets"`
	Services     types.Object `tfsdk:"services"`
	IAC          types.Object `tfsdk:"iac"`
}

var categoriesAttributeTypes = map[string]attr.Type{
	"applications": types.ObjectType{AttrTypes: severitiesAttributeTypes},
	"secrets":      types.ObjectType{AttrTypes: severitiesAttributeTypes},
	"services":     types.ObjectType{AttrTypes: severitiesAttributeTypes},
	"iac":          types.ObjectType{AttrTypes: severitiesAttributeTypes},
}

func (m XrayArtifactsScanResultExposuresIssuesCategoriesModel) AttributeTypes() map[string]attr.Type {
	return categoriesAttributeTypes
}

type XrayArtifactsScanResultExposuresIssuesModel struct {
	Categories  types.Object `tfsdk:"categories"`
	LastScanned types.String `tfsdk:"last_scanned"`
}

func (m XrayArtifactsScanResultExposuresIssuesModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"categories":   types.ObjectType{AttrTypes: categoriesAttributeTypes},
		"last_scanned": types.StringType,
	}
}

type XrayArtifactsScanResultModel struct {
	Name              types.String `tfsdk:"name"`
	RepoPath          types.String `tfsdk:"repo_path"`
	PackageID         types.String `tfsdk:"package_id"`
	Version           types.String `tfsdk:"version"`
	SecIssues         types.Object `tfsdk:"sec_issues"`
	Size              types.String `tfsdk:"size"`
	Violations        types.Int64  `tfsdk:"violations"`
	Created           types.String `tfsdk:"created"`
	DeployedBy        types.String `tfsdk:"deployed_by"`
	RepoFullPath      types.String `tfsdk:"repo_full_path"`
	ExposuresIssues   types.Object `tfsdk:"exposures_issues"`
	MaliciousPackages types.Set    `tfsdk:"malicious_packages"`
}

func (m XrayArtifactsScanResultModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"name":           types.StringType,
		"repo_path":      types.StringType,
		"package_id":     types.StringType,
		"version":        types.StringType,
		"sec_issues":     types.ObjectType{AttrTypes: severitiesAttributeTypes},
		"size":           types.StringType,
		"violations":     types.Int64Type,
		"created":        types.StringType,
		"deployed_by":    types.StringType,
		"repo_full_path": types.StringType,
		"exposures_issues": types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"categories":   types.ObjectType{AttrTypes: categoriesAttributeTypes},
				"last_scanned": types.StringType,
			},
		},
		"malicious_packages": types.SetType{ElemType: types.StringType},
	}
}

func fromSeverityAPIModel(severity ArtifactsScanSeverity) XrayArtifactsScanResultSeverityModel {
	return XrayArtifactsScanResultSeverityModel{
		Critical:    types.Int64Value(severity.Critical),
		High:        types.Int64Value(severity.High),
		Information: types.Int64Value(severity.Information),
		Low:         types.Int64Value(severity.Low),
		Medium:      types.Int64Value(severity.Medium),
		Total:       types.Int64Value(severity.Total),
		Unknown:     types.Int64Value(severity.Unknown),
	}
}

func (d *XrayArtifactsScanDataSourceModel) fromAPIModel(ctx context.Context, scanResult *ArtifactsScanResult) (ds diag.Diagnostics) {
	for _, data := range scanResult.Data {
		s := fromSeverityAPIModel(data.SecIssues)
		secIssues, diag := types.ObjectValueFrom(ctx, s.AttributeTypes(), s)
		if diag != nil {
			ds.Append(diag...)
		}

		a := fromSeverityAPIModel(data.ExposuresIssues.Categories.Applications)
		applications, diag := types.ObjectValueFrom(ctx, a.AttributeTypes(), a)
		if diag != nil {
			ds.Append(diag...)
		}

		sc := fromSeverityAPIModel(data.ExposuresIssues.Categories.Secrets)
		secrets, diag := types.ObjectValueFrom(ctx, sc.AttributeTypes(), sc)
		if diag != nil {
			ds.Append(diag...)
		}

		sv := fromSeverityAPIModel(data.ExposuresIssues.Categories.Services)
		services, diag := types.ObjectValueFrom(ctx, sv.AttributeTypes(), sv)
		if diag != nil {
			ds.Append(diag...)
		}

		i := fromSeverityAPIModel(data.ExposuresIssues.Categories.IAC)
		iac, diag := types.ObjectValueFrom(ctx, i.AttributeTypes(), i)
		if diag != nil {
			ds.Append(diag...)
		}

		c := XrayArtifactsScanResultExposuresIssuesCategoriesModel{
			Applications: applications,
			Secrets:      secrets,
			Services:     services,
			IAC:          iac,
		}
		categories, diag := types.ObjectValueFrom(ctx, c.AttributeTypes(), c)
		if diag != nil {
			ds.Append(diag...)
		}

		e := XrayArtifactsScanResultExposuresIssuesModel{
			Categories:  categories,
			LastScanned: types.StringValue(data.ExposuresIssues.LastScanned),
		}
		exposuresIssues, diag := types.ObjectValueFrom(ctx, e.AttributeTypes(), e)
		if diag != nil {
			ds.Append(diag...)
		}

		maliciousPackages, diag := types.SetValueFrom(ctx, types.StringType, data.MaliciousPackages)
		if diag != nil {
			ds.Append(diag...)
		}

		result := XrayArtifactsScanResultModel{
			Name:              types.StringValue(data.Name),
			RepoPath:          types.StringValue(data.RepoPath),
			PackageID:         types.StringValue(data.PackageID),
			Version:           types.StringValue(data.Version),
			SecIssues:         secIssues,
			Size:              types.StringValue(data.Size),
			Violations:        types.Int64Value(data.Violations),
			Created:           types.StringValue(data.Created),
			DeployedBy:        types.StringValue(data.DeployedBy),
			RepoFullPath:      types.StringValue(data.RepoFullPath),
			ExposuresIssues:   exposuresIssues,
			MaliciousPackages: maliciousPackages,
		}

		r, diag := types.ObjectValueFrom(ctx, result.AttributeTypes(), result)
		if diag != nil {
			ds.Append(diag...)
		}

		d.Results = append(d.Results, r)
	}

	return nil
}

func (d *XrayArtifactsScanDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_artifacts_scan"
}

func (d *XrayArtifactsScanDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

var severitySchemaAttributes = map[string]schema.Attribute{
	"critical":    schema.Int64Attribute{Computed: true},
	"high":        schema.Int64Attribute{Computed: true},
	"information": schema.Int64Attribute{Computed: true},
	"low":         schema.Int64Attribute{Computed: true},
	"medium":      schema.Int64Attribute{Computed: true},
	"total":       schema.Int64Attribute{Computed: true},
	"unknown":     schema.Int64Attribute{Computed: true},
}

func (d *XrayArtifactsScanDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"repo": schema.StringAttribute{
				Required:    true,
				Description: "The repository key for which to get artifacts.",
			},
			"order_by": schema.StringAttribute{
				Optional:    true,
				Description: "By which column to order the results. Allowed value: `created`, `size`, `name`, or `repo_path`.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"created", "size", "name", "repo_path"}...),
				},
			},
			"repo_path": schema.StringAttribute{
				Optional: true,
			},
			"created_start": schema.StringAttribute{
				Optional:    true,
				Description: "Return only records created after the specified time (in RFC 3339 format).",
			},
			"created_end": schema.StringAttribute{
				Optional:    true,
				Description: "Return only records created before the specified time (in RFC 3339 format).",
			},
			"direction": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"asc", "desc"}...),
				},
				Description: "The direction by which to order the results (either ascending or descending). Allowed value: `asc` or `desc`. Default is `asc`.",
			},
			"num_of_rows": schema.Int64Attribute{
				Optional:    true,
				Description: "The number of entries to return. Default is 15.",
			},
			"offset": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "A value returned by the API. It needs to be passed to the API to get the next page. A value of -1 means that the last page was reached.",
			},
			"results": schema.ListNestedAttribute{
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":       schema.StringAttribute{Computed: true},
						"repo_path":  schema.StringAttribute{Computed: true},
						"package_id": schema.StringAttribute{Computed: true},
						"version":    schema.StringAttribute{Computed: true},
						"sec_issues": schema.SingleNestedAttribute{
							Attributes: severitySchemaAttributes,
							Computed:   true,
						},
						"size":           schema.StringAttribute{Computed: true},
						"violations":     schema.Int64Attribute{Computed: true},
						"created":        schema.StringAttribute{Computed: true},
						"deployed_by":    schema.StringAttribute{Computed: true},
						"repo_full_path": schema.StringAttribute{Computed: true},
						"exposures_issues": schema.SingleNestedAttribute{
							Attributes: map[string]schema.Attribute{
								"categories": schema.SingleNestedAttribute{
									Attributes: map[string]schema.Attribute{
										"applications": schema.SingleNestedAttribute{
											Attributes: severitySchemaAttributes,
											Computed:   true,
										},
										"iac": schema.SingleNestedAttribute{
											Attributes: severitySchemaAttributes,
											Computed:   true,
										},
										"secrets": schema.SingleNestedAttribute{
											Attributes: severitySchemaAttributes,
											Computed:   true,
										},
										"services": schema.SingleNestedAttribute{
											Attributes: severitySchemaAttributes,
											Computed:   true,
										},
									},
									Computed: true,
								},
								"last_scanned": schema.StringAttribute{Computed: true},
							},
							Computed: true,
						},
						"malicious_packages": schema.SetAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
					},
				},
				Computed:    true,
				Description: "Result of artifacts scan.",
			},
		},
		MarkdownDescription: "Get a list of artifacts scanned by Xray for a specific repository. See JFrog [Scans List - Get Artifacts API documentation](https://jfrog.com/help/r/xray-rest-apis/scans-list-get-artifacts) for more details.",
	}
}

type ArtifactsScanSeverity struct {
	Critical    int64 `json:"critical"`
	High        int64 `json:"high"`
	Information int64 `json:"information"`
	Low         int64 `json:"low"`
	Medium      int64 `json:"medium"`
	Total       int64 `json:"total"`
	Unknown     int64 `json:"unknown"`
}

type ArtifactsScanExposureIssuesCategories struct {
	Applications ArtifactsScanSeverity `json:"applications"`
	IAC          ArtifactsScanSeverity `json:"iac"`
	Secrets      ArtifactsScanSeverity `json:"secrets"`
	Services     ArtifactsScanSeverity `json:"services"`
}

type ArtifactsScanExposureIssues struct {
	Categories  ArtifactsScanExposureIssuesCategories `json:"categories"`
	LastScanned string                                `json:"last_scanned"`
}

type ArtifactsScanData struct {
	Name              string                      `json:"name"`
	RepoPath          string                      `json:"repo_path"`
	PackageID         string                      `json:"package_id"`
	Version           string                      `json:"version"`
	SecIssues         ArtifactsScanSeverity       `json:"sec_issues"`
	Size              string                      `json:"size"`
	Violations        int64                       `json:"violations"`
	Created           string                      `json:"created"`
	DeployedBy        string                      `json:"deployed_by"`
	RepoFullPath      string                      `json:"repo_full_path"`
	ExposuresIssues   ArtifactsScanExposureIssues `json:"exposures_issues"`
	MaliciousPackages []string                    `json:"malicious_packages"`
}

type ArtifactsScanResult struct {
	Data []ArtifactsScanData `json:"data"`
}

func (d *XrayArtifactsScanDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data XrayArtifactsScanDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	var params = map[string]string{
		"repo": data.Repo.ValueString(),
	}

	if !data.OrderBy.IsNull() {
		params["order_by"] = data.OrderBy.ValueString()
	}

	if !data.RepoPath.IsNull() {
		params["search"] = data.RepoPath.ValueString()
	}

	if !data.CreatedStart.IsNull() {
		params["created_start"] = data.CreatedStart.ValueString()
	}

	if !data.CreatedEnd.IsNull() {
		params["created_end"] = data.CreatedEnd.ValueString()
	}

	if !data.Direction.IsNull() {
		params["direction"] = data.Direction.ValueString()
	}

	if !data.NumOfRows.IsNull() {
		params["num_of_rows"] = fmt.Sprintf("%d", data.NumOfRows.ValueInt64())
	}

	if !data.Offset.IsNull() {
		params["offset"] = fmt.Sprintf("%d", data.Offset.ValueInt64())
	}

	var result ArtifactsScanResult
	response, err := d.ProviderData.Client.R().
		SetQueryParams(params).
		SetResult(&result).
		Get("xray/api/v1/artifacts")

	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to read data source",
			"An unexpected error occurred while attempting to reading data source state. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+err.Error(),
		)
		return
	}

	if response.IsError() {
		resp.Diagnostics.AddError(
			"Unable to read data source",
			"An unexpected error occurred while attempting to reading data source state. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Error: "+response.String(),
		)
		return
	}

	resp.Diagnostics.Append(data.fromAPIModel(ctx, &result)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
