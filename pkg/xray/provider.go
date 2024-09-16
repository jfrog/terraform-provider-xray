package xray

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/util"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	xray_datasource "github.com/jfrog/terraform-provider-xray/pkg/xray/datasource"
	xray_resource "github.com/jfrog/terraform-provider-xray/pkg/xray/resource"
)

var Version = "2.11.1"
var productId = "terraform-provider-xray/" + Version

// Ensure the implementation satisfies the provider.Provider interface.
var _ provider.Provider = &XrayProvider{}

type XrayProvider struct {
	Meta util.ProviderMetadata
}

// XrayProviderModel describes the provider data model.
type XrayProviderModel struct {
	Url              types.String `tfsdk:"url"`
	AccessToken      types.String `tfsdk:"access_token"`
	OIDCProviderName types.String `tfsdk:"oidc_provider_name"`
	CheckLicense     types.Bool   `tfsdk:"check_license"`
}

// Metadata satisfies the provider.Provider interface for ArtifactoryProvider
func (p *XrayProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "xray"
	resp.Version = Version
}

// Schema satisfies the provider.Provider interface for ArtifactoryProvider.
func (p *XrayProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validatorfw_string.IsURLHttpOrHttps(),
				},
				Description: "URL of Xray. This can also be sourced from the `XRAY_URL` or `JFROG_URL` environment variable. Default to 'http://localhost:8081' if not set.",
			},
			"access_token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "This is a bearer token that can be given to you by your admin under `Identity and Access`",
			},
			"oidc_provider_name": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "OIDC provider name. See [Configure an OIDC Integration](https://jfrog.com/help/r/jfrog-platform-administration-documentation/configure-an-oidc-integration) for more details.",
			},
			"check_license": schema.BoolAttribute{
				Optional:           true,
				Description:        "Toggle for pre-flight checking of Artifactory Pro and Enterprise license. Default to `true`.",
				DeprecationMessage: "Remove this attribute from your provider configuration as it is no longer used and the attribute will be removed in the next major version of the provider.",
			},
		},
	}
}

func (p *XrayProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// Check environment variables, first available OS variable will be assigned to the var
	url := util.CheckEnvVars([]string{"JFROG_URL", "XRAY_URL"}, "http://localhost:8081")
	accessToken := util.CheckEnvVars([]string{"JFROG_ACCESS_TOKEN", "XRAY_ACCESS_TOKEN"}, "")

	var config XrayProviderModel

	// Read configuration data into model
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Url.ValueString() != "" {
		url = config.Url.ValueString()
	}

	if url == "" {
		resp.Diagnostics.AddError(
			"Missing URL Configuration",
			"While configuring the provider, the url was not found in "+
				"the JFROG_URL/ARTIFACTORY_URL environment variable or provider "+
				"configuration block url attribute.",
		)
		return
	}

	restyClient, err := client.Build(url, productId)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating Resty client",
			err.Error(),
		)
		return
	}

	oidcAccessToken, err := util.OIDCTokenExchange(ctx, restyClient, config.OIDCProviderName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed OIDC ID token exchange",
			err.Error(),
		)
		return
	}

	// use token from OIDC provider, which should take precedence over
	// environment variable data, if found.
	if oidcAccessToken != "" {
		accessToken = oidcAccessToken
	}

	// Check configuration data, which should take precedence over
	// environment variable data, if found.
	if config.AccessToken.ValueString() != "" {
		accessToken = config.AccessToken.ValueString()
	}

	if accessToken == "" {
		resp.Diagnostics.AddError(
			"Missing JFrog Access Token",
			"While configuring the provider, the Access Token was not found in "+
				"the JFROG_ACCESS_TOKEN/XRAY_ACCESS_TOKEN environment variable, or provider "+
				"configuration block access_token attribute, or from Terraform Cloud Workload Identity token.",
		)
		return
	}

	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error adding Auth to Resty client",
			err.Error(),
		)
	}

	version, err := util.GetXrayVersion(restyClient)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting Xray version",
			err.Error(),
		)
		return
	}

	featureUsage := fmt.Sprintf("Terraform/%s", req.TerraformVersion)
	go util.SendUsage(ctx, restyClient.R(), productId, featureUsage)

	meta := util.ProviderMetadata{
		Client:      restyClient,
		ProductId:   productId,
		XrayVersion: version,
	}

	p.Meta = meta

	resp.DataSourceData = meta
	resp.ResourceData = meta
}

// Resources satisfies the provider.Provider interface for ArtifactoryProvider.
func (p *XrayProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		xray_resource.NewBinaryManagerBuildsResource,
		xray_resource.NewBinaryManagerReposResource,
		xray_resource.NewBinaryManagerReleaseBundlesV2Resource,
		xray_resource.NewCustomIssueResource,
		xray_resource.NewIgnoreRuleResource,
		xray_resource.NewLicensePolicyResource,
		xray_resource.NewLicensesReportResource,
		xray_resource.NewOperationalRiskPolicyResource,
		xray_resource.NewOperationalRisksReportResource,
		xray_resource.NewRepositoryConfigResource,
		xray_resource.NewSecurityPolicyResource,
		xray_resource.NewSettingsResource,
		xray_resource.NewViolationsReportResource,
		xray_resource.NewVulnerabilitiesReportResource,
		xray_resource.NewWatchResource,
		xray_resource.NewWebhookResource,
		xray_resource.NewWorkersCountResource,
	}
}

// DataSources satisfies the provider.Provider interface for ArtifactoryProvider.
func (p *XrayProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		xray_datasource.NewArtifactsScanDataSource,
	}
}

func NewProvider() func() provider.Provider {
	return func() provider.Provider {
		return &XrayProvider{}
	}
}
