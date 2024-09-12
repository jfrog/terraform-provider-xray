package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-shared/validator"
	xray "github.com/jfrog/terraform-provider-xray/pkg/xray/resource"
)

var Version = "0.0.1"
var productId = "terraform-provider-xray/" + Version

// Provider Xray provider that supports configuration via username+password or a token
// Supported resources are policies and watches
func SdkV2() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.MultiEnvDefaultFunc([]string{"XRAY_URL", "JFROG_URL"}, "http://localhost:8081"),
				ValidateFunc: validation.IsURLWithHTTPorHTTPS,
				Description:  "URL of Xray. This can also be sourced from the `XRAY_URL` or `JFROG_URL` environment variable. Default to 'http://localhost:8081' if not set.",
			},
			"access_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"XRAY_ACCESS_TOKEN", "JFROG_ACCESS_TOKEN"}, ""),
				Description: "This is a bearer token that can be given to you by your admin under `Identity and Access`",
			},
			"oidc_provider_name": {
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: validator.StringIsNotEmpty,
				Description:      "OIDC provider name. See [Configure an OIDC Integration](https://jfrog.com/help/r/jfrog-platform-administration-documentation/configure-an-oidc-integration) for more details.",
			},
			"check_license": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Toggle for pre-flight checking of Artifactory Pro and Enterprise license. Default to `true`.",
				Deprecated:  "Remove this attribute from your provider configuration as it is no longer used and the attribute will be removed in the next major version of the provider.",
			},
		},

		ResourcesMap: sdk.AddTelemetry(
			productId,
			map[string]*schema.Resource{
				"xray_violations_report":        xray.ResourceXrayViolationsReport(),
				"xray_operational_risks_report": xray.ResourceXrayOperationalRisksReport(),
			},
		),
	}

	p.ConfigureContextFunc = func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		var ds diag.Diagnostics
		meta, d := providerConfigure(ctx, data, p.TerraformVersion)
		if d != nil {
			ds = append(ds, d...)
		}
		return meta, ds
	}

	return p
}

// Creates the client for artifactory, will use token auth
func providerConfigure(ctx context.Context, d *schema.ResourceData, terraformVersion string) (interface{}, diag.Diagnostics) {
	URL, ok := d.GetOk("url")
	if URL == nil || URL == "" || !ok {
		return nil, diag.Errorf("you must supply a URL")
	}

	restyClient, err := client.Build(URL.(string), productId)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	var accessToken string

	if v, ok := d.GetOk("oidc_provider_name"); ok {
		oidcAccessToken, err := util.OIDCTokenExchange(ctx, restyClient, v.(string))
		if err != nil {
			return nil, diag.FromErr(err)
		}

		if oidcAccessToken != "" {
			accessToken = oidcAccessToken
		}
	}

	if v, ok := d.GetOk("access_token"); ok && v != "" {
		accessToken = v.(string)
	}

	if accessToken == "" {
		return nil, diag.Errorf("While configuring the provider, the Access Token was not found in " +
			"the JFROG_ACCESS_TOKEN/XRAY_ACCESS_TOKEN environment variable, or provider " +
			"configuration block access_token attribute, or from Terraform Cloud Workload Identity token.")
	}

	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	xrayVersion, err := util.GetXrayVersion(restyClient)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	featureUsage := fmt.Sprintf("Terraform/%s", terraformVersion)
	go util.SendUsage(ctx, restyClient.R(), productId, featureUsage)

	return util.ProviderMetadata{
		Client:      restyClient,
		XrayVersion: xrayVersion,
	}, nil

}
