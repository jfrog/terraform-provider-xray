package xray

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/validator"
)

// Version for some reason isn't getting updated by the linker
var Version = "0.0.1"
var productId = "terraform-provider-xray/" + Version

// Provider Xray provider that supports configuration via username+password or a token
// Supported resources are policies and watches
func Provider() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.MultiEnvDefaultFunc([]string{"XRAY_URL", "JFROG_URL"}, "http://localhost:8081"),
				ValidateFunc: validation.IsURLWithHTTPorHTTPS,
				Description:  "URL of Artifactory. This can also be sourced from the `XRAY_URL` or `JFROG_URL` environment variable. Default to 'http://localhost:8081' if not set.",
			},
			"access_token": {
				Type:             schema.TypeString,
				Optional:         true,
				Sensitive:        true,
				DefaultFunc:      schema.MultiEnvDefaultFunc([]string{"XRAY_ACCESS_TOKEN", "JFROG_ACCESS_TOKEN"}, ""),
				ValidateDiagFunc: validator.StringIsNotEmpty,
				Description:      "This is a bearer token that can be given to you by your admin under `Identity and Access`",
			},
		},

		ResourcesMap: util.AddTelemetry(
			productId,
			map[string]*schema.Resource{
				"xray_security_policy": resourceXraySecurityPolicyV2(),
				"xray_license_policy":  resourceXrayLicensePolicyV2(),
				"xray_watch":           resourceXrayWatch(),
				"xray_settings":        resourceXraySettings(),
			},
		),
	}

	p.ConfigureContextFunc = func(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
		tflog.Info(ctx, fmt.Sprintf("Provider version: %s", Version))

		terraformVersion := p.TerraformVersion
		if terraformVersion == "" {
			terraformVersion = "0.13+compatible"
		}
		return providerConfigure(ctx, data, terraformVersion)
	}

	return p
}

// Creates the client for artifactory, will use token auth
func providerConfigure(ctx context.Context, d *schema.ResourceData, terraformVersion string) (interface{}, diag.Diagnostics) {
	URL, ok := d.GetOk("url")
	if URL == nil || URL == "" || !ok {
		return nil, diag.Errorf("you must supply a URL")
	}

	restyBase, err := client.Build(URL.(string), Version)
	if err != nil {
		return nil, diag.FromErr(err)
	}
	accessToken := d.Get("access_token").(string)

	restyBase, err = client.AddAuth(restyBase, "", accessToken)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	licenseErr := util.CheckArtifactoryLicense(restyBase, "Enterprise", "Commercial")
	if licenseErr != nil {
		return nil, licenseErr
	}

	featureUsage := fmt.Sprintf("Terraform/%s", terraformVersion)
	util.SendUsage(ctx, restyBase, productId, featureUsage)

	return restyBase, nil

}
