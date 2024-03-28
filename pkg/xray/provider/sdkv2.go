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

// Version for some reason isn't getting updated by the linker
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
				Type:             schema.TypeString,
				Optional:         true,
				Sensitive:        true,
				DefaultFunc:      schema.MultiEnvDefaultFunc([]string{"XRAY_ACCESS_TOKEN", "JFROG_ACCESS_TOKEN"}, ""),
				ValidateDiagFunc: validator.StringIsNotEmpty,
				Description:      "This is a bearer token that can be given to you by your admin under `Identity and Access`",
			},
			"check_license": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Toggle for pre-flight checking of Artifactory Pro and Enterprise license. Default to `true`.",
			},
		},

		ResourcesMap: sdk.AddTelemetry(
			productId,
			map[string]*schema.Resource{
				"xray_security_policy":          xray.ResourceXraySecurityPolicyV2(),
				"xray_license_policy":           xray.ResourceXrayLicensePolicyV2(),
				"xray_operational_risk_policy":  xray.ResourceXrayOperationalRiskPolicy(),
				"xray_watch":                    xray.ResourceXrayWatch(),
				"xray_ignore_rule":              xray.ResourceXrayIgnoreRule(),
				"xray_settings":                 xray.ResourceXraySettings(),
				"xray_workers_count":            xray.ResourceXrayWorkersCount(),
				"xray_repository_config":        xray.ResourceXrayRepositoryConfig(),
				"xray_vulnerabilities_report":   xray.ResourceXrayVulnerabilitiesReport(),
				"xray_licenses_report":          xray.ResourceXrayLicensesReport(),
				"xray_violations_report":        xray.ResourceXrayViolationsReport(),
				"xray_operational_risks_report": xray.ResourceXrayOperationalRisksReport(),
				"xray_custom_issue":             xray.ResourceXrayCustomIssue(),
				"xray_webhook":                  xray.ResourceXrayWebhook(),
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

	restyBase, err := client.Build(URL.(string), productId)
	if err != nil {
		return nil, diag.FromErr(err)
	}
	accessToken := d.Get("access_token").(string)

	restyBase, err = client.AddAuth(restyBase, "", accessToken)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	checkLicense := d.Get("check_license").(bool)
	if checkLicense {
		licenseErr := sdk.CheckArtifactoryLicense(restyBase, "Enterprise", "Commercial")
		if licenseErr != nil {
			return nil, licenseErr
		}
	}

	artifactoryVersion, err := util.GetArtifactoryVersion(restyBase)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	xrayVersion, err := util.GetXrayVersion(restyBase)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	featureUsage := fmt.Sprintf("Terraform/%s", terraformVersion)
	go util.SendUsage(ctx, restyBase, productId, featureUsage)

	return util.ProvderMetadata{
		Client:             restyBase,
		ArtifactoryVersion: artifactoryVersion,
		XrayVersion:        xrayVersion,
	}, nil

}
