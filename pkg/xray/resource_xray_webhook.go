package xray

import (
	"context"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
)

type Webhook struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	UseProxy    bool              `json:"use_proxy"`
	UserName    string            `json:"user_name"`
	Password    string            `json:"password"`
	Headers     map[string]string `json:"headers"`
}

func resourceXrayWebhook() *schema.Resource {
	var webhookSchema = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "An identifier for the webhook. This is the name that will be used by any Watches that want to invoke the webhook in case of a violation",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.All(
					validation.StringIsNotEmpty,
					validation.StringMatch(
						regexp.MustCompile("^[a-zA-Z0-9]+$"),
						"must contain only alphanumberic characters",
					),
				),
			),
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A free text description.",
		},
		"url": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The URL that this webhook invokes. For details of the payload provided by Xray to the webhook, please refer to Webhook Payload.",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.IsURLWithHTTPorHTTPS,
			),
		},
		"use_proxy": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Set the webhook to go through the predefined proxy. For more information, see [Managing Proxies](https://jfrog.com/help/r/jfrog-platform-administration-documentation/managing-proxies).",
		},
		"user_name": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "An username as required by the webhook.",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.StringIsNotEmpty,
			),
		},
		"password": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A password as required by the webhook.",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.StringIsNotEmpty,
			),
		},
		"headers": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Any custom headers that may need to be added to invoke the webhook.. Name/value pairs.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}

	var packWebhook = func(webhook Webhook, d *schema.ResourceData) diag.Diagnostics {
		if err := d.Set("name", webhook.Name); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("description", webhook.Description); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("url", webhook.URL); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("use_proxy", webhook.UseProxy); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("user_name", webhook.UserName); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("headers", webhook.Headers); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}

	var resourceXrayWebhookRead = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		webhook := Webhook{}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetResult(&webhook).
			SetPathParam("name", d.Id()).
			Get("xray/api/v1/webhooks/{name}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.StatusCode() == http.StatusNotFound {
			d.SetId("")
			return diag.Errorf("webhook (%s) not found, removing from state", d.Id())
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		return packWebhook(webhook, d)
	}

	var unpackWebhook = func(ctx context.Context, d *schema.ResourceData) (Webhook, error) {
		webhook := Webhook{}

		webhook.Name = d.Get("name").(string)
		if v, ok := d.GetOk("description"); ok {
			webhook.Description = v.(string)
		}

		if v, ok := d.GetOk("url"); ok {
			webhook.URL = v.(string)
		}

		if v, ok := d.GetOk("use_proxy"); ok {
			webhook.UseProxy = v.(bool)
		}

		if v, ok := d.GetOk("user_name"); ok {
			webhook.UserName = v.(string)
		}

		if v, ok := d.GetOk("password"); ok {
			webhook.Password = v.(string)
		}

		if v, ok := d.GetOk("headers"); ok {
			headers := map[string]string{}
			for k, v := range v.(map[string]interface{}) {
				headers[k] = v.(string)
			}
			webhook.Headers = headers
		}

		return webhook, nil
	}

	var resourceXrayWebhookCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		webhook, err := unpackWebhook(ctx, d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetBody(webhook).
			Post("xray/api/v1/webhooks")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		d.SetId(webhook.Name)

		return resourceXrayWebhookRead(ctx, d, m)
	}

	var resourceXrayWebhookUpdate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		webhook, err := unpackWebhook(ctx, d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetPathParam("name", d.Id()).
			SetBody(webhook).
			Put("xray/api/v1/webhooks/{name}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.IsError() {
			d.SetId("")
			return diag.Errorf("%s", resp.String())
		}

		d.SetId(webhook.Name)

		return resourceXrayWebhookRead(ctx, d, m)
	}

	var resourceXrayWebhookDelete = func(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetPathParam("name", d.Id()).
			Delete("xray/api/v1/webhooks/{name}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.StatusCode() == http.StatusNotFound {
			d.SetId("")
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		d.SetId("")

		return nil
	}

	return &schema.Resource{
		CreateContext: resourceXrayWebhookCreate,
		ReadContext:   resourceXrayWebhookRead,
		UpdateContext: resourceXrayWebhookUpdate,
		DeleteContext: resourceXrayWebhookDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: webhookSchema,
		Description: "Provides an Xray webhoook resource. See [Xray Webhooks](https://jfrog.com/help/r/jfrog-security-documentation/configuring-xray?section=UUID-bb7641b3-e469-e0ef-221d-c0ebf660dde1_id_ConfiguringXray-ConfiguringWebhooks) " +
			"and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/xray-webhooks) for more details.",
	}
}
