package xray

import (
	"context"
	"net/http"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
)

const (
	WebhooksEndpoint = "xray/api/v1/webhooks"
	WebhookEndpoint  = "xray/api/v1/webhooks/{name}"
)

var _ resource.Resource = &WebhookResource{}

func NewWebhookResource() resource.Resource {
	return &WebhookResource{}
}

type WebhookResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *WebhookResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook"
	r.TypeName = resp.TypeName
}

type WebhookResourceModel struct {
	Name        types.String `tfsdk:"name"`
	URL         types.String `tfsdk:"url"`
	Description types.String `tfsdk:"description"`
	UseProxy    types.Bool   `tfsdk:"use_proxy"`
	UserName    types.String `tfsdk:"user_name"`
	Password    types.String `tfsdk:"password"`
	Headers     types.Map    `tfsdk:"headers"`
}

type WebhookAPIModel struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	UseProxy    bool              `json:"use_proxy"`
	UserName    string            `json:"user_name"`
	Password    string            `json:"password"`
	Headers     map[string]string `json:"headers"`
}

func (r *WebhookResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile("^[a-zA-Z0-9]+$"), "must contain only alphanumberic characters"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "An identifier for the webhook. This is the name that will be used by any Watches that want to invoke the webhook in case of a violation",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "A free text description.",
			},
			"url": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					validatorfw_string.IsURLHttpOrHttps(),
				},
				Description: "The URL that this webhook invokes. For details of the payload provided by Xray to the webhook, please refer to Webhook Payload.",
			},
			"use_proxy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Set the webhook to go through the predefined proxy. For more information, see [Managing Proxies](https://jfrog.com/help/r/jfrog-platform-administration-documentation/managing-proxies).",
			},
			"user_name": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "An username as required by the webhook.",
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "A password as required by the webhook.",
			},
			"headers": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Any custom headers that may need to be added to invoke the webhook. Name/value pairs.",
			},
		},
		Description: "Provides an Xray webhoook resource. See [Xray Webhooks](https://jfrog.com/help/r/jfrog-security-documentation/configure-webhooks-for-working-with-xray) " +
			"and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/xray-webhooks) for more details.",
	}
}

func (r *WebhookResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *WebhookResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WebhookResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var headers map[string]string
	resp.Diagnostics.Append(plan.Headers.ElementsAs(ctx, &headers, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	webhook := WebhookAPIModel{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		URL:         plan.URL.ValueString(),
		UseProxy:    plan.UseProxy.ValueBool(),
		UserName:    plan.UserName.ValueString(),
		Password:    plan.Password.ValueString(),
		Headers:     headers,
	}

	response, err := r.ProviderData.Client.R().
		SetBody(webhook).
		Post(WebhooksEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WebhookResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WebhookResourceModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var webhook WebhookAPIModel
	response, err := r.ProviderData.Client.R().
		SetPathParam("name", state.Name.ValueString()).
		SetResult(&webhook).
		Get(WebhookEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}
	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}
	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	state.Name = types.StringValue(webhook.Name)

	if state.Description.IsNull() {
		state.Description = types.StringValue("")
	}
	if len(webhook.Description) > 0 {
		state.Description = types.StringValue(webhook.Description)
	}

	state.URL = types.StringValue(webhook.URL)
	state.UseProxy = types.BoolValue(webhook.UseProxy)

	if !state.UserName.IsNull() {
		state.UserName = types.StringValue(webhook.UserName)
	}

	if !state.Headers.IsNull() {
		headers, ds := types.MapValueFrom(ctx, types.StringType, webhook.Headers)
		if ds.HasError() {
			resp.Diagnostics.Append(ds...)
			return
		}
		state.Headers = headers
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *WebhookResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WebhookResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var headers map[string]string
	resp.Diagnostics.Append(plan.Headers.ElementsAs(ctx, &headers, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	webhook := WebhookAPIModel{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		URL:         plan.URL.ValueString(),
		UseProxy:    plan.UseProxy.ValueBool(),
		UserName:    plan.UserName.ValueString(),
		Password:    plan.Password.ValueString(),
		Headers:     headers,
	}

	response, err := r.ProviderData.Client.R().
		SetPathParam("name", plan.Name.ValueString()).
		SetBody(webhook).
		Put(WebhookEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WebhookResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WebhookResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	response, err := r.ProviderData.Client.R().
		SetPathParam("name", state.Name.ValueString()).
		Delete(WebhookEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	// Return error if the HTTP status code is not 200 OK, 204 No Content, or 404 Not Found
	if response.IsError() {
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *WebhookResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
