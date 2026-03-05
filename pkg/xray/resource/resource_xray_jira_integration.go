package xray

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
)

const (
	JiraIntegrationsEndpoint       = "xray/api/v1/ticketing/jira-integrations"
	JiraIntegrationEndpoint        = "xray/api/v1/ticketing/jira-integrations/{connection_name}"
	JiraIntegrationDetailsEndpoint = "xray/api/v1/ticketing/jira-integrations/{connection_name}/details"
)

var _ resource.Resource = &JiraIntegrationResource{}

func NewJiraIntegrationResource() resource.Resource {
	return &JiraIntegrationResource{
		TypeName: "xray_jira_integration",
	}
}

type JiraIntegrationResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *JiraIntegrationResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type JiraIntegrationResourceModel struct {
	ConnectionName   types.String `tfsdk:"connection_name"`
	JiraServerURL    types.String `tfsdk:"jira_server_url"`
	InstallationType types.String `tfsdk:"installation_type"`
	AuthType         types.String `tfsdk:"auth_type"`
	Username         types.String `tfsdk:"username"`
	Password         types.String `tfsdk:"password"`
	SkipProxy        types.Bool   `tfsdk:"skip_proxy"`
}

type JiraIntegrationAPIModel struct {
	ConnectionName   string `json:"connection_name"`
	JiraServerURL    string `json:"jira_server_url"`
	InstallationType string `json:"installation_type"`
	AuthType         string `json:"auth_type"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	SkipProxy        bool   `json:"skip_proxy"`
}

type JiraIntegrationGetAPIModel struct {
	IntegrationName  string `json:"integrationName"`
	JiraServerURL    string `json:"jira_server_url"`
	InstallationType string `json:"installation_type"`
	AuthType         string `json:"auth_type"`
	Username         string `json:"username,omitempty"`
	SkipProxy        bool   `json:"skip_proxy"`
}

func (r *JiraIntegrationResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"connection_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "A unique identifier for the Jira integration connection.",
			},
			"jira_server_url": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					validatorfw_string.IsURLHttpOrHttps(),
				},
				Description: "The URL of the Jira server where tickets will be generated.",
			},
			"installation_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("cloud", "server"),
				},
				Description: "Specifies the type of Jira installation. Valid values: `cloud`, `server`.",
			},
			"auth_type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("basic"),
				Validators: []validator.String{
					stringvalidator.OneOf("basic"),
				},
				Description: "The authentication method. Currently only `basic` is supported. Default: `basic`.",
			},
			"username": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "The username for Jira authentication.",
			},
			"password": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				Description: "The password or API token for Jira authentication.",
			},
			"skip_proxy": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Indicates whether proxy settings should be bypassed. Default: `false`.",
			},
		},
		Description: "Manages an Xray Jira integration configuration. " +
			"See [Xray Jira Integration](https://jfrog.com/help/r/jfrog-security-documentation/xray-jira-integration) " +
			"and [REST API](https://jfrog.com/help/r/xray-rest-apis/jira-integration) for more details.",
	}
}

func (r *JiraIntegrationResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *JiraIntegrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan JiraIntegrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	integration := JiraIntegrationAPIModel{
		ConnectionName:   plan.ConnectionName.ValueString(),
		JiraServerURL:    plan.JiraServerURL.ValueString(),
		InstallationType: plan.InstallationType.ValueString(),
		AuthType:         plan.AuthType.ValueString(),
		Username:         plan.Username.ValueString(),
		Password:         plan.Password.ValueString(),
		SkipProxy:        plan.SkipProxy.ValueBool(),
	}

	response, err := r.ProviderData.Client.R().
		SetBody(integration).
		Post(JiraIntegrationsEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *JiraIntegrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state JiraIntegrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var integration JiraIntegrationGetAPIModel
	response, err := r.ProviderData.Client.R().
		SetPathParam("connection_name", state.ConnectionName.ValueString()).
		SetResult(&integration).
		Get(JiraIntegrationDetailsEndpoint)
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

	state.ConnectionName = types.StringValue(integration.IntegrationName)
	state.JiraServerURL = types.StringValue(integration.JiraServerURL)
	state.InstallationType = types.StringValue(integration.InstallationType)
	state.AuthType = types.StringValue(integration.AuthType)
	if integration.Username != "" {
		state.Username = types.StringValue(integration.Username)
	}
	state.SkipProxy = types.BoolValue(integration.SkipProxy)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *JiraIntegrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan JiraIntegrationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	integration := JiraIntegrationAPIModel{
		ConnectionName:   plan.ConnectionName.ValueString(),
		JiraServerURL:    plan.JiraServerURL.ValueString(),
		InstallationType: plan.InstallationType.ValueString(),
		AuthType:         plan.AuthType.ValueString(),
		Username:         plan.Username.ValueString(),
		Password:         plan.Password.ValueString(),
		SkipProxy:        plan.SkipProxy.ValueBool(),
	}

	response, err := r.ProviderData.Client.R().
		SetPathParam("connection_name", plan.ConnectionName.ValueString()).
		SetBody(integration).
		Put(JiraIntegrationEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *JiraIntegrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state JiraIntegrationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.ProviderData.Client.R().
		SetPathParam("connection_name", state.ConnectionName.ValueString()).
		Delete(JiraIntegrationEndpoint)
	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}
}

func (r *JiraIntegrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("connection_name"), req, resp)
}
