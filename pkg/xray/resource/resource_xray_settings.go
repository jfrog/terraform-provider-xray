package xray

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
)

const (
	DBSyncEndPoint              = "xray/api/v1/configuration/dbsync/time"
	BasicSettingsUpdateEndpoint = "artifactory/api/xrayRepo/updateXrayBasicSettings"
)

var _ resource.Resource = &SettingsResource{}

func NewSettingsResource() resource.Resource {
	return &SettingsResource{}
}

type SettingsResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *SettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_settings"
	r.TypeName = resp.TypeName
}

type SettingsResourceModel struct {
	ID                          types.String `tfsdk:"id"`
	DBSyncUpdateTime            types.String `tfsdk:"db_sync_updates_time"`
	Enabled                     types.Bool   `tfsdk:"enabled"`
	AllowBlocked                types.Bool   `tfsdk:"allow_blocked"`
	AllowWhenUnavailable        types.Bool   `tfsdk:"allow_when_unavailable"`
	BlockUnscannedTimeout       types.Int64  `tfsdk:"block_unscanned_timeout"`
	BlockUnfinishedScansTimeout types.Int64  `tfsdk:"block_unfinished_scans_timeout"`
}

// the API doc is wrong and schemas for request and response are not identical!
type BasicSettingsRequestAPIModel struct {
	Enabled                     bool  `json:"xrayEnabled"`
	AllowBlocked                bool  `json:"allowBlockedArtifactsDownload"`
	AllowWhenUnavailable        bool  `json:"allowDownloadsXrayUnavailable"`
	BlockUnscannedTimeout       int64 `json:"blockUnscannedTimeoutSeconds"`
	BlockUnfinishedScansTimeout int64 `json:"blockUnfinishedScansTimeoutSeconds"`
}

type BasicSettingsResponseAPIModel struct {
	Enabled                     bool  `json:"xrayEnabled"`
	AllowBlocked                bool  `json:"xrayAllowBlocked"`
	AllowWhenUnavailable        bool  `json:"xrayAllowWhenUnavailable"`
	BlockUnscannedTimeout       int64 `json:"blockUnscannedTimeoutSeconds"`
	BlockUnfinishedScansTimeout int64 `json:"blockUnfinishedScansTimeoutSeconds"`
}

type DbSyncDailyUpdatesTimeAPIModel struct {
	DbSyncTime string `json:"db_sync_updates_time"`
}

type DbSyncDailyUpdatesTimeErrorAPIModel struct {
	Error string `json:"error"`
}

func (r *SettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"db_sync_updates_time": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^([0-1][0-9]|[2][0-3]):([0-5][0-9])$`), "Wrong format input, expected valid hour:minutes (HH:mm) form"),
				},
				Description: "The time of the Xray DB sync daily update job. Format `HH:mm`",
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Determines whether Xray is currently enabled. Default value: `true`.",
			},
			"allow_blocked": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Determines whether to allow artifacts blocked by Xray to be downloaded. This setting cannot override the blocking of unscanned artifacts. Should only be set to `true` when `enabled` is set. Default value: `false`.",
			},
			"allow_when_unavailable": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Determines whether to block certain operations (for example, downloading artifacts) when the connected Xray instance is unavailable. Should only be set to `true` when `enabled` is set. Default value: `false`.",
			},
			"block_unscanned_timeout": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(60),
				Description: "Defines the amount of time to wait for Xray to _start_ scanning an artifact before blocking operations on that artifact automatically if the scan has still not started. Default value: 60 seconds (1 minute)",
			},
			"block_unfinished_scans_timeout": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(1800),
				Description: "Defines the amount of time to wait for Xray to _finish_ scanning an artifact before blocking operations on that artifact automatically if the scan is still unfinished. Default value: 1800 seconds (30 minutes)",
			},
		},
		Description: "Provides an Xray settings resource.",
	}
}

func (r *SettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *SettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var plan SettingsResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := r.ProviderData.Client.R()

	settings := BasicSettingsRequestAPIModel{
		Enabled:                     plan.Enabled.ValueBool(),
		AllowBlocked:                plan.AllowBlocked.ValueBool(),
		AllowWhenUnavailable:        plan.AllowWhenUnavailable.ValueBool(),
		BlockUnscannedTimeout:       plan.BlockUnscannedTimeout.ValueInt64(),
		BlockUnfinishedScansTimeout: plan.BlockUnfinishedScansTimeout.ValueInt64(),
	}

	response, err := request.
		SetBody(&settings).
		Post(BasicSettingsUpdateEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	dbSyncTime := DbSyncDailyUpdatesTimeAPIModel{
		DbSyncTime: plan.DBSyncUpdateTime.ValueString(),
	}
	var dbSyncTimeError DbSyncDailyUpdatesTimeErrorAPIModel
	response, err = request.
		SetBody(dbSyncTime).
		SetError(&dbSyncTimeError).
		Put(DBSyncEndPoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, dbSyncTimeError.Error)
		return
	}

	plan.ID = types.StringValue(dbSyncTime.DbSyncTime)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var state SettingsResourceModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := r.ProviderData.Client.R()

	var settings BasicSettingsResponseAPIModel
	response, err := request.
		SetResult(&settings).
		Get("artifactory/api/xrayRepo/getIntegrationConfig")
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, fmt.Sprintf("failed to retrieve data from API during Read: %s", err.Error()))
		return
	}
	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, fmt.Sprintf("failed to retrieve data from API during Read: %s", response.String()))
		return
	}

	// Convert from the API data model to the Terraform data model
	// and refresh any attribute values.
	state.Enabled = types.BoolValue(settings.Enabled)
	state.AllowBlocked = types.BoolValue(settings.AllowBlocked)
	state.AllowWhenUnavailable = types.BoolValue(settings.AllowWhenUnavailable)
	state.BlockUnfinishedScansTimeout = types.Int64Value(settings.BlockUnfinishedScansTimeout)
	state.BlockUnscannedTimeout = types.Int64Value(settings.BlockUnscannedTimeout)

	var dbSyncTime DbSyncDailyUpdatesTimeAPIModel
	response, err = request.
		SetResult(&dbSyncTime).
		Get(DBSyncEndPoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, fmt.Sprintf("failed to retrieve data from API during Read: %s", err.Error()))
		return
	}
	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, fmt.Sprintf("failed to retrieve data from API during Read: %s", response.String()))
		return
	}

	state.DBSyncUpdateTime = types.StringValue(dbSyncTime.DbSyncTime)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *SettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	var plan SettingsResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	request := r.ProviderData.Client.R()

	settings := BasicSettingsRequestAPIModel{
		Enabled:                     plan.Enabled.ValueBool(),
		AllowBlocked:                plan.AllowBlocked.ValueBool(),
		AllowWhenUnavailable:        plan.AllowWhenUnavailable.ValueBool(),
		BlockUnscannedTimeout:       plan.BlockUnscannedTimeout.ValueInt64(),
		BlockUnfinishedScansTimeout: plan.BlockUnfinishedScansTimeout.ValueInt64(),
	}

	response, err := request.
		SetBody(&settings).
		Post(BasicSettingsUpdateEndpoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	dbSyncTime := DbSyncDailyUpdatesTimeAPIModel{
		DbSyncTime: plan.DBSyncUpdateTime.ValueString(),
	}
	response, err = request.
		SetBody(dbSyncTime).
		Put(DBSyncEndPoint)
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	plan.ID = types.StringValue(dbSyncTime.DbSyncTime)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete No delete functionality provided by API for the settings or DB sync call.
// This function will remove the object from the Terraform state
func (r *SettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client, r.ProviderData.ProductId, r.TypeName)

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *SettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
