package xray

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
)

func resourceXraySettings() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceXrayBasicSettingsUpdate,
		ReadContext:   resourceXrayBasicSettingsRead,
		UpdateContext: resourceXrayBasicSettingsUpdate,
		DeleteContext: resourceXrayBasicSettingsDelete,
		Description:   "Provides an Xray settings resource.",

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"db_sync_updates_time": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "The time of the Xray DB sync daily update job. Format `HH:mm`",
				ValidateDiagFunc: matchesHoursMinutesTime,
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Determines whether Xray is currently enabled. Default value: `true`.",
			},
			"allow_blocked": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determines whether to allow artifacts blocked by Xray to be downloaded. This setting cannot override the blocking of unscanned artifacts. Should only be set to `true` when `enabled` is set. Default value: `false`.",
			},
			"allow_when_unavailable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determines whether to block certain operations (for example, downloading artifacts) when the connected Xray instance is unavailable. Should only be set to `true` when `enabled` is set. Default value: `false`.",
			},
			"block_unscanned_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     60,
				Description: "Defines the amount of time to wait for Xray to _start_ scanning an artifact before blocking operations on that artifact automatically if the scan has still not started. Default value: 60 seconds (1 minute)",
			},
			"block_unfinished_scans_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1800,
				Description: "Defines the amount of time to wait for Xray to _finish_ scanning an artifact before blocking operations on that artifact automatically if the scan is still unfinished. Default value: 1800 seconds (30 minutes)",
			},
		},
	}
}

// the API doc is wrong and schemas for request and response are not identical!
type XrayBasicSettingsRequest struct {
	Enabled                     bool `json:"xrayEnabled"`
	AllowBlocked                bool `json:"allowBlockedArtifactsDownload"`
	AllowWhenUnavailable        bool `json:"allowDownloadsXrayUnavailable"`
	BlockUnscannedTimeout       int  `json:"blockUnscannedTimeoutSeconds"`
	BlockUnfinishedScansTimeout int  `json:"blockUnfinishedScansTimeoutSeconds"`
}

type XrayBasicSettingsResponse struct {
	Enabled                     bool `json:"xrayEnabled"`
	AllowBlocked                bool `json:"xrayAllowBlocked"`
	AllowWhenUnavailable        bool `json:"xrayAllowWhenUnavailable"`
	BlockUnscannedTimeout       int  `json:"blockUnscannedTimeoutSeconds"`
	BlockUnfinishedScansTimeout int  `json:"blockUnfinishedScansTimeoutSeconds"`
}

type DbSyncDailyUpdatesTime struct {
	DbSyncTime string `json:"db_sync_updates_time"`
}

func unpackSettings(s *schema.ResourceData) XrayBasicSettingsRequest {
	d := &sdk.ResourceData{ResourceData: s}
	settings := XrayBasicSettingsRequest{
		Enabled:                     d.GetBool("enabled", false),
		AllowBlocked:                d.GetBool("allow_blocked", false),
		AllowWhenUnavailable:        d.GetBool("allow_when_unavailable", false),
		BlockUnscannedTimeout:       d.GetInt("block_unscanned_timeout", false),
		BlockUnfinishedScansTimeout: d.GetInt("block_unfinished_scans_timeout", false),
	}
	return settings
}

func unpackDBSyncTime(s *schema.ResourceData) DbSyncDailyUpdatesTime {
	d := &sdk.ResourceData{ResourceData: s}
	dbSyncTime := DbSyncDailyUpdatesTime{
		DbSyncTime: d.GetString("db_sync_updates_time", false),
	}
	return dbSyncTime
}

func packSettings(settings XrayBasicSettingsResponse, d *schema.ResourceData) diag.Diagnostics {
	if err := d.Set("enabled", settings.Enabled); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("allow_blocked", settings.AllowBlocked); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("allow_when_unavailable", settings.AllowWhenUnavailable); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("block_unscanned_timeout", settings.BlockUnscannedTimeout); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("block_unfinished_scans_timeout", settings.BlockUnfinishedScansTimeout); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func packDBSyncTime(dbSyncTime DbSyncDailyUpdatesTime, d *schema.ResourceData) diag.Diagnostics {
	if err := d.Set("db_sync_updates_time", dbSyncTime.DbSyncTime); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceXrayBasicSettingsRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	req := m.(util.ProvderMetadata).Client.R()

	var settings XrayBasicSettingsResponse
	resp, err := req.
		SetResult(&settings).
		Get("artifactory/api/xrayRepo/getIntegrationConfig")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("failed to read Xray basic settings. %s", resp.String())
	}

	packSettings(settings, d)

	var dbSyncTime DbSyncDailyUpdatesTime
	resp, err = req.
		SetResult(&dbSyncTime).
		Get("xray/api/v1/configuration/dbsync/time")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("failed to read DB sync settings")
	}

	packDBSyncTime(dbSyncTime, d)

	return nil
}

func resourceXrayBasicSettingsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	req := m.(util.ProvderMetadata).Client.R()

	settings := unpackSettings(d)
	resp, err := req.
		SetBody(settings).
		Post("artifactory/api/xrayRepo/updateXrayBasicSettings")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("failed to update Xray basic settings. %s", resp.String())
	}

	dbSyncTime := unpackDBSyncTime(d)
	resp, err = req.
		SetBody(dbSyncTime).
		Put("xray/api/v1/configuration/dbsync/time")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("failed to set DB sync time. %s", resp.String())
	}

	d.SetId(dbSyncTime.DbSyncTime)

	return resourceXrayBasicSettingsRead(ctx, d, m)
}

// No delete functionality provided by API for the settings or DB sync call.
// Delete function will remove the object from the Terraform state
func resourceXrayBasicSettingsDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}
