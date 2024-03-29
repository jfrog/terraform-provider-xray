package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

func TestSettings_UpgradeFromSDKv2(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-settings", "xray_settings")

	tmpl := `
	resource "xray_settings" "{{ .name }}" {
		enabled                        = true
		allow_blocked                  = {{ .allowBlocked }}
		allow_when_unavailable         = {{ .allowWhenUnavailable }}
		block_unscanned_timeout        = {{ .blockUnscannedTimeout }}
		block_unfinished_scans_timeout = {{ .blockUnfinishedScansTimeout }}
		db_sync_updates_time           = "00:00"
	}`

	testData := map[string]any{
		"name":                        resourceName,
		"allowBlocked":                testutil.RandBool(),
		"allowWhenUnavailable":        testutil.RandBool(),
		"blockUnscannedTimeout":       120,
		"blockUnfinishedScansTimeout": 3600,
	}

	config := util.ExecuteTemplate(fqrn, tmpl, testData)

	resource.Test(t, resource.TestCase{
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"xray": {
						VersionConstraint: "2.4.0",
						Source:            "jfrog/xray",
					},
				},
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "enabled", "true"),
					resource.TestCheckResourceAttr(fqrn, "allow_blocked", fmt.Sprintf("%t", testData["allowBlocked"])),
					resource.TestCheckResourceAttr(fqrn, "allow_when_unavailable", fmt.Sprintf("%t", testData["allowWhenUnavailable"])),
					resource.TestCheckResourceAttr(fqrn, "block_unscanned_timeout", fmt.Sprintf("%d", testData["blockUnscannedTimeout"])),
					resource.TestCheckResourceAttr(fqrn, "block_unfinished_scans_timeout", fmt.Sprintf("%d", testData["blockUnfinishedScansTimeout"])),
				),
			},
			{
				ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
				Config:                   config,
				// ConfigPlanChecks is a terraform-plugin-testing feature.
				// If acceptance testing is still using terraform-plugin-sdk/v2,
				// use `PlanOnly: true` instead. When migrating to
				// terraform-plugin-testing, switch to `ConfigPlanChecks` or you
				// will likely experience test failures.
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func TestSettings_basic(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-settings", "xray_settings")

	tmpl := `
	resource "xray_settings" "{{ .name }}" {
		enabled                        = true
		allow_blocked                  = {{ .allowBlocked }}
		allow_when_unavailable         = {{ .allowWhenUnavailable }}
		block_unscanned_timeout        = {{ .blockUnscannedTimeout }}
		block_unfinished_scans_timeout = {{ .blockUnfinishedScansTimeout }}
		db_sync_updates_time           = "00:00"
	}`

	testData := map[string]any{
		"name":                        resourceName,
		"allowBlocked":                testutil.RandBool(),
		"allowWhenUnavailable":        testutil.RandBool(),
		"blockUnscannedTimeout":       120,
		"blockUnfinishedScansTimeout": 3600,
	}

	config := util.ExecuteTemplate(fqrn, tmpl, testData)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "enabled", "true"),
					resource.TestCheckResourceAttr(fqrn, "allow_blocked", fmt.Sprintf("%t", testData["allowBlocked"])),
					resource.TestCheckResourceAttr(fqrn, "allow_when_unavailable", fmt.Sprintf("%t", testData["allowWhenUnavailable"])),
					resource.TestCheckResourceAttr(fqrn, "block_unscanned_timeout", fmt.Sprintf("%d", testData["blockUnscannedTimeout"])),
					resource.TestCheckResourceAttr(fqrn, "block_unfinished_scans_timeout", fmt.Sprintf("%d", testData["blockUnfinishedScansTimeout"])),
				),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestSettings_DbSyncTime(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("db_sync-", "xray_settings")
	time := "18:45"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: dbSyncTimeConfig(resourceName, time),
				Check:  resource.TestCheckResourceAttr(fqrn, "db_sync_updates_time", time),
			},
		},
	})
}

func TestSettings_DbSyncTimeNegative(t *testing.T) {
	_, _, resourceName := testutil.MkNames("db_sync-", "xray_settings")
	var invalidTime = []string{"24:00", "24:55", "", "12:0", "string", "12pm", "9:00"}
	for _, time := range invalidTime {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      dbSyncTimeConfig(resourceName, time),
					ExpectError: regexp.MustCompile(`Wrong format input, expected valid hour:minutes \(HH:mm\) form`),
				},
			},
		})
	}
}

func dbSyncTimeConfig(resourceName string, time string) string {
	return fmt.Sprintf(`
		resource "xray_settings" "%s" {
			db_sync_updates_time = "%s"
		}
`, resourceName, time)
}
