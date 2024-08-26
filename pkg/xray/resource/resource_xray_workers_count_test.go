package xray_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

func TestAccWorkersCount_full(t *testing.T) {
	// jfrogURL := os.Getenv("JFROG_URL")
	// if strings.HasSuffix(jfrogURL, "jfrog.io") {
	// 	t.Skipf("env var JFROG_URL '%s' is a cloud instance.", jfrogURL)
	// }

	_, fqrn, resourceName := testutil.MkNames("test-workers-count-", "xray_workers_count")

	temp := `
	resource "xray_workers_count" "{{ .workersCountName }}" {
		index {
			new_content      = {{ .newContent }}
			existing_content = 4
		}
		persist {
			new_content      = {{ .newContent }}
			existing_content = 4
		}
		analysis {
			new_content      = {{ .newContent }}
			existing_content = 4
		}
		policy_enforcer {
			new_content      = {{ .newContent }}
			existing_content = 8
		}
		sbom {
			new_content      = 0
			existing_content = 0
		}
		user_catalog {
			new_content      = 0
			existing_content = 0
		}
		sbom_impact_analysis {
			new_content      = 0
			existing_content = 0
		}
		migration_sbom {
			new_content      = 0
			existing_content = 0
		}
		impact_analysis {
			new_content = {{ .newContent }}
		}
		notification {
			new_content = {{ .newContent }}
		}
		panoramic {
			new_content = {{ .newContent }}
		}
	}`

	params := map[string]interface{}{
		"workersCountName": resourceName,
		"newContent":       8,
	}

	config := util.ExecuteTemplate("TestAccWorkersCount_full", temp, params)

	updatedParams := map[string]string{
		"workersCountName": resourceName,
		"newContent":       "4",
	}
	updatedConfig := util.ExecuteTemplate("TestAccWorkersCount_full", temp, updatedParams)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "index.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "index.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "index.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "persist.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "persist.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "persist.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "analysis.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "analysis.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.0.existing_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "sbom.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "sbom.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "impact_analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "impact_analysis.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "notification.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notification.0.new_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "panoramic.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "panoramic.0.new_content", "8"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "index.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "index.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "index.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "persist.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "persist.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "persist.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "analysis.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "analysis.0.existing_content", "4"),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "policy_enforcer.0.existing_content", "8"),
					resource.TestCheckResourceAttr(fqrn, "sbom.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "sbom.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "user_catalog.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "sbom_impact_analysis.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.0.new_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "migration_sbom.0.existing_content", "0"),
					resource.TestCheckResourceAttr(fqrn, "impact_analysis.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "impact_analysis.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "notification.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notification.0.new_content", updatedParams["newContent"]),
					resource.TestCheckResourceAttr(fqrn, "panoramic.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "panoramic.0.new_content", updatedParams["newContent"]),
				),
			},
			{
				Config:            updatedConfig,
				ImportState:       true,
				ImportStateVerify: true,
				ResourceName:      fqrn,
			},
		},
	})
}
