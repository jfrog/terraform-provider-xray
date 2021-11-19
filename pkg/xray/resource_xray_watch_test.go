package xray

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var tempStructWatch = map[string]string{
	"resource_name":        "",
	"watch_name":           "xray-watch",
	"description":          "This is a new watch created by TF Provider",
	"active":               "true",
	"watch_type":           "all-repos",
	"filter_type_0":        "regex",
	"filter_value_0":       ".*",
	"policy_name":          "xray-policy",
	"assigned_policy_type": "security",
	"watch_recipient_0":    "test@email.com",
	"watch_recipient_1":    "test1@email.com",
}

func TestAccWatch_basic(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = "xray-watch-1"
	tempStruct["policy_name"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, allReposWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
			{
				Config: testAccXrayWatchUnassigned(tempStruct["policy_name"]),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWatchDoesntExist(fqrn),
				),
			},
		},
	})
}

const allReposWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name }}"
  description = "Security policy description"
  type        = "security"
  rules {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = true
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false  
      build_failure_grace_period_in_days = 5   
    }
  }
}

resource "xray_watch" "{{ .resource_name }}" {
  name        	= "{{ .watch_name }}"
  description 	= "{{ .description }}"
  active 		= {{ .active }}

  resources {
	type       	= "{{ .watch_type }}"
	filters {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  assigned_policies {
  	name 	= xray_security_policy.security.name
  	type 	= "{{ .assigned_policy_type }}"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

func verifyXrayWatch(fqrn string, tempStruct map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", tempStruct["watch_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", tempStruct["description"]),
	)
}

// These two tests are commented out because repoName and binMgrId must be real values but neither are terraformable so can't be put into these tests
// I have tested this with some real values, but for obvious privacy reasons am not leaving those real values in here
/*func TestAccWatch_filters(t *testing.T) {
	watchName := "test-watch"
	watchDesc := "watch created by xray acceptance tests"
	repoName := "repo-name"
	binMgrId := "artifactory-id"
	policyName := fmt.Sprintf("test-policy%d",randomInt())
	filterValue := "Debian"
	updatedDesc := "updated watch description"
	updatedValue := "Docker"
	resourceName := "xray_watch.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccXrayWatchFilters(watchName, watchDesc, repoName, binMgrId, policyName, filterValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", watchName),
					resource.TestCheckResourceAttr(resourceName, "description", watchDesc),
					resource.TestCheckResourceAttr(resourceName, "resources.0.filters.0.type", "package-type"),
					resource.TestCheckResourceAttr(resourceName, "resources.0.filters.0.value", filterValue),
					resource.TestCheckResourceAttr(resourceName, "resources.0.type", "repository"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
			},
			{
				Config: testAccXrayWatchFilters(watchName, updatedDesc, repoName, binMgrId, policyName, updatedValue),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", watchName),
					resource.TestCheckResourceAttr(resourceName, "description", updatedDesc),
					resource.TestCheckResourceAttr(resourceName, "resources.0.filters.0.type", "package-type"),
					resource.TestCheckResourceAttr(resourceName, "resources.0.filters.0.value", updatedValue),
					resource.TestCheckResourceAttr(resourceName, "resources.0.type", "repository"),
				),
			},
			{
				Config: testAccXrayWatchUnassigned(policyName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWatchDoesntExist(resourceName),
				),
			},
		},
	})
}

func TestAccWatch_builds(t *testing.T) {
	watchName := "test-watch"
	policyName := "test-policy"
	watchDesc := "watch created by xray acceptance tests"
	binMgrId := "artifactory-id"
	resourceName := "xray_watch.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccXrayWatchBuilds(watchName, watchDesc, policyName, binMgrId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", watchName),
					resource.TestCheckResourceAttr(resourceName, "description", watchDesc),
					resource.TestCheckResourceAttr(resourceName, "resources.0.type", "all-builds"),
					resource.TestCheckResourceAttr(resourceName, "assigned_policies.0.name", policyName),
					resource.TestCheckResourceAttr(resourceName, "assigned_policies.0.type", "security"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
			},
			{
				Config: testAccXrayWatchUnassigned(policyName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckWatchDoesntExist(resourceName),
				),
			},
		},
	})
}*/

func testAccCheckWatchDoesntExist(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		_, ok := s.RootModule().Resources[resourceName]
		if ok {
			return fmt.Errorf("watch %s exists when it shouldn't", resourceName)
		}
		return nil
	}
}

func testAccCheckWatchDestroy(s *terraform.State) error {
	provider, _ := testAccProviders["xray"]()

	client := provider.Meta().(*resty.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type == "xray_watch" {
			watch := Watch{}
			resp, err := client.R().SetResult(watch).Get("xray/api/v2/watches/" + rs.Primary.ID)
			if err != nil {
				if resp != nil && resp.StatusCode() == http.StatusNotFound {
					continue
				}
				return err
			}

			return fmt.Errorf("error: Watch %s still exists %s", rs.Primary.ID, *watch.GeneralData.Name)

		}
		if rs.Type == "xray_security_policy" {
			policy, resp, err := getPolicy(rs.Primary.ID, client)

			if err != nil {
				if resp != nil && resp.StatusCode() == http.StatusInternalServerError &&
					err.Error() != fmt.Sprintf("{\"error\":\"Failed to find Policy %s\"}", rs.Primary.ID) {
					continue
				}
				return err
			}
			return fmt.Errorf("error: Policy %s still exists %s", rs.Primary.ID, *policy.Name)
		}
	}

	return nil
}

// Since policies can't be deleted if they have a watch assigned, we need to force terraform to delete the watch first
// by removing it from the code at the end of every test step
func testAccXrayWatchUnassigned(policyName string) string {
	return fmt.Sprintf(`
resource "xray_security_policy" "security" {
  name        = "%s"
  description = "Security policy description"
  type        = "security"
  rules {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = true
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false  
      build_failure_grace_period_in_days = 5   
    }
  }
}
`, policyName)
}

// You seemingly can't do filters with all-repos - it's an example in the docs but doesn't seem possible via the web ui
//func testAccXrayWatchFilters(name, description, repoName, binMgrId, policyName, filterValue string) string {
//	return fmt.Sprintf(`
//resource "xray_policy" "test" {
//	name  = "%s"
//	description = "test policy description"
//	type = "security"
//
//	rules {
//		name = "rule-name"
//		priority = 1
//		criteria {
//			min_severity = "High"
//		}
//		actions {
//			block_download {
//				unscanned = true
//				active = true
//			}
//		}
//	}
//}
//
//resource "xray_watch" "test" {
//	name  = "%s"
//	description = "%s"
//	resources {
//		type = "repository"
//		name = "%s"
//		bin_mgr_id = "%s"
//		filters {
//			type = "package-type"
//			value = "%s"
//		}
//	}
//	assigned_policies {
//		name = xray_policy.test.name
//		type = "security"
//	}
//}
//`, policyName, name, description, repoName, binMgrId, filterValue)
//}
//
//func testAccXrayWatchBuilds(name, description, policyName, binMgrId string) string {
//	return fmt.Sprintf(`
//resource "xray_policy" "test" {
//	name  = "%s"
//	description = "test policy description"
//	type = "security"
//
//	rules {
//		name = "rule-name"
//		priority = 1
//		criteria {
//			min_severity = "High"
//		}
//		actions {
//			block_download {
//				unscanned = true
//				active = true
//			}
//		}
//	}
//}
//
//resource "xray_watch" "test" {
//	name = "%s"
//	description = "%s"
//	resources {
//		type = "all-builds"
//		name = "All Builds"
//		bin_mgr_id = "%s"
//	}
//	assigned_policies {
//		name = xray_policy.test.name
//		type = "security"
//	}
//}
//`, policyName, name, description, binMgrId)
//}

// TODO for bonus points - test builds with complex filters eg "filters":[{"type":"ant-patterns","value":{"ExcludePatterns":[],"IncludePatterns":["*"]}
