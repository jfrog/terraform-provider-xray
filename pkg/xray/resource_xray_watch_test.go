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
	"filter_type_1":        "package-type",
	"filter_value_1":       "Docker",
	"policy_name_0":        "xray-policy-0",
	"policy_name_1":        "xray-policy-1",
	"assigned_policy_type": "security",
	"watch_recipient_0":    "test@email.com",
	"watch_recipient_1":    "test1@email.com",
}

func TestAccWatch_allReposSinglePolicy(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, allReposSinglePolicyWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

func TestAccWatch__allReposMultiplePolicies(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["policy_name_1"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, allReposMultiplePoliciesWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

// To verify the watch for a single repo we need to create a new repository with Xray indexing enabled
// testAccPreCheckWatch() is creating a local repo with Xray indexing enabled using the API call
// We need to figure out how to use external providers (like Artifactory) in the tests. Documented approach didn't work
func TestAccWatch_singleRepository(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheckWatch(t) },
		CheckDestroy:      testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, singleRepositoryWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

func TestAccWatch_multipleRepositories(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheckWatch(t) },
		CheckDestroy:      testAccCheckWatchDestroy,
		ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, multipleRepositoriesWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
			{
				Config: executeTemplate(fqrn, multipleRepositoriesWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

const allReposSinglePolicyWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
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

  resource {
	type       	= "{{ .watch_type }}"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
}

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const allReposMultiplePoliciesWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
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

resource "xray_license_policy" "license" {
  name        = "{{ .policy_name_1 }}"
  description = "License policy description"
  type        = "license"
  rules {
    name     = "License_rule"
    priority = 1
    criteria {
      allowed_licenses         = ["Apache-1.0", "Apache-2.0"]
      allow_unknown            = false
      multi_license_permissive = true
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false 
      custom_severity                    = "High"
      build_failure_grace_period_in_days = 5 
    }
  }
}

resource "xray_watch" "{{ .resource_name }}" {
  name        	= "{{ .watch_name }}"
  description 	= "{{ .description }}"
  active 		= {{ .active }}

  resource {
	type       	= "{{ .watch_type }}"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
	filter {
		type  	= "{{ .filter_type_1 }}"
		value	= "{{ .filter_value_1 }}"
	}
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
}
  assigned_policy {
  	name 	= xray_license_policy.license.name
  	type 	= "license"
}

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const singleRepositoryWatchTemplate = `resource "xray_security_policy" "security" {
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

  resource {
	type       	= "repository"
	bin_mgr_id  = "default"
	name		= "libs-release-local"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "{{ .assigned_policy_type }}"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const multipleRepositoriesWatchTemplate = `resource "xray_security_policy" "security" {
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

  resource {
	type       	= "repository"
	bin_mgr_id  = "default"
	name		= "libs-release-local"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  resource {
	type       	= "repository"
	bin_mgr_id  = "default"
	name		= "libs-release-local-1"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "{{ .assigned_policy_type }}"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

// TODO: add more verifications
func verifyXrayWatch(fqrn string, tempStruct map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", tempStruct["watch_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", tempStruct["description"]),
	)
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
		if rs.Type == "xray_license_policy" {
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

// TODO for bonus points - test builds with complex filters eg "filters":[{"type":"ant-patterns","value":{"ExcludePatterns":[],"IncludePatterns":["*"]}
