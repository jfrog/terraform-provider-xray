package xray

import (
	"fmt"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var tempStructWatch = map[string]string{
	"resource_name":     "",
	"watch_name":        "xray-watch",
	"description":       "This is a new watch created by TF Provider",
	"active":            "true",
	"watch_type":        "all-repos",
	"filter_type_0":     "regex",
	"filter_value_0":    ".*",
	"filter_type_1":     "package-type",
	"filter_value_1":    "Docker",
	"policy_name_0":     "xray-policy-0",
	"policy_name_1":     "xray-policy-1",
	"watch_recipient_0": "test@email.com",
	"watch_recipient_1": "test@email.com",
}

func TestAccWatch_allReposSinglePolicy(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testCheckPolicyDeleted("xray_security_policy.security", t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, allReposSinglePolicyWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

func TestAccWatch_allReposMultiplePolicies(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["policy_name_1"] = fmt.Sprintf("xray-policy-%d", randomInt())

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testCheckPolicyDeleted("xray_security_policy.security", t, request)
			testCheckPolicyDeleted("xray_license_policy.license", t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, allReposMultiplePoliciesWatchTemplate, tempStruct),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", tempStruct["watch_name"]),
					resource.TestCheckResourceAttr(fqrn, "description", tempStruct["description"]),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", tempStruct["watch_type"]),
				),
			},
		},
	})
}

// To verify the watch for a single repo we need to create a new repository with Xray indexing enabled
// testAccCreateRepos() is creating a local repos with Xray indexing enabled using the API call
// We need to figure out how to use external providers (like Artifactory) in the tests. Documented approach didn't work
func TestAccWatch_singleRepository(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["watch_type"] = "repository"
	repo0 := "libs-release-local"
	repo1 := "libs-release-local-1"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccCreateRepos(t, repo0)
			testAccCreateRepos(t, repo1)
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, repo0)
			testAccDeleteRepo(t, repo1)
			testCheckPolicyDeleted("xray_security_policy.security", t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProviderFactories: testAccProviders(),
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
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["watch_type"] = "repository"
	repo0 := "libs-release-local"
	repo1 := "libs-release-local-1"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccCreateRepos(t, repo0)
			testAccCreateRepos(t, repo1)
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, repo0)
			testAccDeleteRepo(t, repo1)
			testCheckPolicyDeleted("xray_security_policy.security", t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, multipleRepositoriesWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

func TestAccWatch_build(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["watch_type"] = "build"
	tempStruct["build_name0"] = "release-pipeline"
	tempStruct["build_name1"] = "release-pipeline1"
	builds := []string{tempStruct["build_name0"]}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccCreateBuilds(t, builds)
		},
		CheckDestroy:      verifyDeleted(fqrn, testCheckWatch),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, buildWatchTemplate, tempStruct),
				Check:  verifyXrayWatch(fqrn, tempStruct),
			},
		},
	})
}

func TestAccWatch_multipleBuilds(t *testing.T) {
	_, fqrn, resourceName := mkNames("watch-", "xray_watch")
	tempStruct := make(map[string]string)
	copyStringMap(tempStructWatch, tempStruct)

	tempStruct["resource_name"] = resourceName
	tempStruct["watch_name"] = fmt.Sprintf("xray-watch-%d", randomInt())
	tempStruct["policy_name_0"] = fmt.Sprintf("xray-policy-%d", randomInt())
	tempStruct["watch_type"] = "build"
	tempStruct["build_name0"] = "release-pipeline"
	tempStruct["build_name1"] = "release-pipeline1"
	builds := []string{tempStruct["build_name0"], tempStruct["build_name1"]}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccCreateBuilds(t, builds)
		},
		CheckDestroy:      verifyDeleted(fqrn, testCheckWatch),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: executeTemplate(fqrn, multipleBuildsWatchTemplate, tempStruct),
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

  watch_resource {
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

  watch_resource {
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

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "libs-release-local"
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

const multipleRepositoriesWatchTemplate = `resource "xray_security_policy" "security" {
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

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "libs-release-local"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
}
  watch_resource {
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
  	type 	= "security"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const buildWatchTemplate = `resource "xray_security_policy" "security" {
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

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .build_name0 }}"
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const multipleBuildsWatchTemplate = `resource "xray_security_policy" "security" {
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

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .build_name0 }}"
}

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .build_name1 }}"
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

func verifyXrayWatch(fqrn string, tempStruct map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", tempStruct["watch_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", tempStruct["description"]),
		resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", tempStruct["watch_type"]),
		resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.name", tempStruct["policy_name_0"]),
		resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.type", "security"),
	)
}

func checkWatch(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v2/watches/" + id)
}

func testCheckWatch(id string, request *resty.Request) (*resty.Response, error) {
	return checkWatch(id, request.AddRetryCondition(neverRetry))
}
