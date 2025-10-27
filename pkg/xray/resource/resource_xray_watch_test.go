package xray_test

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

var testDataWatch = map[string]string{
	"resource_name":     "",
	"watch_name":        "xray-watch",
	"description":       "This is a new watch created by TF Provider",
	"active":            "true",
	"watch_type":        "all-repos",
	"filter_type_0":     "path-regex",
	"filter_value_0":    ".*",
	"filter_type_1":     "regex",
	"filter_value_1":    ".*",
	"filter_type_2":     "package-type",
	"filter_value_2":    "Docker",
	"policy_name_0":     "xray-policy-0",
	"policy_name_1":     "xray-policy-1",
	"watch_recipient_0": "test@email.com",
	"watch_recipient_1": "test@email.com",
}

func TestAccWatch_UpgradeFromSDKv2(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())

	config := util.ExecuteTemplate(fqrn, allReposSinglePolicyWatchTemplate, testData)

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"xray": {
						VersionConstraint: "2.8.1",
						Source:            "jfrog/xray",
					},
				},
				Config: config,
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Config:                   config,
			},
		},
	})
}

func TestAccWatch_allReposSinglePolicy(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allReposSinglePolicyWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allReposPathAntFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["exclude_patterns0"] = "**/*.md"
	testData["include_patterns0"] = "**/*.js"

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allReposPathAntFilterWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allReposKvFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["kv_filter_key0"] = "test-property-name"
	testData["kv_filter_value0"] = "test-property-value"

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allReposKvFilterWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allReposWithProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	projectKey := RandomProjectName()

	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())

	template := `resource "xray_security_policy" "security" {
	  name        = "{{ .policy_name_0 }}"
	  description = "Security policy description"
	  type        = "security"
	  rule {
		name     = "rule-name-severity"
		priority = 1
		criteria {
		  min_severity = "High"
		}
		actions {
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
	  project_key   = "{{ .project_key }}"

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
	config := util.ExecuteTemplate(fqrn, template, testData)

	updatedTestData := sdk.MergeMaps(testData)
	updatedTestData["description"] = "New description"
	updatedConfig := util.ExecuteTemplate(fqrn, template, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, projectKey)
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteProject(t, projectKey)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				Config: updatedConfig,
				Check:  verifyXrayWatch(fqrn, updatedTestData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s:%s", testData["watch_name"], projectKey),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allReposMultiplePolicies(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-1%d", testutil.RandomInt())
	testData["policy_name_1"] = fmt.Sprintf("xray-policy-2%d", testutil.RandomInt())
	testData["policy_name_2"] = fmt.Sprintf("xray-policy-3%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			acctest.CheckPolicyDeleted(testData["policy_name_1"], t, request)
			acctest.CheckPolicyDeleted(testData["policy_name_2"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allReposMultiplePoliciesWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", testData["watch_name"]),
					resource.TestCheckResourceAttr(fqrn, "description", testData["description"]),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", testData["watch_type"]),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.0.filter.*", map[string]string{
						"type":  "path-regex",
						"value": ".*",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.0.filter.*", map[string]string{
						"type":  "regex",
						"value": ".*",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.0.filter.*", map[string]string{
						"type":  "package-type",
						"value": "Docker",
					}),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.name", testData["policy_name_0"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.type", "security"),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.1.name", testData["policy_name_1"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.1.type", "license"),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.2.name", testData["policy_name_2"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.2.type", "operational_risk"),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func makeSingleRepositoryTestCase(repoType string, t *testing.T) (*testing.T, resource.TestCase) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo_type"] = repoType
	testData["repo0"] = fmt.Sprintf("libs-release-%s-0-%d", repoType, testutil.RandomInt())

	return t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], repoType, "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, singleRepositoryWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.filter.*", map[string]string{
						"type":  "path-regex",
						"value": ".*",
					}),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	}
}

// To verify the watch for a single repo we need to create a new repository with Xray indexing enabled
// acctest.CreateRepos() is creating a repos with Xray indexing enabled using the API call
// We need to figure out how to use external providers (like Artifactory) in the tests. Documented approach didn't work
func TestAccWatch_singleRepository(t *testing.T) {
	for _, repoType := range []string{"local", "remote"} {
		t.Run(repoType, func(t *testing.T) {
			resource.Test(makeSingleRepositoryTestCase(repoType, t))
		})
	}
}

func TestAccWatch_singleRepositoryWithProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	repoKey := fmt.Sprintf("local-%d", testutil.RandomInt())
	projectKey := RandomProjectName()

	testData := sdk.MergeMaps(testDataWatch)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo_type"] = "local"
	testData["repo0"] = repoKey

	template := `resource "xray_security_policy" "security" {
	  name        = "{{ .policy_name_0 }}"
	  description = "Security policy description"
	  type        = "security"
	  rule {
	    name     = "rule-name-severity"
	    priority = 1
	    criteria {
	      min_severity = "High"
	    }
	    actions {
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
	  project_key   = "{{ .project_key }}"

	  watch_resource {
		type       	= "{{ .watch_type }}"
		bin_mgr_id  = "default"
		name		= "{{ .repo0 }}"
		repo_type   = "{{ .repo_type }}"
	  }
	  assigned_policy {
	  	name 	= xray_security_policy.security.name
	  	type 	= "security"
	  }
	  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
	}`

	config := util.ExecuteTemplate(fqrn, template, testData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, projectKey)
			acctest.CreateRepos(t, repoKey, "local", projectKey, "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, repoKey)
			acctest.DeleteProject(t, projectKey)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s:%s", testData["watch_name"], projectKey),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_singleRepoMimeTypeFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	repoType := "local"

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo0"] = fmt.Sprintf("libs-release-%s-0-%d", repoType, testutil.RandomInt())
	testData["repo_type"] = repoType
	testData["filter_type_0"] = "mime-type"
	testData["filter_value_0"] = "application/json"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], repoType, "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, singleRepositoryWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.filter.*", map[string]string{
						"type":  "mime-type",
						"value": "application/json",
					}),
				),
			},
		},
	})
}

func TestAccWatch_singleRepoKvFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	repoType := "local"

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo0"] = fmt.Sprintf("libs-release-%s-0-%d", repoType, testutil.RandomInt())
	testData["repo_type"] = repoType
	testData["kv_filter_type"] = "property"
	testData["kv_filter_key_0"] = "test-key-1"
	testData["kv_filter_value_0"] = "test-value-1"
	testData["kv_filter_key_1"] = "test-key-2"
	testData["kv_filter_value_1"] = "test-value-2"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], repoType, "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			return testCheckWatch(id, request)
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, kvFilters, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.kv_filter.*", map[string]string{
						"type":  "property",
						"key":   "test-key-1",
						"value": "test-value-1",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.kv_filter.*", map[string]string{
						"type":  "property",
						"key":   "test-key-2",
						"value": "test-value-2",
					}),
				),
			},
		},
	})
}

func TestAccWatch_repositoryMissingRepoType(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),

		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, singleRepositoryInvalidWatchTemplate, testData),
				ExpectError: regexp.MustCompile(`.*Attribute 'repo_type' not set when 'watch_resource\.type' is set to.*`),
			},
		},
	})
}

func TestAccWatch_multipleRepositories(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo_type"] = "local"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())
	testData["repo1"] = fmt.Sprintf("libs-release-local-1-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
			acctest.CreateRepos(t, testData["repo1"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.DeleteRepo(t, testData["repo1"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, multipleRepositoriesWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_multipleRepositoriesPathAntPatterns(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo_type"] = "local"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())
	testData["repo1"] = fmt.Sprintf("libs-release-local-1-%d", testutil.RandomInt())
	testData["repo2"] = fmt.Sprintf("libs-release-local-1-%d", testutil.RandomInt())
	testData["include_patterns0"] = "**/*.js"
	testData["exclude_patterns1"] = "**/*.txt"
	testData["include_patterns2"] = "**/*.jar"
	testData["exclude_patterns2"] = "**/*.md"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
			acctest.CreateRepos(t, testData["repo1"], "local", "", "")
			acctest.CreateRepos(t, testData["repo2"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.DeleteRepo(t, testData["repo1"])
			acctest.DeleteRepo(t, testData["repo2"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, pathAntPatterns, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", testData["watch_type"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.name", testData["policy_name_0"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.type", "security"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.path_ant_filter.*.include_patterns.*", testData["include_patterns0"]),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.path_ant_filter.*.exclude_patterns.*", testData["exclude_patterns1"]),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.path_ant_filter.*.exclude_patterns.*", testData["exclude_patterns2"]),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.path_ant_filter.*.include_patterns.*", testData["include_patterns2"]),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_PathAntPatternsError(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "build"
	testData["repo_type"] = "local"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())
	testData["repo1"] = fmt.Sprintf("libs-release-local-1-%d", testutil.RandomInt())
	testData["exclude_patterns0"] = "**/*.md"
	testData["include_patterns0"] = "**/*.js"
	testData["exclude_patterns1"] = "**/*.md"
	testData["include_patterns1"] = "**/*.js"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
			acctest.CreateRepos(t, testData["repo1"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.DeleteRepo(t, testData["repo1"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, pathAntPatterns, testData),
				ExpectError: regexp.MustCompile(".*attribute 'path_ant_filter' is set when 'watch_resource.type' is not set to.*"),
			},
		},
	})
}

func TestAccWatch_multipleRepositoriesKvFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "repository"
	testData["repo_type"] = "local"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())
	testData["repo1"] = fmt.Sprintf("libs-release-local-1-%d", testutil.RandomInt())
	testData["kv_filter_type"] = "property"
	testData["kv_filter_key_0"] = "test-key-1"
	testData["kv_filter_value_0"] = "test-value-1"
	testData["kv_filter_key_1"] = "test-key-2"
	testData["kv_filter_value_1"] = "test-value-2"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
			acctest.CreateRepos(t, testData["repo1"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.DeleteRepo(t, testData["repo1"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, multipleRepositoriesKvFilter, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", testData["watch_type"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.name", testData["policy_name_0"]),
					resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.type", "security"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.kv_filter.*", map[string]string{
						"type":  "property",
						"key":   testData["kv_filter_key_0"],
						"value": testData["kv_filter_value_0"],
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "watch_resource.*.kv_filter.*", map[string]string{
						"type":  "property",
						"key":   testData["kv_filter_key_1"],
						"value": testData["kv_filter_value_1"],
					}),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_KvFilterError(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "build"
	testData["repo_type"] = "local"
	testData["repo0"] = fmt.Sprintf("libs-release-local-0-%d", testutil.RandomInt())
	testData["kv_filter_type"] = "property"
	testData["kv_filter_key_0"] = "test-key-1"
	testData["kv_filter_value_0"] = "test-value-1"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, testData["repo0"], "local", "", "")
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteRepo(t, testData["repo0"])
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, kvFilters, testData),
				ExpectError: regexp.MustCompile(".*attribute 'kv_filter' is set when 'watch_resource.type' is not set to.*"),
			},
		},
	})
}

func TestAccWatch_build(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "build"
	testData["build_name0"] = fmt.Sprintf("release-pipeline-%d", testutil.RandomInt())
	testData["build_name1"] = fmt.Sprintf("release-pipeline1-%d", testutil.RandomInt())
	builds := []string{testData["build_name0"]}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateBuilds(t, builds, "")
		},
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, buildWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_buildWithProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	projectKey := RandomProjectName()

	testData := sdk.MergeMaps(testDataWatch)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "build"
	testData["build_name0"] = fmt.Sprintf("release-pipeline-%d", testutil.RandomInt())

	template := `resource "xray_security_policy" "security" {
	  name        = "{{ .policy_name_0 }}"
	  description = "Security policy description"
	  type        = "security"
	  rule {
	    name     = "rule-name-severity"
	    priority = 1
	    criteria {
	      min_severity = "High"
	    }
	    actions {
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
	  project_key   = "{{ .project_key }}"

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
	config := util.ExecuteTemplate(fqrn, template, testData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, projectKey)
			acctest.CreateBuilds(t, []string{testData["build_name0"]}, projectKey)
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteProject(t, projectKey)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s:%s", testData["watch_name"], projectKey),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allBuildsWithProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	projectKey := RandomProjectName()

	testData := sdk.MergeMaps(testDataWatch)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "all-builds"

	template := `resource "xray_security_policy" "security" {
	  name        = "{{ .policy_name_0 }}"
	  description = "Security policy description"
	  type        = "security"
	  rule {
	    name     = "rule-name-severity"
	    priority = 1
	    criteria {
	      min_severity = "High"
	    }
	    actions {
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
	  project_key   = "{{ .project_key }}"

	  watch_resource {
		type       	= "{{ .watch_type }}"
		bin_mgr_id  = "default"
		ant_filter {
			exclude_patterns = ["a*", "b*"]
			include_patterns = ["ab*"]
		}
		ant_filter {
			exclude_patterns = ["c*", "d*"]
			include_patterns = ["cd*"]
		}
	  }

	  assigned_policy {
	  	name 	= xray_security_policy.security.name
	  	type 	= "security"
	  }
	  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
	}`
	config := util.ExecuteTemplate(fqrn, template, testData)

	updatedTestData := sdk.MergeMaps(testData)
	updatedTestData["description"] = "New description"
	updatedConfig := util.ExecuteTemplate(fqrn, template, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, projectKey)
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteProject(t, projectKey)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				Config: updatedConfig,
				Check:  verifyXrayWatch(fqrn, updatedTestData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s:%s", testData["watch_name"], projectKey),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_multipleBuilds(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "build"
	testData["build_name0"] = fmt.Sprintf("release-pipeline-%d", testutil.RandomInt())
	testData["build_name1"] = fmt.Sprintf("release-pipeline1-%d", testutil.RandomInt())
	builds := []string{testData["build_name0"], testData["build_name1"]}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateBuilds(t, builds, "")
		},
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, multipleBuildsWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_allBuilds(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "all-builds"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allBuildsWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "a*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "b*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.include_patterns.*", "ab*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "c*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "d*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.include_patterns.*", "cd*"),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_invalidBuildFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, invalidBuildsWatchFilterTemplate, testData),
				ExpectError: regexp.MustCompile(`.*attribute 'ant_filter' is set when 'watch_resource.type' is not set to.*`),
			},
		},
	})
}

func TestAccWatch_allProjects(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "all-projects"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allProjectsWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "a*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "b*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.include_patterns.*", "ab*"),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_singleProject(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "project"
	testData["project_name_0"] = fmt.Sprintf("test-project-%d", testutil.RandomInt())
	testData["project_name_1"] = fmt.Sprintf("test-project-%d", testutil.RandomInt())
	testData["project_key_0"] = "test1"
	testData["project_key_1"] = "test2"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, testData["project_key_0"])
			acctest.CreateProject(t, testData["project_key_1"])
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteProject(t, testData["project_key_0"])
			acctest.DeleteProject(t, testData["project_key_1"])
			//watch created by TF, so it will be automatically deleted by DeleteContext function
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			return testCheckWatch(id, request)
		}),

		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, singleProjectWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_invalidProjectFilter(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "project"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{

				Config:      util.ExecuteTemplate(fqrn, invalidProjectWatchFilterTemplate, testData),
				ExpectError: regexp.MustCompile(`attribute 'ant_filter' is set when 'watch_resource.type' is not set to.*`),
			},
		},
	})
}

func TestAccWatch_allReleaseBundle(t *testing.T) {
	for _, watchType := range []string{"all-releaseBundles", "all-releaseBundlesV2"} {
		t.Run(watchType, func(t *testing.T) {
			resource.Test(allReleaseBundleTestCase(watchType, t))
		})
	}
}

func allReleaseBundleTestCase(watchType string, t *testing.T) (*testing.T, resource.TestCase) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = watchType

	return t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, allReleaseBundlesWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "a*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.exclude_patterns.*", "b*"),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.*.ant_filter.*.include_patterns.*", "ab*"),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	}
}

func TestAccWatch_singleReleaseBundle(t *testing.T) {
	// NOTE: can't test release bundle V2 due to no API to add release bundle to Xray scan index,
	// which is required before a watch with release bundle v2 can be created.
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["watch_type"] = "releaseBundle"
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["release_bundle_name"] = fmt.Sprintf("test-release-bundle-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "name", testCheckWatch),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, singleReleaseBundleWatchTemplate, testData),
				Check:  verifyXrayWatch(fqrn, testData),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

func TestAccWatch_gitRepository(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("watch-", "xray_watch")
	testData := sdk.MergeMaps(testDataWatch)

	testData["resource_name"] = resourceName
	testData["watch_name"] = fmt.Sprintf("xray-watch-%d", testutil.RandomInt())
	testData["policy_name_0"] = fmt.Sprintf("xray-policy-%d", testutil.RandomInt())
	testData["watch_type"] = "gitRepository"
	testData["git_repo_1"] = "github.com/attiasas/WebGoat.git"
	testData["git_repo_2"] = "gitlab.com"
	testData["exclude_patterns_1"] = "github.com/attiasas/flask-webgoat-test.git"
	testData["exclude_patterns_2"] = "github.com/attiasas/juice-shop.git"

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "name", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.CheckPolicyDeleted(testData["policy_name_0"], t, request)
			resp, err := testCheckWatch(id, request)
			return resp, err
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, gitRepositoryWatchTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyXrayWatch(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.0.name", testData["git_repo_1"]),
					resource.TestCheckResourceAttr(fqrn, "watch_resource.1.name", testData["git_repo_2"]),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.0.ant_filter.0.exclude_patterns.*", testData["exclude_patterns_1"]),
					resource.TestCheckTypeSetElemAttr(fqrn, "watch_resource.0.ant_filter.0.exclude_patterns.*", testData["exclude_patterns_2"]),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        testData["watch_name"],
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}

const allReposSinglePolicyWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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

const allReposPathAntFilterWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	path_ant_filter {
		exclude_patterns  	= ["{{ .exclude_patterns0 }}"]
		include_patterns	= ["{{ .include_patterns0 }}"]
	}
  }
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const allReposKvFilterWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
    type = "{{ .watch_type }}"

    kv_filter {
      type  = "property"
      key   = "{{ .kv_filter_key0 }}"
      value = "{{ .kv_filter_value0 }}"
    }
  }

  assigned_policy {
    name = xray_security_policy.security.name
    type = "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const allReposMultiplePoliciesWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  rule {
    name     = "License_rule"
    priority = 1
    criteria {
      allowed_licenses         = ["Apache-1.0", "Apache-2.0"]
      allow_unknown            = false
      multi_license_permissive = true
    }
    actions {
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

resource "xray_operational_risk_policy" "op-risk-policy" {
  name        = "{{ .policy_name_2 }}"
  description = "Operational risk policy description"
  type        = "operational_risk"
  rule {
    name     = "Op_risk_rule"
    priority = 1
    criteria {
      op_risk_min_risk = "Low"
    }
    actions {
      block_release_bundle_distribution   = false
      fail_build                         = true
      notify_watch_recipients            = false
      notify_deployer                    = false
      create_ticket_enabled              = false
      build_failure_grace_period_in_days = 5
      block_download {
        unscanned = false
        active    = true
      }
    }
  }
}

resource "xray_watch" "{{ .resource_name }}" {
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
    type = "{{ .watch_type }}"

	  filter {
		type  = "{{ .filter_type_0 }}"
		value = "{{ .filter_value_0 }}"
	  }
	
	  filter {
		type  = "{{ .filter_type_1 }}"
		value = "{{ .filter_value_1 }}"
	  }
	
	  filter {
		type  = "{{ .filter_type_2 }}"
		value = "{{ .filter_value_2 }}"
	  }

  }

  assigned_policy {
    name = xray_security_policy.security.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.license.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op-risk-policy.name
    type = "operational_risk"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const singleRepositoryWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	name		= "{{ .repo0 }}"
	repo_type   = "{{ .repo_type }}"
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

const singleRepositoryInvalidWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	name		= "{{ .repo0 }}"
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
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	name		= "{{ .repo0 }}"
	repo_type   = "{{ .repo_type }}"
	filter {
		type  	= "{{ .filter_type_0 }}"
		value	= "{{ .filter_value_0 }}"
	}
  }
  watch_resource {
	type       	= "repository"
	bin_mgr_id  = "default"
	name		= "{{ .repo1 }}"
	repo_type   = "{{ .repo_type }}"
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

const pathAntPatterns = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	name		= "{{ .repo0 }}"
	repo_type   = "{{ .repo_type }}"
	path_ant_filter {
		include_patterns	= ["{{ .include_patterns0 }}"]
	}
  }
  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .repo1 }}"
	repo_type   = "{{ .repo_type }}"
	path_ant_filter {
		exclude_patterns  	= ["{{ .exclude_patterns1 }}"]
	}
}
  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .repo2 }}"
	repo_type   = "{{ .repo_type }}"
	path_ant_filter {
		exclude_patterns  	= ["{{ .exclude_patterns2 }}"]
		include_patterns	= ["{{ .include_patterns2 }}"]
	}
}
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
}
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const kvFilters = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
	type       	= "{{ .watch_type }}"
	bin_mgr_id  = "default"
	name		= "{{ .repo0 }}"
	repo_type   = "{{ .repo_type }}"
    
    kv_filter {
      type  = "{{ .kv_filter_type }}"
      key   = "{{ .kv_filter_key_0 }}"
      value = "{{ .kv_filter_value_0 }}"
    }
	
    kv_filter {
      type  = "{{ .kv_filter_type }}"
      key   = "{{ .kv_filter_key_1 }}"
      value = "{{ .kv_filter_value_1 }}"
    }
  }

  assigned_policy {
    name = xray_security_policy.security.name
  	type = "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const multipleRepositoriesKvFilter = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
    type       = "{{ .watch_type }}"
    bin_mgr_id = "default"
    name       = "{{ .repo0 }}"
    repo_type  = "{{ .repo_type }}"

    kv_filter {
      type  = "{{ .kv_filter_type }}"
      key   = "{{ .kv_filter_key_0 }}"
      value = "{{ .kv_filter_value_0 }}"
    }
  }

  watch_resource {
    type       = "{{ .watch_type }}"
    bin_mgr_id = "default"
    name       = "{{ .repo1 }}"
    repo_type  = "{{ .repo_type }}"

    kv_filter {
      type  = "{{ .kv_filter_type }}"
      key   = "{{ .kv_filter_key_1 }}"
      value = "{{ .kv_filter_value_1 }}"
    }
  }

  assigned_policy {
    name = xray_security_policy.security.name
  	type = "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const buildWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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

const allBuildsWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	ant_filter {
		exclude_patterns = ["a*", "b*"]
		include_patterns = ["ab*"]
	}
	ant_filter {
		exclude_patterns = ["c*", "d*"]
		include_patterns = ["cd*"]
	}
  }

  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const invalidBuildsWatchFilterTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	type       	= "build"
	bin_mgr_id  = "default"
	ant_filter {
		exclude_patterns = ["a*", "b*"]
		include_patterns = ["ab*"]
	}
  }

  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const allProjectsWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	type       	= "all-projects"
	bin_mgr_id  = "default"
	ant_filter {
		exclude_patterns = ["a*", "b*"]
		include_patterns = ["ab*"]
	}
  }
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const singleProjectWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	type   = "project"
	name   = "{{ .project_key_0 }}"
  }
  watch_resource {
	type       	= "project"
	name 		= "{{ .project_key_1 }}"
  }
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const invalidProjectWatchFilterTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
	type = "project"
	name = "fake-project"
	ant_filter {
		exclude_patterns = ["a*"]
		include_patterns = ["b*"]
	}
  }

  assigned_policy {
  	name = xray_security_policy.security.name
  	type = "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const allReleaseBundlesWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	ant_filter {
		exclude_patterns = ["a*", "b*"]
		include_patterns = ["ab*"]
	}
  }
  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }
  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const gitRepositoryWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = {{ .active }}

  watch_resource {
    type       = "{{ .watch_type }}"
    bin_mgr_id = "default"
    name       = "{{ .git_repo_1 }}"
    
    ant_filter {
      exclude_patterns = ["{{ .exclude_patterns_1 }}", "{{ .exclude_patterns_2 }}"]
    }
  }

  watch_resource {
    type       = "{{ .watch_type }}"
    bin_mgr_id = "default"
    name       = "{{ .git_repo_2 }}"
  }

  assigned_policy {
    name = xray_security_policy.security.name
    type = "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

const singleReleaseBundleWatchTemplate = `resource "xray_security_policy" "security" {
  name        = "{{ .policy_name_0 }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
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
	type   = "releaseBundle"
	bin_mgr_id  = "default"
	name   = "{{ .release_bundle_name }}"
  }

  assigned_policy {
  	name 	= xray_security_policy.security.name
  	type 	= "security"
  }

  watch_recipients = ["{{ .watch_recipient_0 }}", "{{ .watch_recipient_1 }}"]
}`

func verifyXrayWatch(fqrn string, testData map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", testData["watch_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", testData["description"]),
		resource.TestCheckResourceAttr(fqrn, "watch_resource.0.type", testData["watch_type"]),
		resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.name", testData["policy_name_0"]),
		resource.TestCheckResourceAttr(fqrn, "assigned_policy.0.type", "security"),
	)
}

func checkWatch(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v2/watches/" + id)
}

func testCheckWatch(id string, request *resty.Request) (*resty.Response, error) {
	return checkWatch(id, request.AddRetryCondition(client.NeverRetry))
}

func RandomProjectName() string {
	return fmt.Sprintf("testproj%d", rand.Intn(100))
}
