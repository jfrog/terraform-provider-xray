package xray

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/jfrog/terraform-provider-shared/test"
	"github.com/jfrog/terraform-provider-shared/util"
)

func TestAccRepositoryConfigRepoConfigNegative(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    "repo-config-test-repo",
		"retention_in_days":            "90",
		"pattern0_include":             "core/**",
		"pattern0_exclude":             "core/external/**",
		"pattern0_index_new_artifacts": "true",
		"pattern0_retention_in_days":   "45",
		"pattern1_include":             "core/**",
		"pattern1_exclude":             "core/external/**",
		"pattern1_index_new_artifacts": "true",
		"pattern1_retention_in_days":   "45",
		"other_index_new_artifacts":    "true",
		"other_retention_in_days":      "60",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, TestDataRepoConfigErrorTemplate, testData),
				ExpectError: regexp.MustCompile("Conflicting configuration arguments"),
			},
		},
	})
}

func TestAccRepositoryConfigRepoConfigCreate(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name":     resourceName,
		"repo_name":         "repo-config-test-repo",
		"retention_in_days": "90",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccDeleteRepo(t, testData["repo_name"])
			testAccCreateRepos(t, testData["repo_name"], "local", "")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError(t)
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, TestDataRepoConfigTemplate, testData),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.retention_in_days", testData["retention_in_days"]),
				),
			},
		},
	})
}

func TestAccRepositoryConfigRepoPathsCreate(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    "repo-config-test-repo",
		"pattern0_include":             "core/**",
		"pattern0_exclude":             "core/external/**",
		"pattern0_index_new_artifacts": "true",
		"pattern0_retention_in_days":   "45",
		"pattern1_include":             "core/**",
		"pattern1_exclude":             "core/external/**",
		"pattern1_index_new_artifacts": "true",
		"pattern1_retention_in_days":   "45",
		"other_index_new_artifacts":    "true",
		"other_retention_in_days":      "60",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccDeleteRepo(t, testData["repo_name"])
			testAccCreateRepos(t, testData["repo_name"], "local", "")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError(t)
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testData),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testData)),
			},
		},
	})
}

func TestAccRepositoryConfigRepoPathsUpdate(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    "repo-config-test-repo",
		"pattern0_include":             "core/**",
		"pattern0_exclude":             "core/external/**",
		"pattern0_index_new_artifacts": "true",
		"pattern0_retention_in_days":   "45",
		"pattern1_include":             "core/**",
		"pattern1_exclude":             "core/external/**",
		"pattern1_index_new_artifacts": "true",
		"pattern1_retention_in_days":   "45",
		"other_index_new_artifacts":    "true",
		"other_retention_in_days":      "60",
	}
	var testDataUpdated = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    "repo-config-test-repo",
		"pattern0_include":             "core1/**",
		"pattern0_exclude":             "core1/external/**",
		"pattern0_index_new_artifacts": "false",
		"pattern0_retention_in_days":   "50",
		"pattern1_include":             "core1/**",
		"pattern1_exclude":             "core1/external/**",
		"pattern1_index_new_artifacts": "false",
		"pattern1_retention_in_days":   "50",
		"other_index_new_artifacts":    "false",
		"other_retention_in_days":      "70",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccDeleteRepo(t, testData["repo_name"])
			testAccCreateRepos(t, testData["repo_name"], "local", "")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError(t)
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testData),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testData)),
			},
			{
				Config: util.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testDataUpdated),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testDataUpdated)),
			},
		},
	})
}

func verifyRepositoryConfig(fqrn string, testData map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.0.include", testData["pattern0_include"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.0.exclude", testData["pattern0_exclude"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.0.index_new_artifacts", testData["pattern0_index_new_artifacts"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.0.retention_in_days", testData["pattern0_retention_in_days"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.1.include", testData["pattern1_include"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.1.exclude", testData["pattern1_exclude"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.1.index_new_artifacts", testData["pattern1_index_new_artifacts"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.pattern.1.retention_in_days", testData["pattern1_retention_in_days"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.all_other_artifacts.0.index_new_artifacts", testData["other_index_new_artifacts"]),
		resource.TestCheckResourceAttr(fqrn, "paths_config.0.all_other_artifacts.0.retention_in_days", testData["other_retention_in_days"]),
	)
}

const TestDataRepoConfigErrorTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  
  repo_name  = "{{ .repo_name }}"
  
  config {
    retention_in_days       = {{ .retention_in_days }} 
  }
  
  paths_config {
    
    pattern {
      include              = "{{ .pattern0_include }}"
      exclude              = "{{ .pattern0_exclude }}"
      index_new_artifacts  = {{ .pattern0_index_new_artifacts }}
      retention_in_days    = {{ .pattern0_retention_in_days }}
    }

   pattern {
      include              = "{{ .pattern1_include }}"
      exclude              = "{{ .pattern1_exclude }}"
      index_new_artifacts  = {{ .pattern1_index_new_artifacts }}
      retention_in_days    = {{ .pattern1_retention_in_days }}
    }
  
   all_other_artifacts {
      index_new_artifacts = {{ .other_index_new_artifacts }}
      retention_in_days   = {{ .other_retention_in_days }}
    }
  }
}`

const TestDataRepoConfigTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  
  repo_name  = "{{ .repo_name }}"
  
  config {
    #vuln_contextual_analysis  = true
    retention_in_days          = {{ .retention_in_days }} 
  }

}`

const TestDataRepoPathsConfigTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  
  repo_name  = "{{ .repo_name }}"

  paths_config {
    
    pattern {
      include              = "{{ .pattern0_include }}"
      exclude              = "{{ .pattern0_exclude }}"
      index_new_artifacts  = {{ .pattern0_index_new_artifacts }}
      retention_in_days    = {{ .pattern0_retention_in_days }}
    }

   pattern {
      include              = "{{ .pattern1_include }}"
      exclude              = "{{ .pattern1_exclude }}"
      index_new_artifacts  = {{ .pattern1_index_new_artifacts }}
      retention_in_days    = {{ .pattern1_retention_in_days }}
    }
  
   all_other_artifacts {
      index_new_artifacts = {{ .other_index_new_artifacts }}
      retention_in_days   = {{ .other_retention_in_days }}
    }
  }
}`
