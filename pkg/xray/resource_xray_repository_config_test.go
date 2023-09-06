package xray

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
)

func TestAccRepositoryConfigRepoNoConfig(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name": resourceName,
		"repo_name":     "repo-config-test-repo",
	}

	config := sdk.ExecuteTemplate(
		fqrn,
		`resource "xray_repository_config" "{{ .resource_name }}" {
			repo_name = "{{ .repo_name }}"
		}`,
		testData,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile("Missing required argument"),
			},
		},
	})
}

func TestAccRepositoryConfigRepoConfigCreate_VulnContextualAnalysis(t *testing.T) {
	testCase := []struct {
		packageType  string
		template     string
		validVersion string
	}{
		{"docker", TestDataRepoConfigDockerTemplate, "3.67.9"},
		{"maven", TestDataRepoConfigMavenTemplate, "3.77.4"},
	}

	version, err := sdk.GetXrayVersion(GetTestResty(t))
	if err != nil {
		t.Fail()
		return
	}

	for _, tc := range testCase {
		t.Run(tc.packageType, testAccRepositoryConfigRepoConfigCreate_VulnContextualAnalysis(t, tc.packageType, tc.template, tc.validVersion, version))
	}
}

func testAccRepositoryConfigRepoConfigCreate_VulnContextualAnalysis(t *testing.T, packageType, template, validVersion, xrayVersion string) func(t *testing.T) {
	return func(t *testing.T) {
		_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
		var testData = map[string]string{
			"resource_name":            resourceName,
			"repo_name":                "repo-config-test-repo",
			"retention_in_days":        "90",
			"vuln_contextual_analysis": "true",
			"services_scan":            "false",
			"secrets_scan":             "false",
			"applications_scan":        "false",
		}

		valid, _ := sdk.CheckVersion(xrayVersion, validVersion)
		if !valid {
			t.Skipf("xray version %s does not support %s for exposures scanning", xrayVersion, packageType)
			return
		}

		resource.Test(t, resource.TestCase{
			PreCheck: func() {
				testAccPreCheck(t)
				testAccDeleteRepo(t, testData["repo_name"])
				testAccCreateRepos(t, testData["repo_name"], "local", "", packageType)
			},
			CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
				testAccDeleteRepo(t, testData["repo_name"])
				err := fmt.Errorf("repo was deleted")
				errorResp := dummyError()
				return errorResp, err
			}),
			ProviderFactories: testAccProviders(),

			Steps: []resource.TestStep{
				{
					Config: sdk.ExecuteTemplate(fqrn, template, testData),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
						resource.TestCheckResourceAttr(fqrn, "config.0.retention_in_days", testData["retention_in_days"]),
						resource.TestCheckResourceAttr(fqrn, "config.0.vuln_contextual_analysis", testData["vuln_contextual_analysis"]),
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
}

func TestAccRepositoryConfigRepoConfigCreate_exposure(t *testing.T) {
	testCase := []struct {
		packageType  string
		template     string
		validVersion string
		checkFunc    func(fqrn string, testData map[string]string) resource.TestCheckFunc
	}{
		{
			"docker",
			TestDataRepoConfigDockerTemplate,
			"3.67.9",
			func(fqrn string, testData map[string]string) resource.TestCheckFunc {
				return resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.services", testData["services_scan"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.secrets", testData["secrets_scan"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.applications", testData["applications_scan"]),
				)
			},
		},
		{
			"maven",
			TestDataRepoConfigMavenTemplate,
			"3.78.9",
			func(fqrn string, testData map[string]string) resource.TestCheckFunc {
				return resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.secrets", testData["secrets_scan"]),
				)
			},
		},
		{
			"npm",
			TestDataRepoConfigNpmPyPiTemplate,
			"3.78.9",
			func(fqrn string, testData map[string]string) resource.TestCheckFunc {
				return resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.secrets", testData["secrets_scan"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.applications", testData["applications_scan"]),
				)
			},
		},
		{
			"pypi",
			TestDataRepoConfigNpmPyPiTemplate,
			"3.78.9",
			func(fqrn string, testData map[string]string) resource.TestCheckFunc {
				return resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.secrets", testData["secrets_scan"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.exposures.0.scanners_category.0.applications", testData["applications_scan"]),
				)
			},
		},
	}

	version, err := sdk.GetXrayVersion(GetTestResty(t))
	if err != nil {
		t.Fail()
		return
	}

	for _, tc := range testCase {
		t.Run(tc.packageType, testAccRepositoryConfigRepoConfigCreate(t, tc.packageType, tc.template, tc.validVersion, version, tc.checkFunc))
	}
}

func TestAccRepositoryConfigRepoConfigCreate_no_exposure(t *testing.T) {
	packageTypes := []string{"alpine", "bower", "composer", "conan", "conda", "debian", "gems", "generic", "go", "gradle", "ivy", "nuget", "rpm", "sbt"}
	template := `
	resource "xray_repository_config" "{{ .resource_name }}" {
		repo_name = "{{ .repo_name }}"

		config {
			retention_in_days = {{ .retention_in_days }}
		}
	}`
	validVersion := "3.75.10"
	version, err := sdk.GetXrayVersion(GetTestResty(t))
	if err != nil {
		t.Fail()
		return
	}

	checkFunc := func(fqrn string, testData map[string]string) resource.TestCheckFunc {
		return resource.ComposeTestCheckFunc(
			resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
			resource.TestCheckResourceAttr(fqrn, "config.0.retention_in_days", testData["retention_in_days"]),
			resource.TestCheckNoResourceAttr(fqrn, "config.0.vuln_contextual_analysis"),
			resource.TestCheckResourceAttr(fqrn, "config.0.exposures.#", "0"),
		)
	}

	for _, packageType := range packageTypes {
		t.Run(packageType, testAccRepositoryConfigRepoConfigCreate(t, packageType, template, validVersion, version, checkFunc))
	}
}

func testAccRepositoryConfigRepoConfigCreate(t *testing.T, packageType, template, validVersion, xrayVersion string, checkFunc func(fqrn string, testData map[string]string) resource.TestCheckFunc) func(t *testing.T) {
	return func(t *testing.T) {
		_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
		var testData = map[string]string{
			"resource_name":            resourceName,
			"repo_name":                "repo-config-test-repo",
			"retention_in_days":        "90",
			"vuln_contextual_analysis": "false",
			"services_scan":            "true",
			"secrets_scan":             "true",
			"applications_scan":        "true",
		}

		valid, _ := sdk.CheckVersion(xrayVersion, validVersion)
		if !valid {
			t.Skipf("xray version %s does not support %s for exposures scanning", xrayVersion, packageType)
			return
		}

		resource.Test(t, resource.TestCase{
			PreCheck: func() {
				testAccPreCheck(t)
				testAccDeleteRepo(t, testData["repo_name"])
				testAccCreateRepos(t, testData["repo_name"], "local", "", packageType)
			},
			CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
				testAccDeleteRepo(t, testData["repo_name"])
				err := fmt.Errorf("repo was deleted")
				errorResp := dummyError()
				return errorResp, err
			}),
			ProviderFactories: testAccProviders(),
			Steps: []resource.TestStep{
				{
					Config: sdk.ExecuteTemplate(fqrn, template, testData),
					Check:  checkFunc(fqrn, testData),
				},
				{
					ResourceName:      fqrn,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}
}

func TestAccRepositoryConfigRepoConfigCreate_InvalidExposures(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	var testData = map[string]string{
		"resource_name":     resourceName,
		"repo_name":         "repo-config-test-repo",
		"retention_in_days": "90",
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testAccDeleteRepo(t, testData["repo_name"])
			testAccCreateRepos(t, testData["repo_name"], "local", "", "docker")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError()
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config:             sdk.ExecuteTemplate(fqrn, TestDataRepoConfigInvalidExposuresTemplate, testData),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccRepositoryConfigRepoPathsCreate(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
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
			testAccCreateRepos(t, testData["repo_name"], "local", "", "")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError()
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config: sdk.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testData),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testData)),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRepositoryConfigRepoPathsUpdate(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
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
			testAccCreateRepos(t, testData["repo_name"], "local", "", "")
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			testAccDeleteRepo(t, testData["repo_name"])
			err := fmt.Errorf("repo was deleted")
			errorResp := dummyError()
			return errorResp, err
		}),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config: sdk.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testData),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testData)),
			},
			{
				Config: sdk.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testDataUpdated),
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

const TestDataRepoConfigDockerTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = "{{ .repo_name }}"

  config {
    retention_in_days        = {{ .retention_in_days }}
	vuln_contextual_analysis = {{ .vuln_contextual_analysis }}

	exposures {
      scanners_category {
        services     = true
        secrets      = true
        applications = true
      }
	}
  }
}`

const TestDataRepoConfigMavenTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = "{{ .repo_name }}"

  config {
    retention_in_days        = {{ .retention_in_days }}
	vuln_contextual_analysis = {{ .vuln_contextual_analysis }}

	exposures {
      scanners_category {
        secrets      = true
      }
	}
  }
}`

const TestDataRepoConfigNpmPyPiTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = "{{ .repo_name }}"

  config {
    retention_in_days = {{ .retention_in_days }}

	exposures {
      scanners_category {
        secrets      = true
        applications = true
      }
	}
  }
}`

const TestDataRepoConfigInvalidExposuresTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = "{{ .repo_name }}"

  config {
    vuln_contextual_analysis = true
    retention_in_days = {{ .retention_in_days }}
    exposures {
      scanners_category {
        iac = true
      }
    }
  }
}`

const TestDataRepoPathsConfigTemplate = `
resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = "{{ .repo_name }}"

  paths_config {
    pattern {
      include             = "{{ .pattern0_include }}"
      exclude             = "{{ .pattern0_exclude }}"
      index_new_artifacts = {{ .pattern0_index_new_artifacts }}
      retention_in_days   = {{ .pattern0_retention_in_days }}
    }

    pattern {
      include             = "{{ .pattern1_include }}"
      exclude             = "{{ .pattern1_exclude }}"
      index_new_artifacts = {{ .pattern1_index_new_artifacts }}
      retention_in_days   = {{ .pattern1_retention_in_days }}
    }

    all_other_artifacts {
      index_new_artifacts = {{ .other_index_new_artifacts }}
      retention_in_days   = {{ .other_retention_in_days }}
    }
  }
}`
