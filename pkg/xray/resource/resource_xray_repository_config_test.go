package xray_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

func TestAccRepositoryConfig_RepoNoConfig(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("local-generic", "artifactory_local_generic_repository")
	var testData = map[string]string{
		"resource_name": resourceName,
		"repo_name":     repoName,
	}

	config := util.ExecuteTemplate(
		fqrn,
		`resource "xray_repository_config" "{{ .resource_name }}" {
			repo_name = "{{ .repo_name }}"
		}`,
		testData,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile("Missing required argument"),
			},
		},
	})
}

// TestAccRepositoryConfig_JasDisabled needs to be run against a JPD that does not have JAS enabled
// Set JFROG_URL to this instance and set env var JFROG_JAS_DISABLED=true
func TestAccRepositoryConfig_JasDisabled(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) != "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is not set to 'true'")
	}

	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("local-generic-", "artifactory_local_generic_repository")

	var testData = map[string]string{
		"resource_name":     resourceName,
		"repo_name":         repoName,
		"retention_in_days": "90",
	}
	config := util.ExecuteTemplate(
		fqrn,
		`resource "artifactory_local_generic_repository" "{{ .repo_name }}" {
			key        = "{{ .repo_name }}"
			xray_index = true
		}

		resource "xray_repository_config" "{{ .resource_name }}" {
			repo_name   = "{{ .repo_name }}"
			jas_enabled = false

			config {
				retention_in_days = {{ .retention_in_days }}
			}
		}`,
		testData,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source:            "jfrog/artifactory",
				VersionConstraint: "10.1.2",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
					resource.TestCheckResourceAttr(fqrn, "config.0.retention_in_days", testData["retention_in_days"]),
				),
			},
		},
	})
}

// TestAccRepositoryConfig_JasDisabled_vulnContextualAnalysis_set needs to be run against a JPD that does not have JAS enabled
// Set JFROG_URL to this instance and set env var JFROG_JAS_DISABLED=true
func TestAccRepositoryConfig_JasDisabled_vulnContextualAnalysis_set(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) != "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is not set to 'true'")
	}

	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("local-generic", "artifactory_local_generic_repository")

	config := util.ExecuteTemplate(
		fqrn,
		`resource "xray_repository_config" "{{ .resource_name }}" {
			repo_name   = "{{ .repo_name }}"
			jas_enabled = false

			config {
				vuln_contextual_analysis = true
				retention_in_days = 90
			}
		}`,
		map[string]string{
			"resource_name": resourceName,
			"repo_name":     repoName,
		},
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,

		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`.*config\.vuln_contextual_analysis can not be set when jas_enabled is set to 'true'.*`),
			},
		},
	})
}

// TestAccRepositoryConfig_JasDisabled_exposures_set needs to be run against a JPD that does not have JAS enabled
// Set JFROG_URL to this instance and set env var JFROG_JAS_DISABLED=true
func TestAccRepositoryConfig_JasDisabled_exposures_set(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) != "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is not set to 'true'")
	}

	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")

	config := util.ExecuteTemplate(
		fqrn,
		`resource "xray_repository_config" "{{ .resource_name }}" {
			repo_name   = "repo-config-test-repo"
			jas_enabled = false

			config {
				retention_in_days = 90
				exposures {
					scanners_category {
						iac = true
					}
				}
			}
		}`,
		map[string]string{
			"resource_name": resourceName,
		},
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,

		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`.*config\.exposures can not be set when jas_enabled is set to 'true'.*`),
			},
		},
	})
}

func TestAccRepositoryConfig_RepoConfig_Create_VulnContextualAnalysis(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) == "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is set to 'true'")
	}

	testCase := []struct {
		packageType  string
		template     string
		validVersion string
	}{
		{"docker", TestDataRepoConfigDockerTemplate, "3.67.9"},
		{"maven", TestDataRepoConfigMavenTemplate, "3.77.4"},
	}

	version, err := util.GetXrayVersion(acctest.GetTestResty(t))
	if err != nil {
		t.Fail()
		return
	}

	for _, tc := range testCase {
		t.Run(tc.packageType, testAccRepositoryConfigRepoConfigCreate_VulnContextualAnalysis(tc.packageType, tc.template, tc.validVersion, version))
	}
}

func testAccRepositoryConfigRepoConfigCreate_VulnContextualAnalysis(packageType, template, validVersion, xrayVersion string) func(t *testing.T) {
	return func(t *testing.T) {
		_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
		_, _, repoName := testutil.MkNames("local-docker-v2", fmt.Sprintf("artifactory_local_%s_repository", packageType))
		var testData = map[string]string{
			"resource_name":            resourceName,
			"repo_name":                repoName,
			"retention_in_days":        "90",
			"vuln_contextual_analysis": "true",
			"services_scan":            "false",
			"secrets_scan":             "false",
			"applications_scan":        "false",
			"package_type":             packageType,
		}

		valid, _ := util.CheckVersion(xrayVersion, validVersion)
		if !valid {
			t.Skipf("xray version %s does not support %s for exposures scanning", xrayVersion, packageType)
			return
		}

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
			ExternalProviders: map[string]resource.ExternalProvider{
				"artifactory": {
					Source:            "jfrog/artifactory",
					VersionConstraint: "10.1.2",
				},
			},
			Steps: []resource.TestStep{
				{
					Config: util.ExecuteTemplate(fqrn, template, testData),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "repo_name", testData["repo_name"]),
						resource.TestCheckResourceAttr(fqrn, "config.0.retention_in_days", testData["retention_in_days"]),
						resource.TestCheckResourceAttr(fqrn, "config.0.vuln_contextual_analysis", testData["vuln_contextual_analysis"]),
					),
				},
				{
					ResourceName:      fqrn,
					ImportState:       true,
					ImportStateId:     fmt.Sprintf("%s:true", testData["repo_name"]),
					ImportStateVerify: true,
				},
			},
		})
	}
}

func TestAccRepositoryConfig_RepoConfigCreate_exposure(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) == "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is set to 'true'")
	}

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
					resource.TestCheckResourceAttr(fqrn, "jas_enabled", "true"),
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

	version, err := util.GetXrayVersion(acctest.GetTestResty(t))
	if err != nil {
		t.Fail()
		return
	}

	for _, tc := range testCase {
		t.Run(tc.packageType, testAccRepositoryConfigRepoConfigCreate(tc.packageType, tc.template, tc.validVersion, version, tc.checkFunc))
	}
}

func TestAccRepositoryConfig_RepoConfigCreate_no_exposure(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) == "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is set to 'true'")
	}

	packageTypes := []string{"alpine", "bower", "composer", "conan", "conda", "debian", "gems", "generic", "go", "gradle", "ivy", "nuget", "rpm", "sbt"}
	template := `
	resource "artifactory_local_{{ .package_type }}_repository" "{{ .repo_name }}" {
		key        = "{{ .repo_name }}"
		xray_index = true
		{{ if eq .package_type "debian" }}
		index_compression_formats = ["bz2"]
		{{ end }}
	}

	resource "xray_repository_config" "{{ .resource_name }}" {
		repo_name   = artifactory_local_{{ .package_type }}_repository.{{ .repo_name }}.key
		jas_enabled = true

		config {
			retention_in_days = {{ .retention_in_days }}
		}
	}`
	validVersion := "3.75.10"
	version, err := util.GetXrayVersion(acctest.GetTestResty(t))
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
		t.Run(packageType, testAccRepositoryConfigRepoConfigCreate(packageType, template, validVersion, version, checkFunc))
	}
}

func testAccRepositoryConfigRepoConfigCreate(packageType, template, validVersion, xrayVersion string, checkFunc func(fqrn string, testData map[string]string) resource.TestCheckFunc) func(t *testing.T) {
	return func(t *testing.T) {
		_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
		_, _, repoName := testutil.MkNames("test-local", fmt.Sprintf("artifactory_local_%s_repository", packageType))
		var testData = map[string]string{
			"resource_name":            resourceName,
			"repo_name":                repoName,
			"retention_in_days":        "90",
			"vuln_contextual_analysis": "false",
			"services_scan":            "true",
			"secrets_scan":             "true",
			"applications_scan":        "true",
			"package_type":             packageType,
		}

		valid, _ := util.CheckVersion(xrayVersion, validVersion)
		if !valid {
			t.Skipf("xray version %s does not support %s for exposures scanning", xrayVersion, packageType)
			return
		}

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctest.PreCheck(t) },
			ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
			ExternalProviders: map[string]resource.ExternalProvider{
				"artifactory": {
					Source:            "jfrog/artifactory",
					VersionConstraint: "10.1.2",
				},
			},
			Steps: []resource.TestStep{
				{
					Config: util.ExecuteTemplate(fqrn, template, testData),
					Check:  checkFunc(fqrn, testData),
				},
				{
					ResourceName:      fqrn,
					ImportState:       true,
					ImportStateId:     fmt.Sprintf("%s:true", testData["repo_name"]),
					ImportStateVerify: true,
				},
			},
		})
	}
}

func TestAccRepositoryConfig_RepoConfigCreate_InvalidExposures(t *testing.T) {
	jasDisabled := os.Getenv("JFROG_JAS_DISABLED")
	if strings.ToLower(jasDisabled) == "true" {
		t.Skipf("Env var JFROG_JAS_DISABLED is set to 'true'")
	}

	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("local-docker-v2", "artifactory_local_docker_v2_repository")
	var testData = map[string]string{
		"resource_name":     resourceName,
		"repo_name":         repoName,
		"retention_in_days": "90",
		"package_type":      "docker_v2",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source:            "jfrog/artifactory",
				VersionConstraint: "10.1.2",
			},
		},
		Steps: []resource.TestStep{
			{
				Config:             util.ExecuteTemplate(fqrn, TestDataRepoConfigInvalidExposuresTemplate, testData),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccRepositoryConfig_RepoPathsCreate(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("generic-local", "artifactory_local_generic_repository")

	var testData = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    repoName,
		"jas_enabled":                  "false",
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
		"package_type":                 "generic",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source:            "jfrog/artifactory",
				VersionConstraint: "10.1.2",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, TestDataRepoPathsConfigTemplate, testData),
				Check:  resource.ComposeTestCheckFunc(verifyRepositoryConfig(fqrn, testData)),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("%s:false", testData["repo_name"]),
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRepositoryConfig_RepoPathsUpdate(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("xray-repo-config-", "xray_repository_config")
	_, _, repoName := testutil.MkNames("generic-local", "artifactory_local_generic_repository")

	var testData = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    repoName,
		"jas_enabled":                  "false",
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
		"package_type":                 "generic",
	}
	var testDataUpdated = map[string]string{
		"resource_name":                resourceName,
		"repo_name":                    repoName,
		"jas_enabled":                  "false",
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
		"package_type":                 "generic",
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source:            "jfrog/artifactory",
				VersionConstraint: "10.1.2",
			},
		},
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
		resource.TestCheckResourceAttr(fqrn, "jas_enabled", testData["jas_enabled"]),
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
resource "artifactory_local_docker_v2_repository" "{{ .repo_name }}" {
	key        = "{{ .repo_name }}"
	xray_index = true
}

resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name   = artifactory_local_docker_v2_repository.{{ .repo_name }}.key
  jas_enabled = true

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
resource "artifactory_local_maven_repository" "{{ .repo_name }}" {
	key        = "{{ .repo_name }}"
	xray_index = true
}

resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = artifactory_local_maven_repository.{{ .repo_name }}.key
  jas_enabled = true

  config {
    retention_in_days        = {{ .retention_in_days }}
	vuln_contextual_analysis = {{ .vuln_contextual_analysis }}

	exposures {
      scanners_category {
        secrets = true
      }
	}
  }
}`

const TestDataRepoConfigNpmPyPiTemplate = `
resource "artifactory_local_{{ .package_type }}_repository" "{{ .repo_name }}" {
	key        = "{{ .repo_name }}"
	xray_index = true
}

resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = artifactory_local_{{ .package_type }}_repository.{{ .repo_name }}.key
  jas_enabled = true

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
resource "artifactory_local_{{ .package_type }}_repository" "{{ .repo_name }}" {
	key        = "{{ .repo_name }}"
	xray_index = true
}

resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = artifactory_local_{{ .package_type }}_repository.{{ .repo_name }}.key
  jas_enabled = true

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
resource "artifactory_local_{{ .package_type }}_repository" "{{ .repo_name }}" {
	key        = "{{ .repo_name }}"
	xray_index = true
}

resource "xray_repository_config" "{{ .resource_name }}" {
  repo_name = artifactory_local_{{ .package_type }}_repository.{{ .repo_name }}.key

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
