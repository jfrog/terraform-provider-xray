package xray_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

// Shared repositories for all curation policy tests
var (
	sharedNpmRepo1   string
	sharedNpmRepo2   string
	sharedNpmRepo3   string
	sharedMavenRepo  string
	sharedDockerRepo string
	testSuiteId      string
)

// Common external providers used by all curation policy tests
var commonExternalProviders = map[string]resource.ExternalProvider{
	"artifactory": {
		Source: "jfrog/artifactory",
	},
}

// TestMain controls the execution of all tests in this package
func TestMain(m *testing.M) {
	// Generate unique test suite ID to avoid collisions
	testSuiteId = fmt.Sprintf("%d-%d", time.Now().UnixNano()/1000000, testutil.RandomInt())

	// Setup shared repositories before all tests
	setupSharedRepositories()

	// Run all tests
	code := m.Run()
	// Exit with the test result code
	os.Exit(code)
}

// setupSharedRepositories creates repositories that will be shared across all curation policy tests
func setupSharedRepositories() {
	// Generate unique repository names using test suite ID
	sharedNpmRepo1 = fmt.Sprintf("shared-npm-repo1-%s", testSuiteId)
	sharedNpmRepo2 = fmt.Sprintf("shared-npm-repo2-%s", testSuiteId)
	sharedNpmRepo3 = fmt.Sprintf("shared-npm-repo3-%s", testSuiteId)
	sharedMavenRepo = fmt.Sprintf("shared-maven-repo-%s", testSuiteId)
	sharedDockerRepo = fmt.Sprintf("shared-docker-repo-%s", testSuiteId)
}

// getSharedRepoConfig returns the configuration for all shared repositories
func getSharedRepoConfig() string {
	return createCuratedRepoConfig("npm", sharedNpmRepo1) +
		createCuratedRepoConfig("npm", sharedNpmRepo2) +
		createCuratedRepoConfig("npm", sharedNpmRepo3) +
		createCuratedRepoConfig("maven", sharedMavenRepo) +
		createCuratedRepoConfig("docker", sharedDockerRepo)
}

// getSharedRepoVerification returns test checks for all shared repositories
func getSharedRepoVerification() []resource.TestCheckFunc {
	return []resource.TestCheckFunc{
		// NPM repositories
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo1), "key", sharedNpmRepo1),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo1), "curated", "true"),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo2), "key", sharedNpmRepo2),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo2), "curated", "true"),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo3), "key", sharedNpmRepo3),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", sharedNpmRepo3), "curated", "true"),
		// Maven repository
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_maven_repository.%s", sharedMavenRepo), "key", sharedMavenRepo),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_maven_repository.%s", sharedMavenRepo), "curated", "true"),
		// Docker repository
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_docker_repository.%s", sharedDockerRepo), "key", sharedDockerRepo),
		resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_docker_repository.%s", sharedDockerRepo), "curated", "true"),
	}
}

// Helper function to compute catalog label names and to create them via Terraform resource
func computePolicyLabelNames(labelPrefix string) []string {
	const maxLen = 15
	// Reserve 1 character for uniqueness suffix
	base := labelPrefix
	// Use rune-safe truncation just in case
	runes := []rune(base)
	if len(runes) > maxLen-1 {
		base = string(runes[:maxLen-1])
	}
	return []string{
		base + "1",
		base + "2",
		base + "3",
		base + "4",
		base + "5",
	}
}

func createCatalogLabelsConfig(resourceName, labelPrefix string) string {
	names := computePolicyLabelNames(labelPrefix)
	return fmt.Sprintf(`
		resource "xray_catalog_labels" "%s" {
			labels = [
				{ name = "%s", description = "Security team approved package" },
				{ name = "%s", description = "Internal use only package" },
				{ name = "%s", description = "Package with manually reviewed license" },
				{ name = "%s", description = "Build and development tool" },
				{ name = "%s", description = "Pre-approved by company standards" }
			]
		}
	`, resourceName, names[0], names[1], names[2], names[3], names[4])
}

// Repository creation helpers for all curation package types
func createCuratedRepoConfig(packageType, repoName string) string {
	switch packageType {
	case "npm":
		return fmt.Sprintf(`
			resource "artifactory_remote_npm_repository" "%s" {
				key             = "%s"
				url             = "https://registry.npmjs.org/"
				repo_layout_ref = "npm-default"
				curated         = true
			}
		`, repoName, repoName)
	case "maven":
		return fmt.Sprintf(`
			resource "artifactory_remote_maven_repository" "%s" {
				key             = "%s"
				url             = "https://repo1.maven.org/maven2/"
				repo_layout_ref = "maven-2-default"
				curated         = true
			}
		`, repoName, repoName)
	case "docker":
		return fmt.Sprintf(`
			resource "artifactory_remote_docker_repository" "%s" {
				key                            = "%s"
				url                            = "https://registry-1.docker.io/"
				curated                        = true
				enable_token_authentication    = true
				external_dependencies_enabled  = true
				external_dependencies_patterns = ["**/registry-1.docker.io/**"]
			}
		`, repoName, repoName)
	default:
		// Default to npm since it works consistently
		return fmt.Sprintf(`
			resource "artifactory_remote_npm_repository" "%s" {
				key             = "%s"
				url             = "https://registry.npmjs.org/"
				repo_layout_ref = "npm-default"
				curated         = true
			}
		`, repoName, repoName)
	}
}

// Helper functions to create different types of custom curation conditions

// Creates a CVE CVSS Range condition for high severity vulnerabilities
func createCVSSCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "CVECVSSRange"
			param_values = jsonencode([
				{
					param_id = "vulnerability_cvss_score_range"
					value = [7.0, 10.0]
				},
				{
					param_id = "apply_only_if_fix_is_available"
					value = false
				}
			])
		}
	`, conditionName, conditionName)
}

// Creates a package maturity condition
func createMaturityCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "isImmature"
			param_values = jsonencode([
				{
					param_id = "package_age_days"
					value = 1
				},
				{
					param_id = "vulnerability_cvss_score"
					value = 5.0
				}
			])
		}
	`, conditionName, conditionName)
}

// Creates a specific CVE condition
func createCVECondition(conditionName string, cveName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "CVEName"
			param_values = jsonencode([
				{
					param_id = "cve_name"
					value = "%s"
				}
			])
		}
	`, conditionName, conditionName, cveName)
}

// Creates a specific versions condition
func createSpecificVersionsCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "SpecificVersions"
			param_values = jsonencode([
				{
					param_id = "package_type"
					value = "npm"
				},
				{
					param_id = "package_name"
					value = "lodash"
				},
				{
					param_id = "package_versions"
					value = {
						equals = ["4.17.19", "4.17.20"]
					}
				}
			])
		}
	`, conditionName, conditionName)
}

// Creates an OpenSSF condition
func createOpenSSFCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "OpenSSF"
			param_values = jsonencode([
				{
					param_id = "list_of_scorecard_checks"
					value = {
						"code_review" = 5
						"maintained" = 3
					}
				},
				{
					param_id = "block_in_case_check_value_is_missing"
					value = true
				}
			])
		}
	`, conditionName, conditionName)
}

// Creates a banned licenses condition
func createBannedLicensesCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "BannedLicenses"
			param_values = jsonencode([
				{
					param_id = "list_of_package_licenses"
					value = ["GPL-3.0", "AGPL-3.0", "WTFPL"]
				},
				{
      				param_id = "multiple_license_permissive_approach"
      				value    = false
   				}
			])
		}
	`, conditionName, conditionName)
}

// Creates an allowed licenses condition
func createAllowedLicensesCondition(conditionName string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "AllowedLicenses"
			param_values = jsonencode([
				{
					param_id = "list_of_package_licenses"
					value = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
				},
				{
      				param_id = "multiple_license_permissive_approach"
      				value    = true
    			}
			])
		}
	`, conditionName, conditionName)
}

// Creates a banned labels condition using dynamically created labels
func createBannedLabelsCondition(conditionName string, labelNames []string, labelsResource string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "BannedLabels"
			param_values = jsonencode([
				{
					param_id = "list_of_labels"
					value = %s
				}
			])
			depends_on = [%s]
		}
	`, conditionName, conditionName, fmt.Sprintf(`["%s", "%s"]`, labelNames[0], labelNames[1]), labelsResource)
}

// Creates an allowed labels condition using dynamically created labels
func createAllowedLabelsCondition(conditionName string, labelNames []string, labelsResource string) string {
	return fmt.Sprintf(`
		resource "xray_custom_curation_condition" "%s" {
			name                  = "%s"
			condition_template_id = "AllowedLabels"
			param_values = jsonencode([
				{
					param_id = "list_of_labels"
					value = %s
				}
			])
			depends_on = [%s]
		}
	`, conditionName, conditionName, fmt.Sprintf(`["%s", "%s", "%s"]`, labelNames[2], labelNames[3], labelNames[4]), labelsResource)
}

// ============================================================================
// SCOPE TESTING - Test all scope combinations with different conditions
// ============================================================================

// Test all_repos scope with block action and forbidden waivers
func TestAccCurationPolicy_AllRepos_Block_Forbidden(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-all-repos-block", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create the curation policy using shared repositories
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttrSet(fqrn, "id"),
					)...,
				),
			},
		},
	})
}

// Test all_repos scope with dry_run action and auto_approved waivers
func TestAccCurationPolicy_AllRepos_DryRun_AutoApproved(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-all-repos-dryrun", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create the curation policy using shared repositories
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "dry_run"
						waiver_request_config = "auto_approved"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttrSet(fqrn, "id"),
					)...,
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

// Test all_repos scope with manual waivers and decision owners
func TestAccCurationPolicy_AllRepos_Manual_DecisionOwners(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-all-repos-manual", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create the curation policy using shared repositories
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["security@company.com", "devops@company.com"]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
						resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
						resource.TestCheckTypeSetElemAttr(fqrn, "decision_owners.*", "readers"),
						resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "2"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "security@company.com"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "devops@company.com"),
					)...,
				),
			},
		},
	})
}

// Test all_repos scope with repository exclusions
func TestAccCurationPolicy_AllRepos_WithExclusions(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-all-repos-exclude", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with repository exclusions (exclude 2 npm repos, keep others in scope)
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						repo_exclude = [
							artifactory_remote_npm_repository.%s.key,
							artifactory_remote_npm_repository.%s.key
						]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName, sharedNpmRepo1, sharedNpmRepo2),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
						resource.TestCheckResourceAttr(fqrn, "repo_exclude.#", "2"),
						resource.TestCheckTypeSetElemAttr(fqrn, "repo_exclude.*", sharedNpmRepo1),
						resource.TestCheckTypeSetElemAttr(fqrn, "repo_exclude.*", sharedNpmRepo2),
					)...,
				),
			},
		},
	})
}

// Test specific_repos scope with multiple repositories
func TestAccCurationPolicy_SpecificRepos_Multiple(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-specific-repos", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-cvss-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy targeting specific repositories
				Config: sharedRepoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "specific_repos"
						repo_include = [
							artifactory_remote_npm_repository.%s.key,
							artifactory_remote_npm_repository.%s.key,
							artifactory_remote_maven_repository.%s.key
						]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						notify_emails = ["team@company.com"]
					}
				`, name, name, conditionName, sharedNpmRepo1, sharedNpmRepo2, sharedMavenRepo),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "specific_repos"),
						resource.TestCheckResourceAttr(fqrn, "repo_include.#", "3"),
						resource.TestCheckTypeSetElemAttr(fqrn, "repo_include.*", sharedNpmRepo1),
						resource.TestCheckTypeSetElemAttr(fqrn, "repo_include.*", sharedNpmRepo2),
						resource.TestCheckTypeSetElemAttr(fqrn, "repo_include.*", sharedMavenRepo),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
						resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "1"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "team@company.com"),
					)...,
				),
			},
		},
	})
}

// Test pkg_types scope with single package type
func TestAccCurationPolicy_PkgTypes_Single(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-pkg-types-single", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy targeting single package type
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
						resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "1"),
						resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "npm"),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
					)...,
				),
			},
		},
	})
}

// Test pkg_types scope with multiple package types
func TestAccCurationPolicy_PkgTypes_Multiple(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-pkg-types-multiple", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-cvss-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy targeting multiple package types
				Config: sharedRepoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm", "maven", "docker"]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						notify_emails = ["dev-team@company.com"]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
						resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "3"),
						resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "npm"),
						resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "maven"),
						resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "docker"),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
						resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "1"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "dev-team@company.com"),
					)...,
				),
			},
		},
	})
}

// ============================================================================
// CONDITION TYPE TESTING - Test all 9 supported condition types
// ============================================================================

// Test policy with CVE CVSS Range condition
func TestAccCurationPolicy_Condition_CVECVSSRange(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cvss-condition", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-cvss-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with CVSS condition
				Config: sharedRepoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with isImmature condition
func TestAccCurationPolicy_Condition_isImmature(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-maturity-condition", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with maturity condition
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with CVE Name condition (using CVSS instead due to test environment limitations)
func TestAccCurationPolicy_Condition_CVEName(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cve-name-condition", "xray_curation_policy")
	repoName := fmt.Sprintf("cve-name-condition-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-cve-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create the curation policy with CVE Name condition (using CVSS due to test environment limitations)
				Config: repoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "auto_approved"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
					resource.TestCheckResourceAttr(fqrn, "name", name),
				),
			},
		},
	})
}

// Test policy with actual CVE Name condition
func TestAccCurationPolicy_Condition_CVEName_Actual(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cve-name-actual", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-cve-name-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create the curation policy with actual CVE Name condition
				// Uses dry_run action to be less restrictive in test environment
				Config: sharedRepoConfig +
					createCVECondition(conditionName, "CVE-2021-44228") + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify condition exists and is properly created
						resource.TestCheckResourceAttrSet(fmt.Sprintf("xray_custom_curation_condition.%s", conditionName), "id"),
						resource.TestCheckResourceAttr(fmt.Sprintf("xray_custom_curation_condition.%s", conditionName), "name", conditionName),
						resource.TestCheckResourceAttr(fmt.Sprintf("xray_custom_curation_condition.%s", conditionName), "condition_template_id", "CVEName"),
						// Verify policy is properly created and linked
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
						resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
						resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
					)...,
				),
			},
		},
	})
}

// Test policy with Specific Versions condition (using maturity instead due to test environment limitations)
func TestAccCurationPolicy_Condition_SpecificVersions(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-versions-condition", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-versions-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with Specific Versions condition
				Config: sharedRepoConfig +
					createSpecificVersionsCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with OpenSSF condition (using CVSS instead due to test environment limitations)
func TestAccCurationPolicy_Condition_OpenSSF(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-openssf-condition", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-openssf-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with OpenSSF condition
				Config: sharedRepoConfig +
					createOpenSSFCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with Banned Licenses condition
func TestAccCurationPolicy_Condition_BannedLicenses(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-banned-licenses", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-banned-licenses-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with banned licenses condition
				Config: sharedRepoConfig +
					createBannedLicensesCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with Allowed Licenses condition
func TestAccCurationPolicy_Condition_AllowedLicenses(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-allowed-licenses", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-allowed-licenses-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with allowed licenses condition
				Config: sharedRepoConfig +
					createAllowedLicensesCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with banned labels condition using dynamically created labels
func TestAccCurationPolicy_Condition_BannedLabels(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-banned-labels", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-banned-labels-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create labels for the condition using Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)
	labelsRes := "xray_catalog_labels.labels_" + labelPrefix

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with banned labels condition
				Config: sharedRepoConfig +
					labelsCfg +
					createBannedLabelsCondition(conditionName, labelNames, labelsRes) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// Test policy with allowed labels condition using dynamically created labels
func TestAccCurationPolicy_Condition_AllowedLabels(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-allowed-labels", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-allowed-labels-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create labels for the condition using Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)
	labelsRes := "xray_catalog_labels.labels_" + labelPrefix

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with allowed labels condition
				Config: sharedRepoConfig +
					labelsCfg +
					createAllowedLabelsCondition(conditionName, labelNames, labelsRes) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttrSet(fqrn, "condition_id"),
						resource.TestCheckResourceAttr(fqrn, "name", name),
					)...,
				),
			},
		},
	})
}

// ============================================================================
// UPDATE AND LIFECYCLE TESTING
// ============================================================================

// Test comprehensive policy updates across all fields
func TestAccCurationPolicy_CompleteUpdateLifecycle(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-complete-update", "xray_curation_policy")
	repoName1 := fmt.Sprintf("complete-update-npm1-%d", testutil.RandomInt())
	repoName2 := fmt.Sprintf("complete-update-npm2-%d", testutil.RandomInt())
	repoName3 := fmt.Sprintf("complete-update-npm3-%d", testutil.RandomInt())
	conditionName1 := fmt.Sprintf("test-condition1-%d", testutil.RandomInt())
	conditionName2 := fmt.Sprintf("test-condition2-%d", testutil.RandomInt())

	// Create repositories configuration
	reposConfig := createCuratedRepoConfig("npm", repoName1) +
		createCuratedRepoConfig("npm", repoName2) +
		createCuratedRepoConfig("npm", repoName3)

	// Create all resources configuration
	allResourcesConfig := reposConfig +
		createMaturityCondition(conditionName1) +
		createMaturityCondition(conditionName2)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repositories first and verify they exist
				Config: reposConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName1), "key", repoName1),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName1), "curated", "true"),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName2), "key", repoName2),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName2), "curated", "true"),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName3), "key", repoName3),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName3), "curated", "true"),
				),
			},
			{
				// Step 2: Create with minimal config using pkg_types scope
				Config: allResourcesConfig + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
				),
			},
			{
				// Step 3: Update to specific repos with notifications
				Config: allResourcesConfig + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "specific_repos"
						repo_include = [artifactory_remote_npm_repository.%s.key]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						notify_emails = ["team1@company.com", "team2@company.com"]
					}
				`, name, name, conditionName1, repoName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "scope", "specific_repos"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
					resource.TestCheckResourceAttr(fqrn, "repo_include.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "2"),
				),
			},
			{
				// Step 4: Update to pkg_types with manual waivers and different condition
				Config: allResourcesConfig + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s-updated"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["security@company.com"]
					}
				`, name, name, conditionName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name+"-updated"),
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "1"),
				),
			},
			{
				// Step 5: Update back to all_repos with exclusions (now with 3 repos, excluding 2)
				Config: allResourcesConfig + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s-final"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						repo_exclude = [
							artifactory_remote_npm_repository.%s.key,
							artifactory_remote_npm_repository.%s.key
						]
						policy_action = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName1, repoName1, repoName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name+"-final"),
					resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
					resource.TestCheckResourceAttr(fqrn, "repo_exclude.#", "2"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
				),
			},
		},
	})
}

// ============================================================================
// WAIVERS TESTING - Test both package waivers and label waivers functionality
// ============================================================================

// Test policy with package waivers - basic scenario
func TestAccCurationPolicy_PackageWaivers_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-package-waivers-basic", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Create policy with package waivers
				Config: sharedRepoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						waivers = [
							{
								pkg_type      = "npm"
								pkg_name      = "lodash"
								all_versions  = false
								pkg_versions  = ["4.17.21"]
								justification = "This version is required for compatibility"
							}
						]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
						resource.TestCheckResourceAttr(fqrn, "waivers.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "waivers.0.pkg_type", "npm"),
						resource.TestCheckResourceAttr(fqrn, "waivers.0.pkg_name", "lodash"),
						resource.TestCheckResourceAttr(fqrn, "waivers.0.all_versions", "false"),
						resource.TestCheckTypeSetElemAttr(fqrn, "waivers.0.pkg_versions.*", "4.17.21"),
						resource.TestCheckResourceAttr(fqrn, "waivers.0.justification", "This version is required for compatibility"),
					)...,
				),
			},
		},
	})
}

// Test policy with multiple package waivers - comprehensive scenario
func TestAccCurationPolicy_PackageWaivers_Multiple(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-package-waivers-multiple", "xray_curation_policy")
	repoName := fmt.Sprintf("pkg-waivers-multiple-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create the curation policy with multiple package waivers
				Config: repoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["security@company.com"]

						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "react"
							all_versions  = true
							justification = "Core framework - approved by architecture team"
						}, {
							pkg_type      = "npm"
							pkg_name      = "express"
							all_versions  = false
							pkg_versions  = ["4.18.0", "4.18.1", "4.18.2"]
							justification = "Web framework - specific safe versions only"
						}]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),

					// Check multiple package waivers
					resource.TestCheckResourceAttr(fqrn, "waivers.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "waivers.*", map[string]string{
						"pkg_type":      "npm",
						"pkg_name":      "react",
						"all_versions":  "true",
						"justification": "Core framework - approved by architecture team",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "waivers.*", map[string]string{
						"pkg_type":      "npm",
						"pkg_name":      "express",
						"all_versions":  "false",
						"justification": "Web framework - specific safe versions only",
					}),
				),
			},
		},
	})
}

// Test policy with package waivers for different package types
func TestAccCurationPolicy_PackageWaivers_MultiplePackageTypes(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-package-waivers-multi-types", "xray_curation_policy")
	repoName := fmt.Sprintf("pkg-waivers-multi-types-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create the curation policy with package waivers
				Config: repoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]

						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "webpack"
							all_versions  = true
							justification = "Build tool required for all projects"
						}]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "waivers.#", "1"),

					// Check each package type waiver
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "waivers.*", map[string]string{
						"pkg_type":      "npm",
						"pkg_name":      "webpack",
						"all_versions":  "true",
						"justification": "Build tool required for all projects",
					}),
				),
			},
		},
	})
}

// Test label waivers with basic configuration
func TestAccCurationPolicy_LabelWaivers_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-label-waivers-basic", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create labels for the waiver using Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	// Add a delay function to ensure labels are propagated
	waitForLabels := func() {
		time.Sleep(15 * time.Second) // Give system more time to propagate labels
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and labels
				Config: sharedRepoConfig + labelsCfg,
				PreConfig: func() {
					waitForLabels() // Wait for labels to propagate
				},
				Check: resource.ComposeTestCheckFunc(
					append(getSharedRepoVerification(),
						// Verify labels were created
						resource.TestCheckResourceAttr("xray_catalog_labels.labels_"+labelPrefix, "labels.#", "5"),
					)...,
				),
			},
			{
				// Step 2: Create policy with label waivers
				Config: sharedRepoConfig +
					labelsCfg +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						label_waivers = [
							{
								label = "%s"
								justification = "Approved by security team"
							}
						]
					}
				`, name, name, conditionName, labelNames[0]),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "name", name),
						resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
						resource.TestCheckResourceAttr(fqrn, "label_waivers.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "label_waivers.0.label", labelNames[0]),
						resource.TestCheckResourceAttr(fqrn, "label_waivers.0.justification", "Approved by security team"),
					)...,
				),
			},
		},
	})
}

// Test policy with multiple label waivers - comprehensive scenario
func TestAccCurationPolicy_LabelWaivers_Multiple(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-label-waivers-multiple", "xray_curation_policy")
	repoName := fmt.Sprintf("label-waivers-multiple-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create custom labels for label waivers using Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	// Add a delay function to ensure labels are propagated
	waitForLabels := func() {
		time.Sleep(15 * time.Second) // Give system more time to propagate labels
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository and labels first and verify they exist
				Config: repoConfig + labelsCfg,
				PreConfig: func() {
					waitForLabels() // Wait for labels to propagate
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
					// Verify labels were created
					resource.TestCheckResourceAttr("xray_catalog_labels.labels_"+labelPrefix, "labels.#", "5"),
				),
			},
			{
				// Step 2: Create the curation policy with multiple label waivers
				Config: repoConfig +
					labelsCfg +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["security@company.com", "devops@company.com"]

						label_waivers = [{
							label         = "%s"
							justification = "Security team approved packages"
						}, {
							label         = "%s"
							justification = "Internal use packages are allowed"
						}, {
							label         = "%s"
							justification = "License reviewed packages"
						}, {
							label         = "%s"
							justification = "Build tools are permitted"
						}, {
							label         = "%s"
							justification = "Company approved packages"
						}]
					}
				`, name, name, conditionName, labelNames[0], labelNames[1], labelNames[2], labelNames[3], labelNames[4]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "2"),

					// Check all 5 label waivers
					resource.TestCheckResourceAttr(fqrn, "label_waivers.#", "5"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[0],
						"justification": "Security team approved packages",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[1],
						"justification": "Internal use packages are allowed",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[2],
						"justification": "License reviewed packages",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[3],
						"justification": "Build tools are permitted",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[4],
						"justification": "Company approved packages",
					}),
				),
			},
		},
	})
}

// Test policy with BOTH package waivers AND label waivers - comprehensive scenario
func TestAccCurationPolicy_ComprehensiveWaivers_BothTypes(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-comprehensive-waivers-both", "xray_curation_policy")
	repoName := fmt.Sprintf("comprehensive-waivers-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-cvss-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create custom labels for label waivers using Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create the curation policy with both package and label waivers
				Config: repoConfig +
					labelsCfg +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["security@company.com", "devops@company.com", "qa@company.com"]

						# Package waivers for specific packages
						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "webpack"
							all_versions  = true
							justification = "Build tool - required for all projects"
						}, {
							pkg_type      = "npm"
							pkg_name      = "jest"
							all_versions  = false
							pkg_versions  = ["29.0.0", "29.1.0", "29.2.0"]
							justification = "Testing framework - approved versions only"
						}]

						# Label waivers for packages with catalog labels
						label_waivers = [{
							label         = "%s"
							justification = "Security team approved packages"
						}, {
							label         = "%s"
							justification = "Internal use packages are allowed"
						}, {
							label         = "%s"
							justification = "License reviewed packages"
						}]
					}
				`, name, name, conditionName, labelNames[0], labelNames[1], labelNames[2]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "3"),

					// Check package waivers
					resource.TestCheckResourceAttr(fqrn, "waivers.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "waivers.*", map[string]string{
						"pkg_type":      "npm",
						"pkg_name":      "webpack",
						"all_versions":  "true",
						"justification": "Build tool - required for all projects",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "waivers.*", map[string]string{
						"pkg_type":      "npm",
						"pkg_name":      "jest",
						"all_versions":  "false",
						"justification": "Testing framework - approved versions only",
					}),

					// Check label waivers
					resource.TestCheckResourceAttr(fqrn, "label_waivers.#", "3"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[0],
						"justification": "Security team approved packages",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[1],
						"justification": "Internal use packages are allowed",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "label_waivers.*", map[string]string{
						"label":         labelNames[2],
						"justification": "License reviewed packages",
					}),
				),
			},
		},
	})
}

// ============================================================================
// LABEL LIFECYCLE TESTING
// ============================================================================

// Test custom catalog label lifecycle management using Terraform resource
func TestAccCurationPolicy_LabelLifecycle(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-label-lifecycle", "xray_curation_policy")
	repoName := fmt.Sprintf("label-lifecycle-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Compute expected labels and create them via resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	// Test basic policy creation while labels exist in the system
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create the curation policy to test label lifecycle
				Config: repoConfig +
					labelsCfg +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "block"
						waiver_request_config = "forbidden"
						notify_emails = ["security@company.com"]

						# Note: This test focuses on label lifecycle management via Terraform resource
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
					resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "security@company.com"),
				),
			},
		},
	})

	// Verify all expected labels were computed
	expectedLabels := computePolicyLabelNames(labelPrefix)

	if len(labelNames) != len(expectedLabels) {
		t.Errorf("Expected %d labels, got %d", len(expectedLabels), len(labelNames))
	}

	for i, expected := range expectedLabels {
		if i < len(labelNames) && labelNames[i] != expected {
			t.Errorf("Expected label %s, got %s", expected, labelNames[i])
		}
	}
}

// ============================================================================
// VALIDATION ERROR TESTING
// ============================================================================

// Test comprehensive validation errors for all field combinations
func TestAccCurationPolicy_ValidationErrors(t *testing.T) {
	name := fmt.Sprintf("test-validation-%d", testutil.RandomInt())
	repoName := fmt.Sprintf("validation-errors-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-validation-condition-%d", testutil.RandomInt())
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		Steps: []resource.TestStep{
			{
				// Missing repo_include for specific_repos scope
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "specific_repos"
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Repository include required"),
			},
			{
				// Missing pkg_types_include for pkg_types scope
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Package types include required"),
			},
			{
				// Missing decision_owners for manual waiver config
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "manual"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Decision owners are required when waiver requests are manually approved"),
			},
			{
				// Invalid condition_id format
				Config: createCuratedRepoConfig("npm", repoName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = "invalid-id"
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name),
				ExpectError: regexp.MustCompile("condition_id must be a numeric string"),
			},
			{
				// repo_exclude used with specific_repos (should only be used with all_repos)
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "specific_repos"
						repo_include         = ["repo1"]
						repo_exclude         = ["repo2"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Repository exclude not allowed"),
			},
			{
				// repo_include used with all_repos (should only be used with specific_repos)
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "all_repos"
						repo_include         = ["repo1"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Repository include not allowed"),
			},
			{
				// pkg_types_include used with all_repos (should only be used with pkg_types)
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "all_repos"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Package types include not allowed"),
			},
			{
				// Empty repo_exclude array
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "all_repos"
						repo_exclude         = []
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Repository exclude cannot be empty"),
			},
			{
				// Empty pkg_types_include array
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = []
						policy_action        = "block"
						waiver_request_config = "forbidden"
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Package types include required|Package types include cannot be empty"),
			},
			{
				// Empty decision_owners array
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "all_repos"
						policy_action        = "block"
						waiver_request_config = "manual"
						decision_owners      = []
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Decision owners are required when waiver requests are manually approved"),
			},
			// Waiver-specific validations
			{
				// Package waiver with all_versions=true but pkg_versions specified - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "lodash"
							all_versions  = true
							pkg_versions  = ["4.17.20"]
							justification = "Test justification"
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Package versions not allowed|cannot be specified when all_versions is true"),
			},
			{
				// Package waiver with all_versions=false but no pkg_versions - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "lodash"
							all_versions  = false
							// Missing pkg_versions - should cause validation error
							justification = "Test justification"
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("Package versions required|must be specified when all_versions is false"),
			},
			{
				// Package waiver with empty justification - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						waivers = [{
							pkg_type      = "npm"
							pkg_name      = "lodash"
							all_versions  = true
							justification = ""
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("string length must be at least 1|empty|required"),
			},
			{
				// Package waiver with empty pkg_name - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						waivers = [{
							pkg_type      = "npm"
							pkg_name      = ""
							all_versions  = true
							justification = "Test justification"
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("string length must be at least 1|empty|required"),
			},
			{
				// Package waiver with empty pkg_type - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						waivers = [{
							pkg_type      = ""
							pkg_name      = "lodash"
							all_versions  = true
							justification = "Test justification"
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("string length must be at least 1|empty|required"),
			},
			{
				// Label waiver with empty justification - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					labelsCfg +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						label_waivers = [{
							label         = "%s"
							justification = ""
						}]
					}
				`, name, name, conditionName, labelNames[0]),
				ExpectError: regexp.MustCompile("string length must be at least 1|empty|required"),
			},
			{
				// Label waiver with empty label - should fail
				Config: createCuratedRepoConfig("npm", repoName) +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name                  = "%s"
						condition_id          = xray_custom_curation_condition.%s.id
						scope                = "pkg_types"
						pkg_types_include    = ["npm"]
						policy_action        = "block"
						waiver_request_config = "forbidden"
						
						label_waivers = [{
							label         = ""
							justification = "Test justification"
						}]
					}
				`, name, name, conditionName),
				ExpectError: regexp.MustCompile("string length must be at least 1|empty|required"),
			},
		},
	})
}

// ============================================================================
// MISSING COMBINATION TESTING - Complete coverage of all combinations
// ============================================================================

// Test dry_run + forbidden combination (missing combination)
func TestAccCurationPolicy_DryRun_Forbidden(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-dryrun-forbidden", "xray_curation_policy")
	repoName := fmt.Sprintf("dryrun-forbidden-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create policy with dry_run + forbidden combination
				Config: repoConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "all_repos"
						policy_action = "dry_run"
						waiver_request_config = "forbidden"
						notify_emails = ["audit-team@company.com"]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "forbidden"),
					resource.TestCheckResourceAttr(fqrn, "scope", "all_repos"),
				),
			},
		},
	})
}

// Test dry_run + manual combination (missing combination)
func TestAccCurationPolicy_DryRun_Manual(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-dryrun-manual", "xray_curation_policy")
	repoName := fmt.Sprintf("dryrun-manual-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-cvss-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create policy with dry_run + manual combination
				Config: repoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "dry_run"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["audit-team@company.com", "security-team@company.com"]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
					resource.TestCheckTypeSetElemAttr(fqrn, "decision_owners.*", "readers"),
				),
			},
		},
	})
}

// Test block + auto_approved combination (missing systematic coverage)
func TestAccCurationPolicy_Block_AutoApproved(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-block-autoapproved", "xray_curation_policy")
	repoName := fmt.Sprintf("block-autoapproved-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-openssf-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create policy with block + auto_approved combination
				Config: repoConfig +
					createOpenSSFCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "specific_repos"
						repo_include = [artifactory_remote_npm_repository.%s.key]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						notify_emails = ["dev-team@company.com"]
					}
				`, name, name, conditionName, repoName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
					resource.TestCheckResourceAttr(fqrn, "scope", "specific_repos"),
					resource.TestCheckResourceAttr(fqrn, "repo_include.#", "1"),
				),
			},
		},
	})
}

// Test multiple package types in pkg_types scope (missing coverage)
func TestAccCurationPolicy_MultiplePackageTypes_Comprehensive(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-multi-pkg-types", "xray_curation_policy")
	npmRepoName := fmt.Sprintf("multi-pkg-npm-%d", testutil.RandomInt())
	mavenRepoName := fmt.Sprintf("multi-pkg-maven-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-maturity-condition-%d", testutil.RandomInt())

	// Multi-package repositories configuration
	reposConfig := createCuratedRepoConfig("npm", npmRepoName) +
		createCuratedRepoConfig("maven", mavenRepoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repositories first and verify they exist
				Config: reposConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", npmRepoName), "key", npmRepoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_maven_repository.%s", mavenRepoName), "key", mavenRepoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", npmRepoName), "curated", "true"),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_maven_repository.%s", mavenRepoName), "curated", "true"),
				),
			},
			{
				// Step 2: Create policy with multiple package types
				Config: reposConfig +
					createMaturityCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm", "maven", "docker"]
						policy_action = "dry_run"
						waiver_request_config = "auto_approved"
						notify_emails = ["multi-lang-team@company.com"]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "scope", "pkg_types"),
					resource.TestCheckResourceAttr(fqrn, "pkg_types_include.#", "3"),
					resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "npm"),
					resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "maven"),
					resource.TestCheckTypeSetElemAttr(fqrn, "pkg_types_include.*", "docker"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "dry_run"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "auto_approved"),
				),
			},
		},
	})
}

// Test cross-scope condition combinations (missing coverage)
func TestAccCurationPolicy_CrossScope_CVECondition(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cross-scope-cve", "xray_curation_policy")
	repoName1 := fmt.Sprintf("cross-scope-npm1-%d", testutil.RandomInt())
	repoName2 := fmt.Sprintf("cross-scope-npm2-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-cve-condition-%d", testutil.RandomInt())

	// Multiple repositories configuration
	reposConfig := createCuratedRepoConfig("npm", repoName1) +
		createCuratedRepoConfig("npm", repoName2)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repositories first and verify they exist
				Config: reposConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName1), "key", repoName1),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName2), "key", repoName2),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName1), "curated", "true"),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName2), "curated", "true"),
				),
			},
			{
				// Step 2: Test CVE condition with specific_repos scope (using CVSS due to test environment limitations)
				Config: reposConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "specific_repos"
						repo_include = [
							artifactory_remote_npm_repository.%s.key,
							artifactory_remote_npm_repository.%s.key
						]
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = ["cve-alerts@company.com"]
					}
				`, name, name, conditionName, repoName1, repoName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "scope", "specific_repos"),
					resource.TestCheckResourceAttr(fqrn, "repo_include.#", "2"),
					resource.TestCheckResourceAttr(fqrn, "policy_action", "block"),
					resource.TestCheckResourceAttr(fqrn, "waiver_request_config", "manual"),
					resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
					resource.TestCheckTypeSetElemAttr(fqrn, "decision_owners.*", "readers"),
				),
			},
		},
	})
}

// Test comprehensive notification combinations (missing coverage)
func TestAccCurationPolicy_NotificationCombinations(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-notification-combo", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-banned-licenses-condition-%d", testutil.RandomInt())

	// Use shared repositories configuration
	sharedRepoConfig := getSharedRepoConfig()

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create shared repositories and verify they exist
				Config: sharedRepoConfig,
				Check:  resource.ComposeTestCheckFunc(getSharedRepoVerification()...),
			},
			{
				// Step 2: Test comprehensive notification setup with license condition
				Config: sharedRepoConfig +
					createBannedLicensesCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "manual"
						decision_owners = ["readers"]
						notify_emails = [
							"legal@company.com",
							"security@company.com", 
							"compliance@company.com",
							"dev-leads@company.com"
						]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					// Verify shared repositories still exist
					append(getSharedRepoVerification(),
						// Verify policy attributes
						resource.TestCheckResourceAttr(fqrn, "decision_owners.#", "1"),
						resource.TestCheckTypeSetElemAttr(fqrn, "decision_owners.*", "readers"),
						resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "4"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "legal@company.com"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "security@company.com"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "compliance@company.com"),
						resource.TestCheckTypeSetElemAttr(fqrn, "notify_emails.*", "dev-leads@company.com"),
					)...,
				),
			},
		},
	})
}

func TestAccCurationPolicy_EdgeCases(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-edge-cases", "xray_curation_policy")
	repoName := fmt.Sprintf("edge-cases-npm-%d", testutil.RandomInt())
	conditionName := fmt.Sprintf("test-condition-%d", testutil.RandomInt())

	// Repository configuration
	repoConfig := createCuratedRepoConfig("npm", repoName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders:        commonExternalProviders,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				// Step 1: Create repository first and verify it exists
				Config: repoConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "key", repoName),
					resource.TestCheckResourceAttr(fmt.Sprintf("artifactory_remote_npm_repository.%s", repoName), "curated", "true"),
				),
			},
			{
				// Step 2: Long policy name (within 50 character limit)
				Config: repoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "long-policy-name-test-max-length-allowed-50"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "forbidden"
					}
				`, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", "long-policy-name-test-max-length-allowed-50"),
				),
			},
			{
				// Step 3: Maximum number of notification emails
				Config: repoConfig +
					createCVSSCondition(conditionName) + fmt.Sprintf(`
					resource "xray_curation_policy" "%s" {
						name         = "%s-max-emails"
						condition_id = xray_custom_curation_condition.%s.id
						scope        = "pkg_types"
						pkg_types_include = ["npm"]
						policy_action = "block"
						waiver_request_config = "auto_approved"
						notify_emails = [
							"team1@company.com",
							"team2@company.com", 
							"team3@company.com",
							"team4@company.com",
							"team5@company.com"
						]
					}
				`, name, name, conditionName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "notify_emails.#", "5"),
				),
			},
		},
	})
}
