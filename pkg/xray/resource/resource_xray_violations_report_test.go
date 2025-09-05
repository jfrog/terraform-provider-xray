package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

func TestAccViolationsReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("violations_repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-repo-by-name-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		issueId := fmt.Sprintf("XRAY-%d", testutil.RandomInt())
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local"
								}
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								type = "security"
								watch_names = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["High", "Critical"]
								violation_status = "Active"
								security_filters {
									issue_id = "%s"
									cvss_score {
										min_score = 7.0
										max_score = 10.0
									}
									summary_contains = "%s"
									has_remediation = true
									published {
										start = "2023-01-01T00:00:00Z"
										end = "2023-12-31T23:59:59Z"
									}
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, watchName, policyName, componentName, artifactName, issueId, summaryText),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.name", "docker-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.name", "libs-release-local"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.0", watchName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
						// Security filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.issue_id", issueId),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("violations_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-repo-by-pattern-%d", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local"
									include_path_patterns = ["folder1/path/*", "folder2/path*"]
									exclude_path_patterns = ["folder1/path2/*", "folder2/path2*"]
								}
								repository {
									name = "libs-release-local"
									include_path_patterns = ["**/*.jar", "**/*.war"]
									exclude_path_patterns = ["**/test/**", "**/libs/**"]
								}
							}
							filters {
								type = "license"
								watch_patterns = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["Low", "Medium"]
								violation_status = "Ignored"
								license_filters {
									unknown = true
									license_patterns = ["*MIT*", "*GPL*"]
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, watchPattern, policyName, componentName, artifactName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.name", "libs-release-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.0", "**/*.jar"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.1", "**/*.war"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.0", "**/libs/**"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.1", "**/test/**"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.name", "docker-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.0", "folder1/path/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.1", "folder2/path*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.exclude_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.exclude_path_patterns.0", "folder1/path2/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.exclude_path_patterns.1", "folder2/path2*"),

						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "license"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
						// License filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.unknown", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_patterns.1", "*MIT*"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})
}

func TestAccViolationsReport_Build(t *testing.T) {
	// Test case for builds by name
	t.Run("violations_builds_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-build-by-name-%d", testutil.RandomInt())
		buildName1 := fmt.Sprintf("build-local-%d", testutil.RandomInt())
		buildName2 := fmt.Sprintf("build-local-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		issueId := fmt.Sprintf("XRAY-%d", testutil.RandomInt())
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["%s", "%s"]
								}
							}
							filters {
								type = "security"
								watch_names = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["High", "Critical"]
								violation_status = "Active"
								security_filters {
									issue_id = "%s"
									cvss_score {
										min_score = 7.0
										max_score = 10.0
									}
									summary_contains = "%s"
									has_remediation = false
									published {
										start = "2023-01-01T00:00:00Z"
										end = "2023-12-31T23:59:59Z"
									}
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, buildName1, buildName2, watchName, policyName, componentName, artifactName, issueId, summaryText),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.number_of_latest_versions", "1"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.0", watchName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
						// Security filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.issue_id", issueId),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("violations_builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-build-by-pattern-%d", testutil.RandomInt())
		buildPattern1 := fmt.Sprintf("build-pattern-%d-*", testutil.RandomInt())
		buildPattern2 := fmt.Sprintf("release-pattern-%d-*", testutil.RandomInt())
		excludePattern1 := fmt.Sprintf("dev-pattern-%d-*", testutil.RandomInt())
		excludePattern2 := fmt.Sprintf("test-pattern-%d-*", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		cveId := fmt.Sprintf("CVE-2023-%d", testutil.RandomInt())
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["%s", "%s"]
									exclude_patterns = ["%s", "%s"]
									number_of_latest_versions = 3
								}
							}
							filters {
		type = "security"
								watch_patterns = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["Low", "Medium"]
								violation_status = "Ignored"
								security_filters {
									cve = "%s"
									cvss_score {
										min_score = 4.0
										max_score = 6.0
									}
									summary_contains = "%s"
									has_remediation = false
									published {
										start = "2023-01-01T00:00:00Z"
										end = "2023-12-31T23:59:59Z"
									}
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, buildPattern1, buildPattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, cveId, summaryText),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.0", buildPattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.1", buildPattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.0", excludePattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.1", excludePattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.number_of_latest_versions", "3"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
						// Security filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cve", cveId),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "4"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "6"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})
}

func TestAccViolationsReport_ReleaseBundle(t *testing.T) {
	// Test case for release bundles v1 by name
	t.Run("violations_release_bundles_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-release-bundle-by-name-%d", testutil.RandomInt())
		bundleName1 := fmt.Sprintf("release-bundle-%d", testutil.RandomInt())
		bundleName2 := fmt.Sprintf("release-bundle-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		issueId := fmt.Sprintf("XRAY-%d", testutil.RandomInt())
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									names = ["%s", "%s"]
									number_of_latest_versions = 2
								}
							}
							filters {
								type = "security"
								watch_names = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["High", "Critical"]
								violation_status = "Active"
								security_filters {
									issue_id = "%s"
									cvss_score {
										min_score = 7.0
										max_score = 10.0
									}
									summary_contains = "%s"
									has_remediation = true
									published {
										start = "2023-01-01T00:00:00Z"
										end = "2023-12-31T23:59:59Z"
									}
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, bundleName1, bundleName2, watchName, policyName, componentName, artifactName, issueId, summaryText),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.number_of_latest_versions", "2"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.0", watchName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
						// Security filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.issue_id", issueId),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("violations_release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-release-bundle-by-pattern-%d", testutil.RandomInt())
		bundlePattern1 := fmt.Sprintf("bundle-pattern-%d-*", testutil.RandomInt())
		bundlePattern2 := fmt.Sprintf("release-pattern-%d-*", testutil.RandomInt())
		excludePattern1 := fmt.Sprintf("dev-pattern-%d-*", testutil.RandomInt())
		excludePattern2 := fmt.Sprintf("test-pattern-%d-*", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									include_patterns = ["%s", "%s"]
									exclude_patterns = ["%s", "%s"]
									number_of_latest_versions = 5
								}
							}
							filters {
								type = "license"
								watch_patterns = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["Low", "Medium"]
								violation_status = "Ignored"
								license_filters {
									unknown = true
									license_names = [ "Apache-2.0", "MIT" ]
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, bundlePattern1, bundlePattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.0", bundlePattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.1", bundlePattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.0", excludePattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.1", excludePattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.number_of_latest_versions", "5"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "license"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
						// License filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.unknown", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.1", "MIT"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})
}

func TestAccViolationsReport_ReleaseBundleV2(t *testing.T) {
	// Test case for release bundles v2 by name
	t.Run("violations_release_bundles_v2_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-release-bundle-v2-by-name-%d", testutil.RandomInt())
		bundleName1 := fmt.Sprintf("release-bundle-v2-%d", testutil.RandomInt())
		bundleName2 := fmt.Sprintf("release-bundle-v2-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									names = ["%s", "%s"]
									number_of_latest_versions = 2
								}
							}
							filters {
								type = "operational_risk"
								watch_names = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								violation_status = "Active"
								severities = [ "High", "Critical" ]
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, bundleName1, bundleName2, watchName, policyName, componentName, artifactName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "2"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "operational_risk"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.0", watchName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles v2 by pattern
	// t.Run("violations_release_bundles_v2_by_pattern", func(t *testing.T) {
	// 	reportName := fmt.Sprintf("violations-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
	// 	bundlePattern1 := fmt.Sprintf("bundle-pattern-v2-%d-*", testutil.RandomInt())
	// 	bundlePattern2 := fmt.Sprintf("release-pattern-v2-%d-*", testutil.RandomInt())
	// 	excludePattern1 := fmt.Sprintf("dev-pattern-v2-%d-*", testutil.RandomInt())
	// 	excludePattern2 := fmt.Sprintf("test-pattern-v2-%d-*", testutil.RandomInt())
	// 	watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
	// 	policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
	// 	componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
	// 	artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
	// 	cveId := fmt.Sprintf("CVE-2023-%d", testutil.RandomInt())
	// 	summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
	// 	_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

	// 	resource.Test(t, resource.TestCase{
	// 		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
	// 		CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
	// 		Steps: []resource.TestStep{
	// 			{
	// 				Config: fmt.Sprintf(`
	// 					resource "xray_violations_report" "%s" {
	// 						name = "%s"
	// 						resources {
	// 							release_bundles_v2 {
	// 								include_patterns = ["%s", "%s"]
	// 								exclude_patterns = ["%s", "%s"]
	// 								number_of_latest_versions = 5
	// 							}
	// 						}
	// 						filters {
	// 							type = "security"
	// 							watch_patterns = ["%s"]
	// 							policy_names = ["%s"]
	// 							component = "%s"
	// 							artifact = "%s"
	// 							severities = ["Low", "Medium"]
	// 							violation_status = "Ignored"
	// 							security_filters {
	// 								cve = "%s"
	// 								cvss_score {
	// 									min_score = 4.0
	// 									max_score = 6.0
	// 								}
	// 								summary_contains = "%s"
	// 								has_remediation = false
	// 								published {
	// 									start = "2023-01-01T00:00:00Z"
	// 									end = "2023-12-31T23:59:59Z"
	// 								}
	// 							}
	// 							updated {
	// 								start = "2023-01-01T00:00:00Z"
	// 								end = "2023-12-31T23:59:59Z"
	// 							}
	// 						}
	// 					}
	// 				`, name, reportName, bundlePattern1, bundlePattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, cveId, summaryText),
	// 				Check: resource.ComposeTestCheckFunc(
	// 					resource.TestCheckResourceAttr(fqrn, "name", reportName),
	// 					// Resource checks
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", bundlePattern1),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", bundlePattern2),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", excludePattern1),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", excludePattern2),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
	// 					// Filter checks
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Medium"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Low"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
	// 					// Security filter checks
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cve", cveId),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "4.0"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "6.0"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
	// 					// Date range checks
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
	// 				),
	// 			},
	// 		},
	// 	})
	// })
}

func TestAccViolationsReport_Project(t *testing.T) {
	// Test case for projects by name
	t.Run("violations_projects_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-project-by-name-%d", testutil.RandomInt())
		projectName1 := fmt.Sprintf("project-%d", testutil.RandomInt())
		projectName2 := fmt.Sprintf("project-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["%s", "%s"]
									number_of_latest_versions = 2
								}
							}
							filters {
								type = "license"
								watch_names = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								severities = ["High", "Critical"]
								violation_status = "Active"
								license_filters {
									unknown = false
									license_names = [ "Apache-2.0", "MIT" ]
								}
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, projectName1, projectName2, watchName, policyName, componentName, artifactName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.number_of_latest_versions", "2"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "license"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_names.0", watchName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
						// License filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_filters.0.license_names.1", "MIT"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})

	// Test case for projects by pattern
	t.Run("violations_projects_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-project-by-pattern-%d", testutil.RandomInt())
		projectPattern1 := fmt.Sprintf("project-pattern-%d-*", testutil.RandomInt())
		projectPattern2 := fmt.Sprintf("release-pattern-%d-*", testutil.RandomInt())
		excludePattern1 := fmt.Sprintf("dev-pattern-%d-*", testutil.RandomInt())
		excludePattern2 := fmt.Sprintf("test-pattern-%d-*", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["%s", "%s"]
									exclude_key_patterns = ["%s", "%s"]
									number_of_latest_versions = 5
								}
							}
							filters {
								type = "operational_risk"
								watch_patterns = ["%s"]
								policy_names = ["%s"]
								component = "%s"
								artifact = "%s"
								violation_status = "Ignored"
								severities = [ "Low", "Medium" ]
								updated {
									start = "2023-01-01T00:00:00Z"
									end = "2023-12-31T23:59:59Z"
								}
							}
						}
					`, name, reportName, projectPattern1, projectPattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Resource checks
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.0", projectPattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.1", projectPattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.0", excludePattern1),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.1", excludePattern2),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.number_of_latest_versions", "5"),
						// Filter checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.type", "operational_risk"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
						// Date range checks
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
					),
				},
			},
		})
	})
}

func TestAccViolationsReport_Invalid(t *testing.T) {
	reportName := fmt.Sprintf("violations-invalid-%d", testutil.RandomInt())
	_, _, name := testutil.MkNames(reportName, "xray_violations_report")

	t.Run("empty_name", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = ""
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
							}
						}
					`, name),
					ExpectError: regexp.MustCompile("Attribute name string length must be at least 1"),
				},
			},
		})
	})

	t.Run("multiple_resource_types", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
								builds {
									names = ["build1"]
								}
							}
							filters {
								type = "security"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)(Error: Invalid Resource Configuration.*Only one type of resource \(repository, builds, release_bundles, release_bundles_v2, or projects\) can be specified per report|Error: Invalid Attribute Combination.*Attribute.*resources\[.*\]\.builds.*cannot be specified when.*resources\[.*\]\.repository.*is specified)`),
				},
			},
		})
	})

	t.Run("conflicting_watch_attributes", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								watch_names = ["watch1"]
								watch_patterns = ["pattern1"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Combination.*Attribute.*filters\[.*\]\.watch_patterns.*cannot be specified when.*filters\[.*\]\.watch_names.*is specified`),
				},
			},
		})
	})

	t.Run("invalid_type", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "invalid"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value Match.*filters\[.*\]\.type.*value must be one of: \["security" "license" "operational_risk"\], got:\s*"invalid"`),
				},
			},
		})
	})

	t.Run("invalid_severity", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								severities = ["Invalid"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value Match.*filters\[.*\]\.severities\[Value\("Invalid"\)\].*value must be one of: \["Low" "Medium" "High" "Critical"\], got: "Invalid"`),
				},
			},
		})
	})

	t.Run("invalid_violation_status", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								violation_status = "Invalid"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value Match.*filters\[.*\]\.violation_status.*value must be one of: \["All" "Active" "Ignored"\], got: "Invalid"`),
				},
			},
		})
	})

	t.Run("conflicting_security_filters", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								security_filters {
									cve = "CVE-2021-44228"
									issue_id = "XRAY-87343"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Combination.*Only one of 'cve' or 'issue_id' can be specified in security_filters block`),
				},
			},
		})
	})

	t.Run("conflicting_license_filters", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "license"
								license_filters {
									license_names = ["GPL-3.0"]
									license_patterns = ["*GPL*"]
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Combination.*Attribute.*filters\[.*\]\.license_filters\[.*\]\.license_patterns.*cannot be specified when.*filters\[.*\]\.license_filters\[.*\]\.license_names.*is specified`),
				},
			},
		})
	})

	t.Run("invalid_date_range", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								updated {
									start = "2023-12-31T23:59:59Z"
									end = "2023-01-01T00:00:00Z"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid updated range.*End date must be after start date`),
				},
			},
		})
	})

	t.Run("invalid_date_format", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								updated {
									start = "2023/01/01"
									end = "2023/12/31"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile("Value must be a valid RFC3339 date"),
				},
			},
		})
	})

	t.Run("missing_severities_for_operational_risk", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "operational_risk"
								component = "*log4j*"
								artifact = "*spring*"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Missing Required Attribute.*severities must be specified when type is "operational_risk"`),
				},
			},
		})
	})

	t.Run("mixing_filter_types", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_violations_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local-vio"
								}
							}
							filters {
								type = "security"
								security_filters {
									issue_id = "XRAY-87343"
								}
								license_filters {
									unknown = true
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Combination.*license_filters cannot be specified when type is "security"`),
				},
			},
		})
	})
}
