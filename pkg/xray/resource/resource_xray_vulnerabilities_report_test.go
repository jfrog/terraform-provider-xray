package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

func TestAccVulnerabilitiesReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("vuln_repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-repo-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
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
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = true
								issue_id = "XRAY-87343"
								severities = ["Critical", "High"]
								published {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.name", "docker-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.name", "libs-release-local"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.issue_id", "XRAY-87343"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.end", "2020-07-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("vuln_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-repo-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
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
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = false
								issue_id = "XRAY-87343"
								severities = ["Critical", "High"]
								published {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.name", "docker-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.0", "folder1/path/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.1", "folder2/path*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.0", "folder1/path2/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.1", "folder2/path2*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.name", "libs-release-local"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.0", "**/*.jar"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.1.include_path_patterns.1", "**/*.war"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.issue_id", "XRAY-87343"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.end", "2020-07-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccVulnerabilitiesReport_Build(t *testing.T) {
	// Test case for builds by name
	t.Run("vuln_builds_by_name", func(t *testing.T) {
		build1Name := fmt.Sprintf("build-1-%d", testutil.RandomInt())
		build2Name := fmt.Sprintf("build-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("vuln-build-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for builds by name
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["%s", "%s"]
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = true
								cve = "CVE-2021-44228"
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName, build1Name, build2Name),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cve", "CVE-2021-44228"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("vuln_builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-build-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for builds by pattern
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["build-*", "release-*"]
									exclude_patterns = ["test-*", "dev-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = false
								cve = "CVE-2021-44228"
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.0", "build-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.include_patterns.1", "release-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.0", "dev-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.exclude_patterns.1", "test-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.builds.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cve", "CVE-2021-44228"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccVulnerabilitiesReport_ReleaseBundle(t *testing.T) {
	// Test case for release bundles by name
	t.Run("vuln_release_bundles_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("release-bundle-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("release-bundle-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("vuln-release-bundle-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for release bundles by name
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									names = ["%s", "%s"]
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = true
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName, releaseBundle1Name, releaseBundle2Name),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("vuln_release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-release-bundle-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for release bundles by pattern
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									include_patterns = ["prod-*", "release-*"]
									exclude_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = false
								cve = "CVE-2021-44228"
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.0", "prod-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.include_patterns.1", "release-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.0", "dev-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.exclude_patterns.1", "test-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cve", "CVE-2021-44228"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

}

func TestAccVulnerabilitiesReport_ReleaseBundleV2(t *testing.T) {
	// Test case for release bundles v2 by name
	t.Run("vuln_release_bundles_v2_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("vuln-release-bundle-v2-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("vuln-release-bundle-v2-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("vuln-release-bundle-v2-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for release bundles v2 by name
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									names = ["%s", "%s"]
									number_of_latest_versions = 3
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = true
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName, releaseBundle1Name, releaseBundle2Name),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.names.0", releaseBundle1Name),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.names.1", releaseBundle2Name),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "3"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles v2 by pattern
	t.Run("vuln_release_bundles_v2_by_pattern", func(t *testing.T) {
		// Skip test if Xray version is lower than 3.130.0
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), FixVersionForReleaseBundleV2, "")
		if err != nil || version < FixVersionForReleaseBundleV2 {
			t.Skipf("Skipping test: requires Xray version %s or higher", FixVersionForReleaseBundleV2)
			return
		}
		reportName := fmt.Sprintf("vuln-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for release bundles v2 by pattern
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									include_patterns = ["v2.*-release", "v2.*-hotfix"]
									exclude_patterns = ["*-snapshot", "*-rc"]
									number_of_latest_versions = 5
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = false
								cvss_score {
									min_score = 8.0
									max_score = 10.0
								}
								scan_date {
									start = "2020-07-29T12:22:16Z"
									end = "2020-08-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", "v2.*-hotfix"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", "v2.*-release"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", "*-rc"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", "*-snapshot"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "8"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-07-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-08-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccVulnerabilitiesReport_Project(t *testing.T) {
	// Test case for project by name
	t.Run("vuln_project_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-project-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), FixVersionForProjectScopeKey, "")

		var projectConfig string
		if err == nil && version >= FixVersionForProjectScopeKey {
			projectConfig = `
							keys = ["key1", "key2"]
							number_of_latest_versions = 2`
		} else {
			projectConfig = `
							names = ["test-project-1", "test-project-2"]
							number_of_latest_versions = 2`
		}

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								projects {%s
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = true
								issue_id = "XRAY-87343"
								severities = ["Critical", "High"]
								published {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName, projectConfig),
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "name", reportName),
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.number_of_latest_versions", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.issue_id", "XRAY-87343"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.start", "2020-06-29T12:22:16Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.end", "2020-07-29T12:22:16Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
						}

						projectNamesChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.0", "test-project-1"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.1", "test-project-2"),
						}

						projectKeysChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.keys.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.keys.0", "key1"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.keys.1", "key2"),
						}

						if err == nil && version >= FixVersionForProjectScopeKey {
							allChecks := append(baseChecks, projectKeysChecks...)
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						allChecks := append(baseChecks, projectNamesChecks...)
						return resource.ComposeTestCheckFunc(allChecks...)
					}(),
				},
			},
		})
	})

	// Test case for project by pattern
	t.Run("vuln_project_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-project-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["dev-*", "test-*"]
									exclude_key_patterns = ["prod-*", "staging-*"]
								}
							}
							filters {
								vulnerable_component = "*log4j*"
								impacted_artifact = "*spring*"
								has_remediation = false
								issue_id = "XRAY-87343"
								severities = ["Critical", "High"]
								published {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.0", "dev-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.1", "test-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.0", "prod-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.1", "staging-*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.issue_id", "XRAY-87343"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.published.0.end", "2020-07-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccVulnerabilitiesReport_Invalid(t *testing.T) {
	reportName := fmt.Sprintf("vuln-invalid-report-%d", testutil.RandomInt())
	_, _, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

	t.Run("conflicting_cve_and_issue_id", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								cve = "CVE-2021-44228"
								issue_id = "XRAY-87343"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Attribute.*cannot be specified when.*is specified.*`),
				},
			},
		})
	})

	t.Run("conflicting_severities_and_cvss_score", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								severities = ["Critical"]
								cvss_score {
									min_score = 7.0
									max_score = 10.0
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Attribute.*cannot be specified when.*is specified.*`),
				},
			},
		})
	})

	t.Run("invalid_severity_value", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								severities = ["Invalid"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*value must be one of: \["Low" "Medium" "High" "Critical"\], got: "Invalid".*`),
				},
			},
		})
	})

	t.Run("invalid_cve_format", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								cve = "invalid-cve"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*invalid Vulnerability, must be a valid CVE, example CVE-2021-12345.*`),
				},
			},
		})
	})

	t.Run("invalid_cve_year", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								cve = "CVE-202-12345"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*invalid Vulnerability, must be a valid CVE, example CVE-2021-12345.*`),
				},
			},
		})
	})

	t.Run("invalid_cve_id", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								cve = "CVE-2021-123"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*invalid Vulnerability, must be a valid CVE, example CVE-2021-12345.*`),
				},
			},
		})
	})

	t.Run("project_names_and_patterns", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["test-project"]
									include_key_patterns = ["test-*"]
								}
							}
							filters {
								severities = ["Critical"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})

	t.Run("build_names_and_patterns", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["test-build"]
									include_patterns = ["test-*"]
								}
							}
							filters {
								severities = ["Critical"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})

	t.Run("invalid_scan_date_range", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								scan_date {
									start = "2020-12-31T00:00:00Z"
									end = "2020-01-01T00:00:00Z"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid scan_date range.*End date must be after start date.*`),
				},
			},
		})
	})

	t.Run("invalid_published_date_range", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								published {
									start = "2020-12-31T00:00:00Z"
									end = "2020-01-01T00:00:00Z"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid published range.*End date must be after start date.*`),
				},
			},
		})
	})
}
