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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "now"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "15 06 * * TUE"
					cron_schedule_timezone = "America/Los_Angeles"
					emails = ["user1@example.com", "user2@example.com"]`
		}

		config := fmt.Sprintf(`
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "15 06 * * TUE"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "America/Los_Angeles"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "user1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "user2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "now"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("vuln_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-repo-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "1 hour"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "30 09 * * WED"
					cron_schedule_timezone = "Europe/London"
					emails = ["admin1@example.com", "admin2@example.com"]`
		}

		config := fmt.Sprintf(`
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "30 09 * * WED"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Europe/London"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "admin1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "admin2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "1 hour"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "24 hours"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "45 12 * * THU"
					cron_schedule_timezone = "Asia/Tokyo"
					emails = ["dev1@example.com", "dev2@example.com"]`
		}

		config := fmt.Sprintf(`
				# Create vulnerabilities report for builds by name
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, build1Name, build2Name, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "45 12 * * THU"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Asia/Tokyo"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "dev1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "dev2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "24 hours"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("vuln_builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-build-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["not_scanned", "not_covered", "rescan_required"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "3 days"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "00 15 * * FRI"
					cron_schedule_timezone = "Australia/Sydney"
					emails = ["qa1@example.com", "qa2@example.com"]`
		}

		config := fmt.Sprintf(`
				# Create vulnerabilities report for builds by pattern
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
					resources {
						builds {
							include_patterns = ["build-*", "release-*"]
							exclude_patterns = ["dev-*","test-*"]
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "00 15 * * FRI"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Australia/Sydney"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "qa1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "qa2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "not_covered"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_scanned"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "rescan_required"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "3 days"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "24 hours"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "15 18 * * SAT"
					cron_schedule_timezone = "UTC"
					emails = ["ops1@example.com", "ops2@example.com"]`
		}

		config := fmt.Sprintf(`
				# Create vulnerabilities report for release bundles by name
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, releaseBundle1Name, releaseBundle2Name, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "name", reportName),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles.0.names.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.vulnerable_component", "*log4j*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.has_remediation", "true"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.min_score", "7"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.cvss_score.0.max_score", "10"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "15 18 * * SAT"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "UTC"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "ops1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "ops2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "24 hours"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("vuln_release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("vuln-release-bundle-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["rescan_required", "upgrade_required", "technology_unsupported"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "7 days"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "30 21 * * SUN"
					cron_schedule_timezone = "America/Chicago"
					emails = ["security1@example.com", "security2@example.com"]`
		}

		config := fmt.Sprintf(`
				# Create vulnerabilities report for release bundles by pattern
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "30 21 * * SUN"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "America/Chicago"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "security1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "security2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "rescan_required"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "technology_unsupported"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "upgrade_required"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "7 days"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "24 hours"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "45 00 * * MON"
					cron_schedule_timezone = "Europe/Paris"
					emails = ["release1@example.com", "release2@example.com"]`
		}

		config := fmt.Sprintf(`
				# Create vulnerabilities report for release bundles v2 by name
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, releaseBundle1Name, releaseBundle2Name, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "45 00 * * MON"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Europe/Paris"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "release1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "release2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "24 hours"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["upgrade_required", "technology_unsupported"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "30 days"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "15 03 * * TUE"
					cron_schedule_timezone = "Asia/Singapore"
					emails = ["v2-team1@example.com", "v2-team2@example.com"]`
		}

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create vulnerabilities report for release bundles v2 by pattern
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"%s
							resources {
								release_bundles_v2 {
									include_patterns = ["v2.*-hotfix","v2.*-release"]
									exclude_patterns = ["*-rc","*-snapshot"]
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
								}%s
							}
						}
					`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter)),
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "15 03 * * TUE"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Asia/Singapore"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "v2-team1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "v2-team2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "technology_unsupported"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "upgrade_required"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "30 days"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

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

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "not_applicable", "undetermined"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "24 hours"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "00 12 * * MON"
					cron_schedule_timezone = "America/New_York"
					emails = ["project1@example.com", "project2@example.com"]`
		}

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"%s
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
								}%s
							}
						}
					`, name, reportName, extendedAttrs, projectConfig, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter)),
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

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "00 12 * * MON"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "America/New_York"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "project1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "project2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "24 hours"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							allChecks = append(allChecks, projectKeysChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["not_scanned", "not_covered", "rescan_required"]
						}`
		}

		var runtimeFilter string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			if isRuntimeFilterEnabled() {
				runtimeFilter = `
						runtime_filter {
							time_period = "10 days"
						}`
			}
		}

		var extendedAttrs string
		if err == nil && version >= MinVersionForCronAndNotify {
			extendedAttrs = `
					cron_schedule = "30 09 * * THU"
					cron_schedule_timezone = "Europe/London"
					emails = ["manager1@example.com", "manager2@example.com"]`
		}

		config := fmt.Sprintf(`
				resource "xray_vulnerabilities_report" "%s" {
					name = "%s"%s
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
						}%s
					}
				}
			`, name, reportName, extendedAttrs, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "30 09 * * THU"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Europe/London"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "manager1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "manager2@example.com"),
							// CA filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.#", "3"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "not_covered"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_scanned"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "rescan_required"),
						}

						runtimeChecks := []resource.TestCheckFunc{
							// Runtime filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.runtime_filter.0.time_period", "10 days"),
						}

						if err == nil && version >= MinVersionForCAAndRuntimeFilters {
							allChecks := append(baseChecks, extendedChecks...)
							if isRuntimeFilterEnabled() {
								allChecks = append(allChecks, runtimeChecks...)
							}
							return resource.ComposeTestCheckFunc(allChecks...)
						}
						return resource.ComposeTestCheckFunc(baseChecks...)
					}(),
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

// TestAccVulnerabilitiesReport_ListOrdering verifies that pattern attributes maintain
// their order (List behavior) rather than being sorted (Set behavior).
// This is important for performance with large pattern lists.
func TestAccVulnerabilitiesReport_ListOrdering(t *testing.T) {
	reportName := fmt.Sprintf("vuln-list-ordering-%d", testutil.RandomInt())
	_, fqrn, name := testutil.MkNames(reportName, "xray_vulnerabilities_report")

	// Test repository include_path_patterns ordering
	t.Run("repository_patterns_ordering", func(t *testing.T) {
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
									include_path_patterns = ["z-pattern/*", "a-pattern/*", "m-pattern/*"]
									exclude_path_patterns = ["z-exclude/*", "a-exclude/*", "m-exclude/*"]
								}
							}
							filters {
								severities = ["Critical"]
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						// Verify include_path_patterns maintain insertion order (not alphabetically sorted)
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.0", "z-pattern/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.1", "a-pattern/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.include_path_patterns.2", "m-pattern/*"),
						// Verify exclude_path_patterns maintain insertion order (not alphabetically sorted)
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.0", "z-exclude/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.1", "a-exclude/*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.repository.0.exclude_path_patterns.2", "m-exclude/*"),
					),
				},
			},
		})
	})

	// Test builds patterns ordering
	t.Run("builds_patterns_ordering", func(t *testing.T) {
		reportName2 := fmt.Sprintf("vuln-builds-ordering-%d", testutil.RandomInt())
		_, fqrn2, name2 := testutil.MkNames(reportName2, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn2, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["zebra-*", "alpha-*", "beta-*"]
									exclude_patterns = ["zoo-*", "ant-*", "bat-*"]
									number_of_latest_versions = 3
								}
							}
							filters {
								severities = ["High"]
							}
						}
					`, name2, reportName2),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn2, "name", reportName2),
						// Verify include_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.include_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.include_patterns.0", "zebra-*"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.include_patterns.1", "alpha-*"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.include_patterns.2", "beta-*"),
						// Verify exclude_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.exclude_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.exclude_patterns.0", "zoo-*"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.exclude_patterns.1", "ant-*"),
						resource.TestCheckResourceAttr(fqrn2, "resources.0.builds.0.exclude_patterns.2", "bat-*"),
					),
				},
			},
		})
	})

	// Test release_bundles patterns ordering
	t.Run("release_bundles_patterns_ordering", func(t *testing.T) {
		reportName3 := fmt.Sprintf("vuln-rb-ordering-%d", testutil.RandomInt())
		_, fqrn3, name3 := testutil.MkNames(reportName3, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn3, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									include_patterns = ["zulu-*", "apache-*", "mysql-*"]
									exclude_patterns = ["zeta-*", "aws-*", "mongo-*"]
									number_of_latest_versions = 2
								}
							}
							filters {
								severities = ["Medium"]
							}
						}
					`, name3, reportName3),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn3, "name", reportName3),
						// Verify include_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.include_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.include_patterns.0", "zulu-*"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.include_patterns.1", "apache-*"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.include_patterns.2", "mysql-*"),
						// Verify exclude_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.exclude_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.exclude_patterns.0", "zeta-*"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.exclude_patterns.1", "aws-*"),
						resource.TestCheckResourceAttr(fqrn3, "resources.0.release_bundles.0.exclude_patterns.2", "mongo-*"),
					),
				},
			},
		})
	})

	// Test projects patterns ordering
	t.Run("projects_patterns_ordering", func(t *testing.T) {
		reportName4 := fmt.Sprintf("vuln-proj-ordering-%d", testutil.RandomInt())
		_, fqrn4, name4 := testutil.MkNames(reportName4, "xray_vulnerabilities_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn4, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_vulnerabilities_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["z-proj-*", "a-proj-*", "m-proj-*"]
									exclude_key_patterns = ["z-skip-*", "a-skip-*", "m-skip-*"]
								}
							}
							filters {
								severities = ["Low"]
							}
						}
					`, name4, reportName4),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn4, "name", reportName4),
						// Verify include_key_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.include_key_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.include_key_patterns.0", "z-proj-*"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.include_key_patterns.1", "a-proj-*"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.include_key_patterns.2", "m-proj-*"),
						// Verify exclude_key_patterns maintain insertion order
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.exclude_key_patterns.#", "3"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.exclude_key_patterns.0", "z-skip-*"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.exclude_key_patterns.1", "a-skip-*"),
						resource.TestCheckResourceAttr(fqrn4, "resources.0.projects.0.exclude_key_patterns.2", "m-skip-*"),
					),
				},
			},
		})
	})
}
