package xray_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

const (
	FixVersionForProjectScopeKey     = "3.130.0"
	FixVersionForReleaseBundleV2     = "3.130.0"
	MinVersionForCAAndRuntimeFilters = "3.130.0"
	MinVersionForCronAndNotify       = "3.130.0"
	RuntimeFilterEnvVar              = "XRAY_RUNTIME_FILTER_ENABLED"
)

func isRuntimeFilterEnabled() bool {
	val := os.Getenv(RuntimeFilterEnvVar)
	return val == "true" // disabled by default unless explicitly enabled
}

func TestAccViolationsReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("violations_repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-repo-by-name-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		issueId := fmt.Sprintf("XRAY-%06d", testutil.RandomInt()%1000000)
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
				resource "xray_violations_report" "%s" {
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
								min_score = 7.6
								max_score = 8.7
							}
							summary_contains = "%s"
							has_remediation = true
							published {
								start = "2023-01-01T00:00:00Z"
								end = "2023-12-31T23:59:59Z"
							}
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, watchName, policyName, componentName, artifactName, issueId, summaryText, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "7.6"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "8.7"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "true"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
							// Date range checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
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
	t.Run("violations_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-repo-by-pattern-%d", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
				resource "xray_violations_report" "%s" {
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
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, watchPattern, policyName, componentName, artifactName, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
		issueId := fmt.Sprintf("XRAY-%06d", testutil.RandomInt()%1000000)
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
						violation_status = "Active"
						severities = ["Critical", "High"]
						security_filters {
							issue_id = "%s"
							cvss_score {
								min_score = 7.7
								max_score = 10
							}
							summary_contains = "%s"
							has_remediation = false
							published {
								start = "2023-01-01T00:00:00Z"
								end = "2023-12-31T23:59:59Z"
							}
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, buildName1, buildName2, watchName, policyName, componentName, artifactName, issueId, summaryText, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Active"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "Critical"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "High"),
							// Security filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.issue_id", issueId),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "7.7"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "10"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
							// Date range checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
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

		// Check if Xray version supports extended features
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), MinVersionForCAAndRuntimeFilters, "")

		var extendedFilters string
		if err == nil && version >= MinVersionForCAAndRuntimeFilters {
			extendedFilters = `
						ca_filter {
							allowed_ca_statuses = ["applicable", "undetermined", "not_covered"]
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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
						violation_status = "Ignored"
						severities = ["Low", "High"]
						security_filters {
							cve = "%s"
							cvss_score {
								min_score = 4.6
								max_score = 6.8
							}
							summary_contains = "%s"
							has_remediation = false
							published {
								start = "2023-01-01T00:00:00Z"
								end = "2023-12-31T23:59:59Z"
							}
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, buildPattern1, buildPattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, cveId, summaryText, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "High"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Low"),
							// Security filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cve", cveId),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "4.6"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "6.8"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
							// Date range checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.0", "applicable"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.1", "not_covered"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.ca_filter.0.allowed_ca_statuses.2", "undetermined"),
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
		issueId := fmt.Sprintf("XRAY-%06d", testutil.RandomInt()%1000000)
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
								min_score = 5.6
								max_score = 6.5
							}
							summary_contains = "%s"
							has_remediation = true
							published {
								start = "2023-01-01T00:00:00Z"
								end = "2023-12-31T23:59:59Z"
							}
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, bundleName1, bundleName2, watchName, policyName, componentName, artifactName, issueId, summaryText, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "5.6"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "6.5"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "true"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
							// Date range checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, bundlePattern1, bundlePattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
						severities = [ "High", "Critical" ]%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, bundleName1, bundleName2, watchName, policyName, componentName, artifactName, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
	t.Run("violations_release_bundles_v2_by_pattern", func(t *testing.T) {
		// Skip test if Xray version is lower than 3.130.0
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), FixVersionForReleaseBundleV2, "")
		if err != nil || version < FixVersionForReleaseBundleV2 {
			t.Skipf("Skipping test: requires Xray version %s or higher", FixVersionForReleaseBundleV2)
			return
		}

		reportName := fmt.Sprintf("violations-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
		bundlePattern1 := fmt.Sprintf("bundle-pattern-v2-%d-*", testutil.RandomInt())
		bundlePattern2 := fmt.Sprintf("release-pattern-v2-%d-*", testutil.RandomInt())
		excludePattern1 := fmt.Sprintf("dev-pattern-v2-%d-*", testutil.RandomInt())
		excludePattern2 := fmt.Sprintf("test-pattern-v2-%d-*", testutil.RandomInt())
		watchPattern := fmt.Sprintf("watch-pattern-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		cveId := fmt.Sprintf("CVE-2023-%d", testutil.RandomInt())
		summaryText := fmt.Sprintf("summary-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
					cron_schedule = "00 03 * * TUE"
					cron_schedule_timezone = "Asia/Singapore"
					emails = ["support1@example.com", "support2@example.com"]`
		}

		config := fmt.Sprintf(`
				resource "xray_violations_report" "%s" {
					name = "%s"%s
					resources {
						release_bundles_v2 {
							include_patterns = ["%s", "%s"]
							exclude_patterns = ["%s", "%s"]
							number_of_latest_versions = 5
						}
					}
					filters {
						type = "security"
						watch_patterns = ["%s"]
						policy_names = ["%s"]
						component = "%s"
						artifact = "%s"
						violation_status = "Ignored"
						severities = ["High", "Medium"]
						security_filters {
							cve = "%s"
							cvss_score {
								min_score = 4.2
								max_score = 6.8
							}
							summary_contains = "%s"
							has_remediation = false
							published {
								start = "2023-01-01T00:00:00Z"
								end = "2023-12-31T23:59:59Z"
							}
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, bundlePattern1, bundlePattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, cveId, summaryText, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "name", reportName),
							// Resource checks
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", bundlePattern1),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", bundlePattern2),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", excludePattern1),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", excludePattern2),
							resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
							// Filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.type", "security"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.#", "1"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.watch_patterns.0", watchPattern),
							resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.#", "1"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.policy_names.0", policyName),
							resource.TestCheckResourceAttr(fqrn, "filters.0.component", componentName),
							resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", artifactName),
							resource.TestCheckResourceAttr(fqrn, "filters.0.violation_status", "Ignored"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.0", "High"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.severities.1", "Medium"),
							// Security filter checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cve", cveId),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.min_score", "4.2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.cvss_score.0.max_score", "6.8"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.summary_contains", summaryText),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.has_remediation", "false"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.security_filters.0.published.0.end", "2023-12-31T23:59:59Z"),
							// Date range checks
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.start", "2023-01-01T00:00:00Z"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.updated.0.end", "2023-12-31T23:59:59Z"),
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "00 03 * * TUE"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Asia/Singapore"),
							// Email checks
							resource.TestCheckResourceAttr(fqrn, "emails.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "emails.0", "support1@example.com"),
							resource.TestCheckResourceAttr(fqrn, "emails.1", "support2@example.com"),
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
}

func TestAccViolationsReport_Project(t *testing.T) {
	// Test case for projects by name
	t.Run("violations_projects_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("violations-project-by-name-%d", testutil.RandomInt())
		watchName := fmt.Sprintf("watch-%d", testutil.RandomInt())
		policyName := fmt.Sprintf("policy-%d", testutil.RandomInt())
		componentName := fmt.Sprintf("component-%d", testutil.RandomInt())
		artifactName := fmt.Sprintf("artifact-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_violations_report")

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
					cron_schedule = "15 06 * * WED"
					cron_schedule_timezone = "Pacific/Auckland"
					emails = ["project1@example.com", "project2@example.com"]`
		}

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

		config := fmt.Sprintf(`
				resource "xray_violations_report" "%s" {
					name = "%s"%s
					resources {
						projects {%s
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
						}%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, projectConfig, watchName, policyName, componentName, artifactName, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
							resource.TestCheckResourceAttr(fqrn, "name", reportName),
							// Resource checks
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
						}

						extendedChecks := []resource.TestCheckFunc{
							// Cron schedule checks
							resource.TestCheckResourceAttr(fqrn, "cron_schedule", "15 06 * * WED"),
							resource.TestCheckResourceAttr(fqrn, "cron_schedule_timezone", "Pacific/Auckland"),
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
				resource "xray_violations_report" "%s" {
					name = "%s"%s
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
						severities = [ "Low", "Medium" ]%s
						updated {
							start = "2023-01-01T00:00:00Z"
							end = "2023-12-31T23:59:59Z"
						}
					}
				}
			`, name, reportName, extendedAttrs, projectPattern1, projectPattern2, excludePattern1, excludePattern2, watchPattern, policyName, componentName, artifactName, fmt.Sprintf("%s%s", extendedFilters, runtimeFilter))

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: config,
					Check: func() resource.TestCheckFunc {
						baseChecks := []resource.TestCheckFunc{
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
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value Match.*Attribute\s+filters\[Value\(\{.*\}\)\]\.type\s+value must be one of: \["security" "license" "malicious" "operational_risk"\],\s+got: "invalid"`),
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

	t.Run("invalid_issue_id_format", func(t *testing.T) {
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
									issue_id = "XRAY-1234567"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`invalid Issue ID, must be a valid Issue ID, example XRAY-123456`),
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
									issue_id = "XRAY-1234567"
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

	t.Run("empty_emails", func(t *testing.T) {
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
							}
							emails = []
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile("Attribute emails set must contain at least 1 elements"),
				},
			},
		})
	})

	t.Run("invalid_cron_schedule", func(t *testing.T) {
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
							}
							cron_schedule = "10 03 * * MON"
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value.*Attribute cron_schedule Invalid minute in cron expression, got: The minute\s+field must be one of: 00, 15, 30, 45\. Got: 10\. Minutes must be exactly 00,\s+15, 30, or 45`),
				},
			},
		})
	})

	t.Run("invalid_cron_timezone", func(t *testing.T) {
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
							}
							cron_schedule = "00 03 * * MON"
							cron_schedule_timezone = "Invalid/Timezone"
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s)Error: Invalid Attribute Value.*Attribute cron_schedule_timezone Invalid timezone, got: Invalid/Timezone\.\s+Must be a valid IANA timezone\. For valid timezone formats, see:\s+https://timeapi\.io/documentation/iana-timezones`),
				},
			},
		})
	})
}
