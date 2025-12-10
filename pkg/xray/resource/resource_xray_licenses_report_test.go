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

func TestAccLicensesReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("license_repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("license-repo-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
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
								component = "*log4j*"
								artifact = "*spring*"
								license_names = ["Apache-2.0", "MIT"]
								unrecognized = true
								unknown = false
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.1", "MIT"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("license_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("license-repo-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
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
								component = "*log4j*"
								artifact = "*spring*"
								license_patterns = ["*GPL*", "*MIT*"]
								unrecognized = false
								unknown = true
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.1", "*MIT*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccLicensesReport_Build(t *testing.T) {
	// Test case for builds by name
	t.Run("license_builds_by_name", func(t *testing.T) {
		build1Name := fmt.Sprintf("license-build-1-%d", testutil.RandomInt())
		build2Name := fmt.Sprintf("license-build-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("license-build-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_names = ["Apache-2.0", "MIT"]
								unrecognized = true
								unknown = true
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.1", "MIT"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("license_builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("license-build-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["build-*", "release-*"]
									exclude_patterns = ["dev-*","test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_patterns = ["*GPL*", "*MIT*"]
								unrecognized = true
								unknown = true
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.1", "*MIT*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccLicensesReport_ReleaseBundle(t *testing.T) {
	// Test case for release bundles v1 by name
	t.Run("license_release_bundles_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("license-release-bundle-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("license-release-bundle-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("license-release-bundle-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_names = ["Apache-2.0", "MIT"]
								unrecognized = false
								unknown = false
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.1", "MIT"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("license_release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("license-release-bundle-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									include_patterns = ["prod-*", "release-*"]
									exclude_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_patterns = ["*GPL*", "*MIT*"]
								unrecognized = true
								unknown = false
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.1", "*MIT*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

}

func TestAccLicensesReport_ReleaseBundleV2(t *testing.T) {
	// Test case for release bundles v2 by name
	t.Run("license_release_bundles_v2_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("license-release-bundle-v2-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("license-release-bundle-v2-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("license-release-bundle-v2-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_names = ["Apache-2.0", "MIT"]
								unrecognized = false
								unknown = false
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.0", "Apache-2.0"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.1", "MIT"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles v2 by pattern
	t.Run("license_release_bundles_v2_by_pattern", func(t *testing.T) {
		// Skip test if Xray version is lower than 3.130.0
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), FixVersionForReleaseBundleV2, "")
		if err != nil || version < FixVersionForReleaseBundleV2 {
			t.Skipf("Skipping test: requires Xray version %s or higher", FixVersionForReleaseBundleV2)
			return
		}
		reportName := fmt.Sprintf("license-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									include_patterns = ["prod-*", "release-*"]
									exclude_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_patterns = ["*GPL*", "*MIT*"]
								unrecognized = true
								unknown = false
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", "prod-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", "release-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", "dev-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", "test-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.1", "*MIT*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccLicensesReport_Project(t *testing.T) {
	// Test case for projects by name
	t.Run("license_projects_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("license-project-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

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
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								projects {%s
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_names = ["Apache-2.0", "MIT"]
								unrecognized = false
								unknown = false
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.#", "2"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.0", "Apache-2.0"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.license_names.1", "MIT"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "false"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
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

	// Test case for projects by pattern
	t.Run("license_projects_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("license-project-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_licenses_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["prod-*", "release-*"]
									exclude_key_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								license_patterns = ["*GPL*", "*MIT*"]
								unrecognized = true
								unknown = false
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
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.0", "prod-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.include_key_patterns.1", "release-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.0", "dev-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.exclude_key_patterns.1", "test-*"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.0", "*GPL*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.license_patterns.1", "*MIT*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unrecognized", "true"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.unknown", "false"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccLicensesReport_Invalid(t *testing.T) {
	reportName := fmt.Sprintf("license-invalid-report-%d", testutil.RandomInt())
	_, _, name := testutil.MkNames(reportName, "xray_licenses_report")

	t.Run("empty_name", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = ""
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								license_names = ["MIT"]
								unrecognized = true
								unknown = false
							}
						}
					`, name),
					ExpectError: regexp.MustCompile(`(?s).*Attribute name string length must be at least 1.*`),
				},
			},
		})
	})

	t.Run("empty_license_names", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								license_names = []
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*set must contain at least 1 elements, got: 0.*`),
				},
			},
		})
	})

	t.Run("license_names_and_patterns", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								license_names = ["MIT"]
								license_patterns = ["*GPL*"]
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Attribute.*license_patterns.*cannot be specified when.*license_names.*is specified.*`),
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
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["test-project"]
									include_key_patterns = ["test-*"]
								}
							}
							filters {
								license_names = ["MIT"]
								unrecognized = true
								unknown = false
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
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["test-build"]
									include_patterns = ["test-*"]
								}
							}
							filters {
								license_names = ["MIT"]
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})

	t.Run("invalid_scan_date_format", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								license_names = ["MIT"]
								scan_date {
									start = "2023/01/01"
									end = "2023/12/31"
								}
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Value must be a valid RFC3339 date.*`),
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
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								license_names = ["MIT"]
								scan_date {
									start = "2023-12-31T00:00:00Z"
									end = "2023-01-01T00:00:00Z"
								}
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid scan_date range.*End date must be after start date.*`),
				},
			},
		})
	})

	t.Run("invalid_number_of_latest_versions", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["test-*"]
									number_of_latest_versions = 0
								}
							}
							filters {
								license_names = ["MIT"]
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Attribute.*number_of_latest_versions.*value must be at least 1, got: 0.*`),
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
						resource "xray_licenses_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
								builds {
									names = ["test-build"]
								}
							}
							filters {
								license_names = ["MIT"]
								unrecognized = true
								unknown = false
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*Attribute.*resources.*builds.*cannot be specified when.*resources.*repository.*is specified.*`),
				},
			},
		})
	})
}
