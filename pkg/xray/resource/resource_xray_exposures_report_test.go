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

func TestAccExposuresReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("exp_repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-repo-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
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
								impacted_artifact = "*spring*"
								category = "secrets"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "secrets"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("exp_repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-repo-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
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
								impacted_artifact = "*spring*"
								category = "services"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "services"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccExposuresReport_Build(t *testing.T) {
	// Test case for builds by name
	t.Run("exp_builds_by_name", func(t *testing.T) {
		build1Name := fmt.Sprintf("exp-build-1-%d", testutil.RandomInt())
		build2Name := fmt.Sprintf("exp-build-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("exp-build-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["%s", "%s"]
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "applications"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "applications"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("exp_builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-build-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["build-*", "release-*"]
									exclude_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "iac"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "iac"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccExposuresReport_ReleaseBundle(t *testing.T) {
	// Test case for release bundles by name
	t.Run("exp_release_bundles_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("exp-release-bundle-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("exp-release-bundle-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("exp-release-bundle-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									names = ["%s", "%s"]
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "secrets"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "secrets"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("exp_release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-release-bundle-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									include_patterns = ["prod-*", "release-*"]
									exclude_patterns = ["dev-*", "test-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "services"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "services"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccExposuresReport_ReleaseBundleV2(t *testing.T) {
	// Test case for release bundles v2 by name
	t.Run("exp_release_bundles_v2_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("exp-release-bundle-v2-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("exp-release-bundle-v2-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("exp-release-bundle-v2-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									names = ["%s", "%s"]
									number_of_latest_versions = 3
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "secrets"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "secrets"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// // Test case for release bundles v2 by pattern
	t.Run("exp_release_bundles_v2_by_pattern", func(t *testing.T) {
		// Skip test if Xray version is lower than 3.130.0
		version, err := util.CheckXrayVersion(acctest.GetTestResty(t), FixVersionForReleaseBundleV2, "")
		if err != nil || version < FixVersionForReleaseBundleV2 {
			t.Skipf("Skipping test: requires Xray version %s or higher", FixVersionForReleaseBundleV2)
			return
		}

		reportName := fmt.Sprintf("exp-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									include_patterns = ["v2.*-release", "v2.*-hotfix"]
									exclude_patterns = ["*-snapshot", "*-rc"]
									number_of_latest_versions = 5
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "services"
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
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", "v2.*-hotfix"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", "v2.*-release"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", "*-rc"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", "*-snapshot"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "services"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccExposuresReport_Project(t *testing.T) {
	// Test case for project by name
	t.Run("exp_project_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-project-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

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
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								projects {%s
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "iac"
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
							resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
							resource.TestCheckResourceAttr(fqrn, "filters.0.category", "iac"),
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
	t.Run("exp_project_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-project-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["dev-*", "test-*"]
									exclude_key_patterns = ["prod-*", "staging-*"]
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "services"
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.impacted_artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.category", "services"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccExposuresReport_Invalid(t *testing.T) {
	// Test case for empty category array
	t.Run("exp_empty_category", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-empty-category-%d", testutil.RandomInt())
		_, _, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local"
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = ""
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*value must be one of: \["secrets" "services" "applications" "iac"\], got: "".*`),
				},
			},
		})
	})

	// Test case for invalid category value
	t.Run("exp_invalid_category", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-invalid-category-%d", testutil.RandomInt())
		_, _, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local"
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "invalid"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*value must be one of: \["secrets" "services" "applications" "iac"\], got:\s+"invalid".*`),
				},
			},
		})
	})

	// Test case for invalid scan date format
	t.Run("exp_invalid_scan_date", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-invalid-scan-date-%d", testutil.RandomInt())
		_, _, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
				resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "docker-local"
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "secrets"
								scan_date {
									start = "2023/01/01"
									end = "2023/12/31"
								}
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Value must be a valid RFC3339 date.*`),
				},
			},
		})
	})

	// Test case for project names and patterns together
	t.Run("exp_project_names_and_patterns", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-project-names-patterns-%d", testutil.RandomInt())
		_, _, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["test-project"]
									include_key_patterns = ["test-*"]
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "secrets"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})

	// Test case for build names and patterns together
	t.Run("exp_build_names_and_patterns", func(t *testing.T) {
		reportName := fmt.Sprintf("exp-build-names-patterns-%d", testutil.RandomInt())
		_, _, name := testutil.MkNames(reportName, "xray_exposures_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_exposures_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["test-build"]
									include_patterns = ["test-*"]
								}
							}
							filters {
								impacted_artifact = "*spring*"
								category = "secrets"
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})
}
