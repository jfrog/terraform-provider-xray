package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

func TestAccOperationalRisksReport_Repository(t *testing.T) {
	// Test case for repository by name
	t.Run("opsrisk-repository_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-repo-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
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
								risks = ["None", "Low", "High", "Medium"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "4"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.2", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.3", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for repository by pattern
	t.Run("opsrisk-repository_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-repo-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
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
								risks = ["None", "Low", "High", "Medium"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "4"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.2", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.3", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccOperationalRisksReport_Build(t *testing.T) {
	// Test case for builds by name
	t.Run("opsrisk-builds_by_name", func(t *testing.T) {
		build1Name := fmt.Sprintf("opsrisk-build-1-%d", testutil.RandomInt())
		build2Name := fmt.Sprintf("opsrisk-build-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("opsrisk-build-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create operational risks report for builds by name
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["Low", "High"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for builds by pattern
	t.Run("opsrisk-builds_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-build-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create operational risks report for builds by pattern
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								builds {
									include_patterns = ["build-*", "release-*"]
									exclude_patterns = ["test-*", "dev-*"]
									number_of_latest_versions = 5
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["None", "Low", "High"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "3"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.2", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccOperationalRisksReport_ReleaseBundle(t *testing.T) {
	// Test case for release bundles by name
	t.Run("opsrisk-release_bundles_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("opsrisk-release-bundle-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("opsrisk-release-bundle-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("opsrisk-release-bundle-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create operational risks report for release bundles by name
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								release_bundles {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["None", "Medium"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles by pattern
	t.Run("opsrisk-release_bundles_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-release-bundle-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create operational risks report for release bundles by pattern
						resource "xray_operational_risks_report" "%s" {
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
								risks = ["None", "Medium"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccOperationalRisksReport_ReleaseBundleV2(t *testing.T) {
	// Test case for release bundles v2 by name
	t.Run("opsrisk-release_bundles_v2_by_name", func(t *testing.T) {
		releaseBundle1Name := fmt.Sprintf("opsrisk-release-bundle-v2-1-%d", testutil.RandomInt())
		releaseBundle2Name := fmt.Sprintf("opsrisk-release-bundle-v2-2-%d", testutil.RandomInt())
		reportName := fmt.Sprintf("opsrisk-release-bundle-v2-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						# Create operational risks report for release bundles v2 by name
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								release_bundles_v2 {
									names = ["%s", "%s"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["None", "Medium"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "Medium"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for release bundles v2 by pattern
	// t.Run("opsrisk-release_bundles_v2_by_pattern", func(t *testing.T) {
	// 	reportName := fmt.Sprintf("opsrisk-release-bundle-v2-by-pattern-%d", testutil.RandomInt())
	// 	_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

	// 	resource.Test(t, resource.TestCase{
	// 		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
	// 		CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
	// 		Steps: []resource.TestStep{
	// 			{
	// 				Config: fmt.Sprintf(`
	// 					# Create operational risks report for release bundles v2 by pattern
	// 					resource "xray_operational_risks_report" "%s" {
	// 						name = "%s"
	// 						resources {
	// 							release_bundles_v2 {
	// 								include_patterns = ["v2.*-release", "v2.*-hotfix"]
	// 								exclude_patterns = ["*-snapshot", "*-rc"]
	// 								number_of_latest_versions = 5
	// 							}
	// 						}
	// 						filters {
	// 							component = "*log4j*"
	// 							artifact = "*spring*"
	// 							risks = ["None", "Medium"]
	// 							scan_date {
	// 								start = "2020-06-29T12:22:16Z"
	// 								end = "2020-07-29T12:22:16Z"
	// 							}
	// 						}
	// 					}
	// 				`, name, reportName),
	// 				Check: resource.ComposeTestCheckFunc(
	// 					resource.TestCheckResourceAttr(fqrn, "name", reportName),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.0", "v2.*-release"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.include_patterns.1", "v2.*-hotfix"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.0", "*-snapshot"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.exclude_patterns.1", "*-rc"),
	// 					resource.TestCheckResourceAttr(fqrn, "resources.0.release_bundles_v2.0.number_of_latest_versions", "5"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "2"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "Medium"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "None"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
	// 					resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
	// 				),
	// 			},
	// 		},
	// 	})
	// })
}

func TestAccOperationalRisksReport_Project(t *testing.T) {
	// Test case for project by name
	t.Run("opsrisk-project_by_name", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-project-by-name-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["test-project-1", "test-project-2"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["None", "Low", "High"]
								scan_date {
									start = "2020-06-29T12:22:16Z"
									end = "2020-07-29T12:22:16Z"
								}
							}
						}
					`, name, reportName),
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(fqrn, "name", reportName),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.#", "2"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.0", "test-project-1"),
						resource.TestCheckResourceAttr(fqrn, "resources.0.projects.0.names.1", "test-project-2"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "3"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.2", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})

	// Test case for project by pattern
	t.Run("opsrisk-project_by_pattern", func(t *testing.T) {
		reportName := fmt.Sprintf("opsrisk-project-by-pattern-%d", testutil.RandomInt())
		_, fqrn, name := testutil.MkNames(reportName, "xray_operational_risks_report")

		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			//CheckDestroy:             acctest.VerifyDeleted(fqrn, "report_id", acctest.CheckReport),
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								projects {
									include_key_patterns = ["dev-*", "test-*"]
									exclude_key_patterns = ["prod-*", "staging-*"]
								}
							}
							filters {
								component = "*log4j*"
								artifact = "*spring*"
								risks = ["None", "Low", "High"]
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
						resource.TestCheckResourceAttr(fqrn, "filters.0.component", "*log4j*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.artifact", "*spring*"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.#", "3"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.0", "High"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.1", "Low"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.risks.2", "None"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.start", "2020-06-29T12:22:16Z"),
						resource.TestCheckResourceAttr(fqrn, "filters.0.scan_date.0.end", "2020-07-29T12:22:16Z"),
					),
				},
			},
		})
	})
}

func TestAccOperationalRisksReport_Invalid(t *testing.T) {
	reportName := fmt.Sprintf("opsrisk-invalid-report-%d", testutil.RandomInt())
	_, _, name := testutil.MkNames(reportName, "xray_operational_risks_report")

	t.Run("invalid_risk_level", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								risks = ["Invalid"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*value must be one of: \["None" "Low" "Medium" "High"\], got: "Invalid".*`),
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
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								projects {
									names = ["test-project"]
									include_key_patterns = ["test-*"]
								}
							}
							filters {
								risks = ["High"]
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
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								builds {
									names = ["test-build"]
									include_patterns = ["test-*"]
								}
							}
							filters {
								risks = ["High"]
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*Invalid Attribute Combination.*`),
				},
			},
		})
	})

	t.Run("empty_risks_array", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								risks = []
							}
						}
					`, name, reportName),
					ExpectError: regexp.MustCompile(`(?s).*set must contain at least 1 elements.*`),
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
						resource "xray_operational_risks_report" "%s" {
							name = "%s"
							resources {
								repository {
									name = "libs-release-local"
								}
							}
							filters {
								risks = ["High"]
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

	t.Run("invalid_scan_date_range", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: fmt.Sprintf(`
						resource "xray_operational_risks_report" "%s" {
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
}
