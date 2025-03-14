package xray_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
	"github.com/samber/lo"
)

func TestAccBinaryManagerRepos_full(t *testing.T) {
	testCases := []struct {
		packageType  string
		resourceType string
	}{
		{packageType: "Alpine Linux", resourceType: "artifactory_local_alpine_repository"},
		{packageType: "Bower", resourceType: "artifactory_local_bower_repository"},
		{packageType: "Cargo", resourceType: "artifactory_local_cargo_repository"},
		{packageType: "Composer", resourceType: "artifactory_local_composer_repository"},
		{packageType: "CocoaPods", resourceType: "artifactory_local_cocoapods_repository"},
		{packageType: "Conan", resourceType: "artifactory_local_conan_repository"},
		{packageType: "Conda", resourceType: "artifactory_local_conda_repository"},
		{packageType: "CRAN", resourceType: "artifactory_local_cran_repository"},
		{packageType: "Debian", resourceType: "artifactory_local_debian_repository"},
		{packageType: "Docker", resourceType: "artifactory_local_docker_v2_repository"},
		{packageType: "Gems", resourceType: "artifactory_local_gems_repository"},
		{packageType: "Generic", resourceType: "artifactory_local_generic_repository"},
		{packageType: "Go", resourceType: "artifactory_local_go_repository"},
		{packageType: "Gradle", resourceType: "artifactory_local_gradle_repository"},
		{packageType: "HuggingFaceML", resourceType: "artifactory_local_huggingfaceml_repository"},
		{packageType: "Ivy", resourceType: "artifactory_local_ivy_repository"},
		{packageType: "Maven", resourceType: "artifactory_local_maven_repository"},
		{packageType: "npm", resourceType: "artifactory_local_npm_repository"},
		{packageType: "NuGet", resourceType: "artifactory_local_nuget_repository"},
		{packageType: "OCI", resourceType: "artifactory_local_oci_repository"},
		{packageType: "Pypi", resourceType: "artifactory_local_pypi_repository"},
		{packageType: "RPM", resourceType: "artifactory_local_rpm_repository"},
		{packageType: "SBT", resourceType: "artifactory_local_sbt_repository"},
		{packageType: "TerraformBackend", resourceType: "artifactory_local_terraformbackend_repository"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.packageType, func(t *testing.T) {
			_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-repos", "xray_binary_manager_repos")
			_, _, repo1Name := testutil.MkNames(fmt.Sprintf("test-%s-local", strings.ReplaceAll(strings.ToLower(testCase.packageType), " ", "")), testCase.resourceType)
			_, _, repo2Name := testutil.MkNames("test-local-generic-repo", "artifactory_local_generic_repository")

			const template = `
				resource "{{ .resourceType }}" "{{ .repo1 }}" {
					key = "{{ .repo1 }}"
					xray_index = true
					project_key = "default"
					{{if eq .packageType "Debian"}}
					index_compression_formats = ["bz2"]
					{{end}}
					
					lifecycle {
						ignore_changes = ["project_key"]
					}
				}

				resource "xray_binary_manager_repos" "{{ .name }}" {
					id = "default"
					indexed_repos = [
						{
							name = {{ .resourceType }}.{{ .repo1 }}.key
							type = "local"
							package_type = "{{ .packageType }}"
						}
					]
				}
			`

			testData := map[string]string{
				"name":         resourceName,
				"repo1":        repo1Name,
				"resourceType": testCase.resourceType,
				"packageType":  testCase.packageType,
			}

			config := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", template, testData)

			const updateTemplate = `
				resource "{{ .resourceType }}" "{{ .repo1 }}" {
					key = "{{ .repo1 }}"
					xray_index = true
					project_key = "default"
					{{if eq .packageType "Debian"}}
					index_compression_formats = ["bz2"]
					{{end}}

					lifecycle {
						ignore_changes = ["project_key"]
					}
				}

				resource "artifactory_local_generic_repository" "{{ .repo2 }}" {
					key = "{{ .repo2 }}"
					xray_index = true
					project_key = "default"

					lifecycle {
						ignore_changes = ["project_key"]
					}
				}

				resource "xray_binary_manager_repos" "{{ .name }}" {
					id = "default"
					indexed_repos = [
						{
							name = {{ .resourceType }}.{{ .repo1 }}.key
							type = "local"
							package_type = "{{ .packageType }}"
						},
						{
							name = artifactory_local_generic_repository.{{ .repo2 }}.key
							type = "local"
							package_type = "Generic"
						}
					]
				}
			`
			updatedTestData := map[string]string{
				"name":         resourceName,
				"repo1":        repo1Name,
				"repo2":        repo2Name,
				"resourceType": testCase.resourceType,
				"packageType":  testCase.packageType,
			}
			updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", updateTemplate, updatedTestData)

			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				ExternalProviders: map[string]resource.ExternalProvider{
					"artifactory": {
						Source: "jfrog/artifactory",
					},
				},
				Steps: []resource.TestStep{
					{
						Config: config,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(fqrn, "id", "default"),
							resource.TestCheckResourceAttr(fqrn, "indexed_repos.#", "1"),
							resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.name", repo1Name),
							resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.type", "local"),
							resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.package_type", testCase.packageType),
						),
					},
					{
						Config: updatedConfig,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(fqrn, "id", "default"),
							resource.TestCheckResourceAttr(fqrn, "indexed_repos.#", "2"),
							resource.TestCheckTypeSetElemNestedAttrs(fqrn, "indexed_repos.*", map[string]string{
								"name":         repo1Name,
								"type":         "local",
								"package_type": testCase.packageType,
							}),
							resource.TestCheckTypeSetElemNestedAttrs(fqrn, "indexed_repos.*", map[string]string{
								"name":         repo2Name,
								"type":         "local",
								"package_type": "Generic",
							}),
						),
						ConfigPlanChecks: testutil.ConfigPlanChecks("xray_binary_manager_repos"),
					},
					{
						ResourceName:                         fqrn,
						ImportState:                          true,
						ImportStateId:                        resourceName,
						ImportStateVerify:                    true,
						ImportStateVerifyIdentifierAttribute: "id",
					},
				},
			})
		})
	}
}

func TestAccBinaryManagerRepos_project_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-repos", "xray_binary_manager_repos")
	_, _, repo1Name := testutil.MkNames("test-local-generic-repo", "artifactory_local_generic_repository")
	_, _, repo2Name := testutil.MkNames("test-local-docker-repo", "artifactory_local_docker_v2_repository")
	_, _, repo3Name := testutil.MkNames("test-local-npm-repo", "artifactory_local_npm_repository")
	_, _, projectName := testutil.MkNames("test-project", "project")

	projectKey := lo.RandomString(6, lo.LowerCaseLettersCharset)

	const template = `
		resource "artifactory_local_generic_repository" "{{ .repo1 }}" {
			key = "{{ .repo1 }}"
			project_environments = ["DEV"]
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key", "project_environments"]
			}
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
			key = "{{ .repo2 }}"
			project_environments = ["DEV"]
			xray_index = false

			lifecycle {
				ignore_changes = ["project_key", "project_environments"]
			}
		}

		resource "project" "{{ .projectName }}" {
			key = "{{ .projectKey }}"
			display_name = "{{ .projectName }}"
			admin_privileges {
				manage_members = true
				manage_resources = true
				index_resources = true
			}
		}

		resource "project_repository" "{{ .projectKey }}-{{ .repo1 }}" {
			project_key = project.{{ .projectName }}.key
			key = artifactory_local_generic_repository.{{ .repo1 }}.key
		}

		resource "project_repository" "{{ .projectKey }}-{{ .repo2 }}" {
			project_key = project.{{ .projectName }}.key
			key = artifactory_local_docker_v2_repository.{{ .repo2 }}.key
		}

		resource "xray_binary_manager_repos" "{{ .name }}" {
			id = "default"
			project_key = project.{{ .projectName }}.key
			indexed_repos = [
				{
					name = artifactory_local_generic_repository.{{ .repo1 }}.key
					type = "local"
					package_type = "Generic"
				}
			]

			depends_on = [
				project_repository.{{ .projectKey }}-{{ .repo1 }},
			]
		}
	`

	testData := map[string]string{
		"name":        resourceName,
		"repo1":       repo1Name,
		"repo2":       repo2Name,
		"projectName": projectName,
		"projectKey":  projectKey,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", template, testData)

	const updateTemplate = `
		resource "artifactory_local_generic_repository" "{{ .repo1 }}" {
			key = "{{ .repo1 }}"
			project_environments = ["DEV"]
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key", "project_environments"]
			}
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
			key = "{{ .repo2 }}"
			project_environments = ["DEV"]
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key", "project_environments"]
			}
		}

		resource "project" "{{ .projectName }}" {
			key = "{{ .projectKey }}"
			display_name = "{{ .projectName }}"
			admin_privileges {
				manage_members = true
				manage_resources = true
				index_resources = true
			}
		}

		resource "project_repository" "{{ .projectKey }}-{{ .repo1 }}" {
			project_key = project.{{ .projectName }}.key
			key = artifactory_local_generic_repository.{{ .repo1 }}.key
		}

		resource "project_repository" "{{ .projectKey }}-{{ .repo2 }}" {
			project_key = project.{{ .projectName }}.key
			key = artifactory_local_docker_v2_repository.{{ .repo2 }}.key
		}

		resource "xray_binary_manager_repos" "{{ .name }}" {
			id = "default"
			project_key = project.{{ .projectName }}.key
			indexed_repos = [
				{
					name = artifactory_local_generic_repository.{{ .repo1 }}.key
					type = "local"
					package_type = "Generic"
				},
				{
					name = artifactory_local_docker_v2_repository.{{ .repo2 }}.key
					type = "local"
					package_type = "Docker"
				}
			]

			depends_on = [
				project_repository.{{ .projectKey }}-{{ .repo1 }},
				project_repository.{{ .projectKey }}-{{ .repo2 }},
			]
		}
	`
	updatedTestData := map[string]string{
		"name":        resourceName,
		"repo1":       repo1Name,
		"repo2":       repo2Name,
		"repo3":       repo3Name,
		"projectName": projectName,
		"projectKey":  projectKey,
	}
	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source: "jfrog/artifactory",
			},
			"project": {
				Source: "jfrog/project",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.name", repo1Name),
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.type", "local"),
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.package_type", "Generic"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "indexed_repos.*", map[string]string{
						"name":         repo1Name,
						"type":         "local",
						"package_type": "Generic",
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "indexed_repos.*", map[string]string{
						"name":         repo2Name,
						"type":         "local",
						"package_type": "Docker",
					}),
				),
				ConfigPlanChecks: testutil.ConfigPlanChecks("xray_binary_manager_repos"),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("%s:%s", resourceName, projectKey),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}
