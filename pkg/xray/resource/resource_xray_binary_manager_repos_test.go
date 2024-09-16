package xray_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
	"github.com/samber/lo"
)

func TestAccBinaryManagerRepos_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-repos", "xray_binary_manager_repos")
	_, _, repo1Name := testutil.MkNames("test-local-generic-repo", "artifactory_local_generic_repository")
	_, _, repo2Name := testutil.MkNames("test-local-docker-repo", "artifactory_local_docker_repository")
	_, _, repo3Name := testutil.MkNames("test-local-npm-repo", "artifactory_local_npm_repository")

	const template = `
		resource "artifactory_local_generic_repository" "{{ .repo1 }}" {
			key = "{{ .repo1 }}"
			xray_index = true
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
			key = "{{ .repo2 }}"
			xray_index = false
		}

		resource "xray_binary_manager_repos" "{{ .name }}" {
			id = "default"
			indexed_repos = [
				{
					name = artifactory_local_generic_repository.{{ .repo1 }}.key
					type = "local"
					package_type = "Generic"
				}
			]
		}
	`

	testData := map[string]string{
		"name":  resourceName,
		"repo1": repo1Name,
		"repo2": repo2Name,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", template, testData)

	const updateTemplate = `
		resource "artifactory_local_generic_repository" "{{ .repo1 }}" {
		  key = "{{ .repo1 }}"
		  xray_index = true
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
		  key = "{{ .repo2 }}"
		  xray_index = true
		}

		resource "artifactory_local_npm_repository" "{{ .repo3 }}" {
		  key = "{{ .repo3 }}"
		}

		resource "xray_binary_manager_repos" "{{ .name }}" {
			id = "default"
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
		}
	`
	updatedTestData := map[string]string{
		"name":  resourceName,
		"repo1": repo1Name,
		"repo2": repo2Name,
		"repo3": repo3Name,
	}
	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerRepos_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
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
					resource.TestCheckResourceAttr(fqrn, "indexed_repos.0.package_type", "Generic"),
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
				ImportStateId:                        resourceName,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
		},
	})
}

func TestAccBinaryManagerRepos_project_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-repos", "xray_binary_manager_repos")
	_, _, repo1Name := testutil.MkNames("test-local-generic-repo", "artifactory_local_generic_repository")
	_, _, repo2Name := testutil.MkNames("test-local-docker-repo", "artifactory_local_docker_repository")
	_, _, repo3Name := testutil.MkNames("test-local-npm-repo", "artifactory_local_npm_repository")
	_, _, projectName := testutil.MkNames("test-project", "project")

	projectKey := lo.RandomString(6, lo.LowerCaseLettersCharset)

	const template = `
		resource "artifactory_local_generic_repository" "{{ .repo1 }}" {
			key = "{{ .repo1 }}"
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key"]
			}
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
			key = "{{ .repo2 }}"
			xray_index = false

			lifecycle {
				ignore_changes = ["project_key"]
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
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key"]
			}
		}

		resource "artifactory_local_docker_v2_repository" "{{ .repo2 }}" {
			key = "{{ .repo2 }}"
			xray_index = true

			lifecycle {
				ignore_changes = ["project_key"]
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
