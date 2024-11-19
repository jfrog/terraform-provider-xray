package xray_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
	"github.com/samber/lo"
)

func uploadBuild(t *testing.T, name, number, projectKey string) error {
	type Build struct {
		Version string `json:"version"`
		Name    string `json:"name"`
		Number  string `json:"number"`
		Started string `json:"started"`
	}

	build := Build{
		Version: "1.0.1",
		Name:    name,
		Number:  number,
		Started: time.Now().Format("2006-01-02T15:04:05.000Z0700"),
	}

	restyClient := acctest.GetTestResty(t)

	req := restyClient.R()

	if projectKey != "" {
		req.SetQueryParam("project", projectKey)
	}

	res, err := req.
		SetBody(build).
		Put("artifactory/api/build")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

func deleteBuild(t *testing.T, name, projectKey string) error {
	type Build struct {
		Name      string `json:"buildName"`
		BuildRepo string `json:"buildRepo"`
		DeleteAll bool   `json:"deleteAll"`
	}

	build := Build{
		Name:      name,
		DeleteAll: true,
	}

	restyClient := acctest.GetTestResty(t)

	req := restyClient.R()

	if projectKey != "" {
		build.BuildRepo = fmt.Sprintf("%s-build-info", projectKey)
	}

	res, err := req.
		SetBody(build).
		Post("artifactory/api/build/delete")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

func TestAccBinaryManagerBuilds_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-builds", "xray_binary_manager_builds")

	build1Name := fmt.Sprintf("test-build-%d", testutil.RandomInt())
	build2Name := fmt.Sprintf("test-build-%d", testutil.RandomInt())

	const template = `
		resource "xray_binary_manager_builds" "{{ .name }}" {
			id = "default"
			indexed_builds = ["{{ .build1Name }}"]
		}
	`

	testData := map[string]string{
		"name":       resourceName,
		"build1Name": build1Name,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerBuilds_full", template, testData)

	const updateTemplate = `
		resource "xray_binary_manager_builds" "{{ .name }}" {
			id = "default"
			indexed_builds = ["{{ .build1Name }}", "{{ .build2Name }}"]
		}

	`
	updatedTestData := map[string]string{
		"name":       resourceName,
		"build1Name": build1Name,
		"build2Name": build2Name,
	}
	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerBuilds_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			if err := uploadBuild(t, build1Name, "1", ""); err != nil {
				t.Fatalf("failed to upload build: %s", err)
			}
			if err := uploadBuild(t, build2Name, "1", ""); err != nil {
				t.Fatalf("failed to upload build: %s", err)
			}
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			if err := deleteBuild(t, build1Name, ""); err != nil {
				return err
			}

			if err := deleteBuild(t, build2Name, ""); err != nil {
				return nil
			}

			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.0", build1Name),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.#", "2"),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_builds.*", build1Name),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_builds.*", build2Name),
				),
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

func TestAccBinaryManagerBuilds_project_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-builds", "xray_binary_manager_builds")

	projectKey := lo.RandomString(6, lo.LowerCaseLettersCharset)

	build1Name := fmt.Sprintf("test-build-%d", testutil.RandomInt())
	build2Name := fmt.Sprintf("test-build-%d", testutil.RandomInt())

	const template = `
		resource "xray_binary_manager_builds" "{{ .name }}" {
			id = "default"
			project_key = "{{ .projectKey }}"
			indexed_builds = ["{{ .build1Name }}"]
		}
	`

	testData := map[string]string{
		"name":       resourceName,
		"build1Name": build1Name,
		"projectKey": projectKey,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerBuilds_full", template, testData)

	const updateTemplate = `
		resource "xray_binary_manager_builds" "{{ .name }}" {
			id = "default"
			project_key = "{{ .projectKey }}"
			indexed_builds = ["{{ .build1Name }}", "{{ .build2Name }}"]
		}

	`
	updatedTestData := map[string]string{
		"name":       resourceName,
		"build1Name": build1Name,
		"build2Name": build2Name,
		"projectKey": projectKey,
	}

	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerBuilds_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateProject(t, projectKey)
			if err := uploadBuild(t, build1Name, "1", projectKey); err != nil {
				t.Fatalf("failed to upload build: %s", err)
			}
			if err := uploadBuild(t, build2Name, "1", projectKey); err != nil {
				t.Fatalf("failed to upload build: %s", err)
			}
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			if err := deleteBuild(t, build1Name, projectKey); err != nil {
				return err
			}

			if err := deleteBuild(t, build2Name, projectKey); err != nil {
				return nil
			}

			acctest.DeleteProject(t, projectKey)

			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.0", build1Name),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_builds.#", "2"),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_builds.*", build1Name),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_builds.*", build2Name),
				),
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

func TestAccBinaryManagerBuilds_invalid_patterns(t *testing.T) {
	invalidPatterns := []string{"*", "**", "?"}

	for _, invalidPattern := range invalidPatterns {
		t.Run(invalidPattern, func(t *testing.T) {
			_, _, resourceName := testutil.MkNames("test-bin-mgr-builds", "xray_binary_manager_builds")

			const template = `
				resource "xray_binary_manager_builds" "{{ .name }}" {
					id = "default"
					indexed_builds = ["{{ .pattern }}"]
				}
			`

			testData := map[string]string{
				"name":    resourceName,
				"pattern": invalidPattern,
			}

			config := util.ExecuteTemplate("TestAccBinaryManagerBuilds_invalid_patterns", template, testData)

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      config,
						ExpectError: regexp.MustCompile(`.*cannot contain Ant-style patterns.*`),
					},
				},
			})
		})
	}
}
