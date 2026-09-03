package xray_test

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
	xrayresource "github.com/jfrog/terraform-provider-xray/v3/pkg/xray/resource"
	"github.com/samber/lo"
)

type releaseBundleV2 struct {
	Name                         string                `json:"release_bundle_name"`
	Version                      string                `json:"release_bundle_version"`
	SkipDockerManifestResolution bool                  `json:"skip_docker_manifest_resolution"`
	SourceType                   string                `json:"source_type"`
	Source                       releaseBundleV2Source `json:"source"`
}

type releaseBundleV2Source struct {
	Artifacts []releaseBundleV2SourceArtifact `json:"artifacts"`
}

type releaseBundleV2SourceArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func createReleaseBundleV2(t *testing.T, name, keyPairName, repoName, projectKey, artifactPath, artifactSHA string) error {
	releaseBundle := releaseBundleV2{
		Name:                         name,
		Version:                      "1.0.0",
		SkipDockerManifestResolution: true,
		SourceType:                   "artifacts",
		Source: releaseBundleV2Source{
			Artifacts: []releaseBundleV2SourceArtifact{
				{
					Path:   fmt.Sprintf("%s%s", repoName, artifactPath),
					SHA256: artifactSHA,
				},
			},
		},
	}

	request := acctest.GetTestResty(t).R().
		SetHeader("X-JFrog-Signing-Key-Name", keyPairName).
		SetQueryParam("async", "false").
		SetBody(releaseBundle)

	if projectKey != "" {
		request.SetQueryParam("project", projectKey)
	}

	res, err := request.
		Post("lifecycle/api/v2/release_bundle")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

func deleteReleaseBundleV2Version(t *testing.T, name, projectKey string) error {
	request := acctest.GetTestResty(t).R().
		SetPathParam("name", name)

	if projectKey != "" {
		request.SetQueryParam("project", projectKey)
	}

	res, err := request.
		Delete("lifecycle/api/v2/release_bundle/records/{name}/1.0.0")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

type KeyPair struct {
	PairName   string `json:"pairName"`
	PairType   string `json:"pairType"`
	Alias      string `json:"alias"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`
	PublicKey  string `json:"publicKey"`
}

func createKeyPair(t *testing.T, name string) error {
	keyPair := KeyPair{
		PairName: name,
		Alias:    name,
		PairType: "RSA",
		PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2ymVc24BoaZb0ElXoI3X4zUKJGZEetR6F4yT1tJhkPDg7UTm
iNoFB5TZJvP6LBrrSwszkpZbxaVOkBrwrGbqFUaXPgud8VabfHl0imXvN746zmpj
YEMGqJzm+Gh6aBWOlnPdLuHhds/kcanFAEppj5yN0tVWDnqjOJjR7EpxMSdP3TSd
6tNAY73LGNLNJQc6tSxh8nMIb4HhSWQSgfof+FwcLGvs+mmyBq8Jz5Zy4BSCk1fQ
FmCnSGyzpyBD0vMd6eLHk2l0tm56DrlonbDMX8KGs7e9ZgjANkT5PnipLOaeLJU4
H+OWyBZUAT4hl/iRVvLwV81x7g0/O38kmPYJDQIDAQABAoIBAFb7wyhEIfuhhlE9
uryrb2LrGzJlMIq7qBWOouKhLz4SjIM/VGw+c76VkjZGoSU+LeLj+D0W1ie0u2Cw
gJM8aW22TbK/c5lksWOO5PVFDdPG+ZoRWY3MLGlhlL5E4UhMPgJyy/eeiRjZ3CZM
pja+UfVAwn1KVNR8UinVZYPt680AvEd1FGxoNLxemIPNug46nNqp6Al86Bn+BnkN
GXpwyooXVSfo4k+pnFBFIXUdA1dUEXQSVb1AxlTo6g/Ok/+8Gfq8idCdu+5fcZI2
1eLeC+FAa92rr1SFX/UWeB4cMyuAqwuxbFFIplT22SaUSsNuOUSH4E00nbP/AuCb
1BqrLmECgYEA7tQKfyF9aiXTsOMdOnSAa5OyEaCfsFtcmLd4ykVrwN8O36NoX005
VbGuqo87fwIXQIKHU+kOEs/TmaQ8bNcbCD/SfWGTtOnHG4qfIsepJuoMwbQHRhGF
JeoXh5yEUKg5pcDBY8PENEtEVKmFuL4bPOdn+9FNLGsjftvXpmGWbGUCgYEA6uuQ
7kzO6WD88OsxdJzlJM11hg2SaSBCh3+5tnOhF1ULOUt4tdYXzh3QI6BPX7tkArYf
XteVfWoWqn6T7LtCjFm350BqVpPhqfLKnt6fYf1yotsj/cyZXlXquRbxbgakB0n0
4PrsZaube0TPPVeirzNyOVHyFc+iW+F+IUYD+4kCgYEApDEjBkP/9PoMj4+UiJuP
rmXcBkJnhtdI0bVRVb5kVjUEBLxTBTISONfvPVM7lBXb5n3Wi9mt00EOOJKw+CLq
csFt9MUgxz/xov2qaj7aC+bc3k7msUVaRLardpAkZ09AUrQyQGRWf50/XPUu+dO4
5iYxVu6OH/uIa664k6qDwAECgYEAslS8oomgEL3VhbWkx1dLA5MMggTPfgpFNsMY
4Y4JXcLrUEUgjzjEvW0YUdMiLhP8qapDSiXxj1D3f9myxWSp8g0xc9UMZEjCZ9at
RcjNyP8zBLnCKqokSt6B3puyDsnvvrC/ugIBbnTFBOCJSZG7J7CwJx8z3KbQI1ub
+fpCj7ECgYAd69soLEybUGMjsdI+OijIGoUTUoZGXJm+0VpBt4QJCe7AMnYPfYzA
JnEmN4D7HLTKUBklQnb/FhP/RuiT2bSAd1l+PNeuU7gYROCBBonzxXQ1wEbNrSYA
iyoc9g/kvV8HTW8361xEhu7wmuSEEx1gQ/7sdhTkgrTncc8hxVRxuA==
-----END RSA PRIVATE KEY-----
`,
		Passphrase: "password",
		PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ymVc24BoaZb0ElXoI3X
4zUKJGZEetR6F4yT1tJhkPDg7UTmiNoFB5TZJvP6LBrrSwszkpZbxaVOkBrwrGbq
FUaXPgud8VabfHl0imXvN746zmpjYEMGqJzm+Gh6aBWOlnPdLuHhds/kcanFAEpp
j5yN0tVWDnqjOJjR7EpxMSdP3TSd6tNAY73LGNLNJQc6tSxh8nMIb4HhSWQSgfof
+FwcLGvs+mmyBq8Jz5Zy4BSCk1fQFmCnSGyzpyBD0vMd6eLHk2l0tm56DrlonbDM
X8KGs7e9ZgjANkT5PnipLOaeLJU4H+OWyBZUAT4hl/iRVvLwV81x7g0/O38kmPYJ
DQIDAQAB
-----END PUBLIC KEY-----
`,
	}

	res, err := acctest.GetTestResty(t).R().
		SetBody(keyPair).
		Post("artifactory/api/security/keypair")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

func deleteKeyPair(t *testing.T, name string) error {
	res, err := acctest.GetTestResty(t).R().
		SetPathParam("name", name).
		Delete("artifactory/api/security/keypair/{name}")

	if err != nil {
		return err
	}

	if res.IsError() {
		return fmt.Errorf("%s", res.String())
	}

	return nil
}

type artifactUploadResponse struct {
	Path      string                         `json:"path"`
	Checksums artifactUploadChecksumResponse `json:"checksums"`
}

type artifactUploadChecksumResponse struct {
	SHA256 string `json:"sha256"`
}

func uploadTestFile(t *testing.T, repoKey string) (string, string, error) {
	body, err := os.ReadFile("../../../samples/multi1-3.7-20220310.233748-1.jar")
	if err != nil {
		return "", "", err
	}
	uri := fmt.Sprintf("/artifactory/%s/org/jfrog/test/multi1/3.7-SNAPSHOT/multi1-3.7-SNAPSHOT.jar", repoKey)

	var result artifactUploadResponse
	_, err = acctest.GetTestResty(t).R().
		SetHeader("Content-Type", "application/java-archive").
		SetBody(body).
		SetResult(&result).
		Put(uri)
	if err != nil {
		return "", "", err
	}

	return result.Path, result.Checksums.SHA256, nil
}

func TestAccBinaryManagerReleaseBundlesV2_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-release-bundles-v2", "xray_binary_manager_release_bundles_v2")

	keyPairName := fmt.Sprintf("test-keypair-%d", testutil.RandomInt())

	repoName := fmt.Sprintf("test-repo-%d", testutil.RandomInt())

	releaseBundle1Name := fmt.Sprintf("test-release-bundles-v2-%d", testutil.RandomInt())
	releaseBundle2Name := fmt.Sprintf("test-release-bundles-v2-%d", testutil.RandomInt())

	const template = `
		resource "xray_binary_manager_release_bundles_v2" "{{ .name }}" {
			id = "default"
			indexed_release_bundle_v2 = ["{{ .releaseBundle1Name }}"]
		}
	`

	testData := map[string]string{
		"name":               resourceName,
		"releaseBundle1Name": releaseBundle1Name,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_full", template, testData)

	const updateTemplate = `
		resource "xray_binary_manager_release_bundles_v2" "{{ .name }}" {
			id = "default"
			indexed_release_bundle_v2 = ["{{ .releaseBundle1Name }}", "{{ .releaseBundle2Name }}"]
		}

	`
	updatedTestData := map[string]string{
		"name":               resourceName,
		"releaseBundle1Name": releaseBundle1Name,
		"releaseBundle2Name": releaseBundle2Name,
	}
	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, repoName, "local", "", "maven")

			path, sha256, err := uploadTestFile(t, repoName)
			if err != nil {
				t.Fatalf("failed to upload file: %s", err)
			}

			if err := createKeyPair(t, keyPairName); err != nil {
				t.Fatalf("failed to create key pair: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundle1Name, keyPairName, repoName, "", path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundle2Name, keyPairName, repoName, "", path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			var errs []error

			if err := deleteReleaseBundleV2Version(t, releaseBundle1Name, ""); err != nil {
				errs = append(errs, err)
			}

			if err := deleteReleaseBundleV2Version(t, releaseBundle2Name, ""); err != nil {
				errs = append(errs, err)
			}

			if err := deleteKeyPair(t, keyPairName); err != nil {
				errs = append(errs, err)
			}

			acctest.DeleteRepo(t, repoName)

			return errors.Join(errs...)
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.0", releaseBundle1Name),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.#", "2"),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_release_bundle_v2.*", releaseBundle1Name),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_release_bundle_v2.*", releaseBundle2Name),
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

func TestAccBinaryManagerReleaseBundlesV2_project_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-bin-mgr-release-bundles-v2", "xray_binary_manager_release_bundles_v2")

	projectKey := lo.RandomString(6, lo.LowerCaseLettersCharset)

	keyPairName := fmt.Sprintf("test-keypair-%d", testutil.RandomInt())

	repoName := fmt.Sprintf("test-repo-%d", testutil.RandomInt())

	releaseBundle1Name := fmt.Sprintf("test-release-bundles-v2-%d", testutil.RandomInt())
	releaseBundle2Name := fmt.Sprintf("test-release-bundles-v2-%d", testutil.RandomInt())

	const template = `
		resource "xray_binary_manager_release_bundles_v2" "{{ .name }}" {
			id = "default"
			project_key = "{{ .projectKey }}"
			indexed_release_bundle_v2 = ["{{ .releaseBundle1Name }}"]
		}
	`

	testData := map[string]string{
		"name":               resourceName,
		"projectKey":         projectKey,
		"releaseBundle1Name": releaseBundle1Name,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_full", template, testData)

	const updateTemplate = `
		resource "xray_binary_manager_release_bundles_v2" "{{ .name }}" {
			id = "default"
			project_key = "{{ .projectKey }}"
			indexed_release_bundle_v2 = ["{{ .releaseBundle1Name }}", "{{ .releaseBundle2Name }}"]
		}

	`
	updatedTestData := map[string]string{
		"name":               resourceName,
		"projectKey":         projectKey,
		"releaseBundle1Name": releaseBundle1Name,
		"releaseBundle2Name": releaseBundle2Name,
	}
	updatedConfig := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_full", updateTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, repoName, "local", "", "maven")

			path, sha256, err := uploadTestFile(t, repoName)
			if err != nil {
				t.Fatalf("failed to upload file: %s", err)
			}

			acctest.CreateProject(t, projectKey)

			if err := createKeyPair(t, keyPairName); err != nil {
				t.Fatalf("failed to create key pair: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundle1Name, keyPairName, repoName, projectKey, path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundle2Name, keyPairName, repoName, projectKey, path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			var errs []error

			if err := deleteReleaseBundleV2Version(t, releaseBundle1Name, projectKey); err != nil {
				errs = append(errs, err)
			}

			if err := deleteReleaseBundleV2Version(t, releaseBundle2Name, projectKey); err != nil {
				errs = append(errs, err)
			}

			if err := deleteKeyPair(t, keyPairName); err != nil {
				errs = append(errs, err)
			}

			acctest.DeleteProject(t, projectKey)

			acctest.DeleteRepo(t, repoName)

			return errors.Join(errs...)
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.0", releaseBundle1Name),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", "default"),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
					resource.TestCheckResourceAttr(fqrn, "indexed_release_bundle_v2.#", "2"),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_release_bundle_v2.*", releaseBundle1Name),
					resource.TestCheckTypeSetElemAttr(fqrn, "indexed_release_bundle_v2.*", releaseBundle2Name),
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

func TestAccBinaryManagerReleaseBundlesV2_same_name_different_projects(t *testing.T) {
	_, fqrn1, resourceName1 := testutil.MkNames("test-bin-mgr-release-bundles-v2", "xray_binary_manager_release_bundles_v2")
	_, fqrn2, resourceName2 := testutil.MkNames("test-bin-mgr-release-bundles-v2", "xray_binary_manager_release_bundles_v2")

	projectKey1 := lo.RandomString(6, lo.LowerCaseLettersCharset)
	projectKey2 := lo.RandomString(6, lo.LowerCaseLettersCharset)

	keyPairName := fmt.Sprintf("test-keypair-%d", testutil.RandomInt())

	repoName := fmt.Sprintf("test-repo-%d", testutil.RandomInt())

	// Release Bundle V2 names are scoped per project, so the same name in two
	// projects must not be treated as a duplicate set element.
	releaseBundleName := fmt.Sprintf("test-release-bundles-v2-%d", testutil.RandomInt())

	const template = `
		resource "xray_binary_manager_release_bundles_v2" "{{ .name1 }}" {
			id = "default"
			project_key = "{{ .projectKey1 }}"
			indexed_release_bundle_v2 = ["{{ .releaseBundleName }}"]
		}

		resource "xray_binary_manager_release_bundles_v2" "{{ .name2 }}" {
			id = "default"
			project_key = "{{ .projectKey2 }}"
			indexed_release_bundle_v2 = ["{{ .releaseBundleName }}"]
		}
	`

	testData := map[string]string{
		"name1":             resourceName1,
		"name2":             resourceName2,
		"projectKey1":       projectKey1,
		"projectKey2":       projectKey2,
		"releaseBundleName": releaseBundleName,
	}

	config := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_same_name_different_projects", template, testData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.CreateRepos(t, repoName, "local", "", "maven")

			path, sha256, err := uploadTestFile(t, repoName)
			if err != nil {
				t.Fatalf("failed to upload file: %s", err)
			}

			acctest.CreateProject(t, projectKey1)
			acctest.CreateProject(t, projectKey2)

			if err := createKeyPair(t, keyPairName); err != nil {
				t.Fatalf("failed to create key pair: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundleName, keyPairName, repoName, projectKey1, path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}

			if err := createReleaseBundleV2(t, releaseBundleName, keyPairName, repoName, projectKey2, path, sha256); err != nil {
				t.Fatalf("failed to create release bundle: %s", err)
			}
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			var errs []error

			if err := deleteReleaseBundleV2Version(t, releaseBundleName, projectKey1); err != nil {
				errs = append(errs, err)
			}

			if err := deleteReleaseBundleV2Version(t, releaseBundleName, projectKey2); err != nil {
				errs = append(errs, err)
			}

			if err := deleteKeyPair(t, keyPairName); err != nil {
				errs = append(errs, err)
			}

			acctest.DeleteProject(t, projectKey1)
			acctest.DeleteProject(t, projectKey2)

			acctest.DeleteRepo(t, repoName)

			return errors.Join(errs...)
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn1, "project_key", projectKey1),
					resource.TestCheckResourceAttr(fqrn1, "indexed_release_bundle_v2.#", "1"),
					resource.TestCheckResourceAttr(fqrn1, "indexed_release_bundle_v2.0", releaseBundleName),
					resource.TestCheckResourceAttr(fqrn2, "project_key", projectKey2),
					resource.TestCheckResourceAttr(fqrn2, "indexed_release_bundle_v2.#", "1"),
					resource.TestCheckResourceAttr(fqrn2, "indexed_release_bundle_v2.0", releaseBundleName),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

func TestAccBinaryManagerReleaseBundlesV2_invalid_patterns(t *testing.T) {
	invalidPatterns := []string{"*", "**", "?"}

	for _, invalidPattern := range invalidPatterns {
		t.Run(invalidPattern, func(t *testing.T) {
			_, _, resourceName := testutil.MkNames("test-bin-mgr-release-bundles-v2", "xray_binary_manager_release_bundles_v2")

			const template = `
				resource "xray_binary_manager_release_bundles_v2" "{{ .name }}" {
					id = "default"
					indexed_release_bundle_v2 = ["{{ .pattern }}"]
				}
			`

			testData := map[string]string{
				"name":    resourceName,
				"pattern": invalidPattern,
			}

			config := util.ExecuteTemplate("TestAccBinaryManagerReleaseBundlesV2_invalid_patterns", template, testData)

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      config,
						ExpectError: regexp.MustCompile(`.*cannot contain Ant-style\n.*patterns.*`),
					},
				},
			})
		})
	}
}

func TestReleaseBundleV2NamesFromAPI(t *testing.T) {
	testCases := []struct {
		name       string
		apiNames   []string
		projectKey string
		expected   []string
	}{
		{
			name:       "scopes names to the project",
			apiNames:   []string{"[suriya-release-bundles-v2]/demo1", "[suriyams-release-bundles-v2]/demo1"},
			projectKey: "suriya",
			expected:   []string{"demo1"},
		},
		{
			name:       "scopes names to the other project",
			apiNames:   []string{"[suriya-release-bundles-v2]/demo1", "[suriyams-release-bundles-v2]/demo2"},
			projectKey: "suriyams",
			expected:   []string{"demo2"},
		},
		{
			name:       "excludes names from foreign project repositories",
			apiNames:   []string{"[suriya-release-bundles-v2]/demo1", "[suriyams-release-bundles-v2]/demo1"},
			projectKey: "",
			expected:   []string{},
		},
		{
			name:       "keeps default scope names",
			apiNames:   []string{"[release-bundles-v2]/demo1", "[suriya-release-bundles-v2]/demo2"},
			projectKey: "",
			expected:   []string{"demo1"},
		},
		{
			name:       "keeps names without a repository prefix",
			apiNames:   []string{"demo1", "demo2"},
			projectKey: "suriya",
			expected:   []string{"demo1", "demo2"},
		},
		{
			name:       "handles empty response",
			apiNames:   []string{},
			projectKey: "suriya",
			expected:   []string{},
		},
		{
			name:       "preserves empty result for only foreign project entries",
			apiNames:   []string{"[other-release-bundles-v2]/demo1", "[suriyams-release-bundles-v2]/demo2"},
			projectKey: "suriya",
			expected:   []string{},
		},
		{
			name:       "falls back to all names for default-scoped API response",
			apiNames:   []string{"[release-bundles-v2]/demo1", "demo2"},
			projectKey: "suriya",
			expected:   []string{"demo1", "demo2"},
		},
		{
			name:       "does not fall back for mixed default and foreign entries",
			apiNames:   []string{"[release-bundles-v2]/demo1", "[other-release-bundles-v2]/demo2"},
			projectKey: "suriya",
			expected:   []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := xrayresource.ReleaseBundleV2NamesFromAPI(testCase.apiNames, testCase.projectKey)

			if len(actual) != len(testCase.expected) {
				t.Fatalf("expected %v, got %v", testCase.expected, actual)
			}

			for _, expectedName := range testCase.expected {
				if !lo.Contains(actual, expectedName) {
					t.Errorf("expected %v to contain %q", actual, expectedName)
				}
			}

			if len(lo.Uniq(actual)) != len(actual) {
				t.Errorf("expected unique names, got %v", actual)
			}
		})
	}
}

func TestSplitReleaseBundleV2Name(t *testing.T) {
	testCases := []struct {
		apiName         string
		expectedRepoKey string
		expectedName    string
	}{
		{apiName: "[suriya-release-bundles-v2]/demo1", expectedRepoKey: "suriya-release-bundles-v2", expectedName: "demo1"},
		{apiName: "[release-bundles-v2]/demo1", expectedRepoKey: "release-bundles-v2", expectedName: "demo1"},
		{apiName: "demo1", expectedRepoKey: "", expectedName: "demo1"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.apiName, func(t *testing.T) {
			repoKey, name := xrayresource.SplitReleaseBundleV2Name(testCase.apiName)

			if repoKey != testCase.expectedRepoKey {
				t.Errorf("expected repository key %q, got %q", testCase.expectedRepoKey, repoKey)
			}

			if name != testCase.expectedName {
				t.Errorf("expected name %q, got %q", testCase.expectedName, name)
			}
		})
	}
}
