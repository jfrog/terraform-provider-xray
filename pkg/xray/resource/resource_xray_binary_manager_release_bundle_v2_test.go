package xray_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
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
			if err := deleteReleaseBundleV2Version(t, releaseBundle1Name, ""); err != nil {
				return nil
			}

			if err := deleteReleaseBundleV2Version(t, releaseBundle2Name, ""); err != nil {
				return nil
			}

			if err := deleteKeyPair(t, keyPairName); err != nil {
				return nil
			}

			acctest.DeleteRepo(t, repoName)

			return nil
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
			if err := deleteReleaseBundleV2Version(t, releaseBundle1Name, projectKey); err != nil {
				return nil
			}

			if err := deleteReleaseBundleV2Version(t, releaseBundle2Name, projectKey); err != nil {
				return nil
			}

			if err := deleteKeyPair(t, keyPairName); err != nil {
				return nil
			}

			acctest.DeleteProject(t, projectKey)

			acctest.DeleteRepo(t, repoName)

			return nil
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
