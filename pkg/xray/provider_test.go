package xray

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var testAccProviders = func() map[string]func() (*schema.Provider, error) {
	provider := Provider()
	return map[string]func() (*schema.Provider, error){
		"xray": func() (*schema.Provider, error) {
			return provider, nil
		},
	}
}()

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func getTestResty(t *testing.T) *resty.Client {
	if v := os.Getenv("ARTIFACTORY_URL"); v == "" {
		t.Fatal("ARTIFACTORY_URL must be set for acceptance tests")
	}
	restyClient, err := buildResty(os.Getenv("ARTIFACTORY_URL"))
	if err != nil {
		t.Fatal(err)
	}
	accessToken := os.Getenv("ARTIFACTORY_ACCESS_TOKEN")
	restyClient, err = addAuthToResty(restyClient, accessToken)
	if err != nil {
		t.Fatal(err)
	}
	return restyClient
}

func testAccPreCheck(t *testing.T) error {
	restyClient := getTestResty(t)
	err := checkArtifactoryLicense(restyClient)
	if err != nil {
		return err
	}
	ctx := context.Background()
	provider, _ := testAccProviders["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Fatal(oldErr)
	}
	return nil
}

// Create a local repository with Xray indexing enabled. It will be used in the tests
func testAccCreateRepos(t *testing.T, repos []string) {
	restyClient := getTestResty(t)
	body := "{\n\"rclass\":\"local\",\n\"xrayIndex\":true\n}"
	for _, repo := range repos {
		_, errRepo := restyClient.R().SetBody(body).Put("artifactory/api/repositories/" + repo)
		repoExists := strings.Contains(fmt.Sprint(errRepo), "Case insensitive repository key already exists")
		repoCreated := strings.Contains(fmt.Sprint(errRepo), "Successfully created repository")
		if !repoExists && !repoCreated {
			t.Fatal(errRepo)
		}
	}
}

// Create a set of builds or a single build, add the build into the Xray indexing configuration, to be able to add it to
// the xray watch
func testAccCreateBuilds(t *testing.T, builds []string) {
	restyClient := getTestResty(t)
	for _, build := range builds {
		createBuildBody := fmt.Sprintf("{\n\"version\": \"1.0.1\",\n\"name\":\"%s\",\n\"number\":\"28\",\n \"started\":\"2021-10-30T12:00:19.893+0300\"\n}",
			build)
		addIndexBody := fmt.Sprintf("{\n\"names\": [\"%s\"]\n}", build)
		respCreateBuild, errCreateBuild := restyClient.R().SetBody(createBuildBody).Put("artifactory/api/build")
		if respCreateBuild.StatusCode() != 204 {
			t.Fatal(errCreateBuild)
		}
		respAddIndexBody, errAddIndexBody := restyClient.R().SetBody(addIndexBody).Post("xray/api/v1/binMgr/builds")
		if respAddIndexBody.StatusCode() != 200 {
			t.Fatal(errAddIndexBody)
		}
	}
}
