package xray

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func testAccProviders() map[string]func() (*schema.Provider, error) {
	return map[string]func() (*schema.Provider, error){
		"xray": func() (*schema.Provider, error) {
			return Provider(), nil
		},
	}
}

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
	accessToken := os.Getenv("XRAY_ACCESS_TOKEN")
	restyClient, err = addAuthToResty(restyClient, accessToken)
	if err != nil {
		t.Fatal(err)
	}
	return restyClient
}

func testAccPreCheck(t *testing.T) {
	ctx := context.Background()
	provider, _ := testAccProviders()["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Fatal(oldErr)
	}
}

// Create a local repository with Xray indexing enabled. It will be used in the tests
func testAccCreateRepos(t *testing.T, repos []string) {
	restyClient := getTestResty(t)

	type Repository struct {
		Rclass    string `json:"rclass"`
		XrayIndex bool   `json:"xrayIndex"`
	}

	repository := Repository{}
	repository.Rclass = "local"
	repository.XrayIndex = true
	for _, repo := range repos {
		response, errRepo := restyClient.R().SetBody(repository).Put("artifactory/api/repositories/" + repo)
		repoExists := strings.Contains(fmt.Sprint(errRepo), "Case insensitive repository key already exists")
		if !repoExists && response.StatusCode() != http.StatusOK {
			t.Fatal(errRepo)
		}
	}
}

func testAccDeleteRepos(t *testing.T, repos []string) (*resty.Response, error) {
	restyClient := getTestResty(t)
	for _, repo := range repos {
		response, errRepo := restyClient.R().Delete("artifactory/api/repositories/" + repo)
		if response.StatusCode() != http.StatusOK {
			t.Fatal(errRepo)
		}
	}
	return nil, nil
}

// Create a set of builds or a single build, add the build into the Xray indexing configuration, to be able to add it to
// the xray watch
func testAccCreateBuilds(t *testing.T, builds []string) {
	restyClient := getTestResty(t)

	type BuildBody struct {
		Version string `json:"version"`
		Name    string `json:"name"`
		Number  string `json:"number"`
		Started string `json:"started"`
	}

	type XrayIndexBody struct {
		Names []string `json:"names"`
	}

	for _, build := range builds {
		buildBody := BuildBody{
			Version: "1.0.1",
			Name:    build,
			Number:  "28",
			Started: "2021-10-30T12:00:19.893+0300",
		}
		respCreateBuild, errCreateBuild := restyClient.R().SetBody(buildBody).Put("artifactory/api/build")
		if respCreateBuild.StatusCode() != http.StatusNoContent {
			t.Fatal(errCreateBuild)
		}
	}

	xrayIndexBody := XrayIndexBody{
		Names: builds,
	}

	respAddIndexBody, errAddIndexBody := restyClient.R().SetBody(xrayIndexBody).Post("xray/api/v1/binMgr/builds")
	if respAddIndexBody.StatusCode() != http.StatusOK {
		t.Fatal(errAddIndexBody)
	}

}
