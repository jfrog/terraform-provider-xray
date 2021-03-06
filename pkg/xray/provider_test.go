package xray

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/jfrog/terraform-provider-shared/client"
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
	var ok bool
	var xrayUrl string
	if xrayUrl, ok = os.LookupEnv("XRAY_URL"); !ok {
		if xrayUrl, ok = os.LookupEnv("JFROG_URL"); !ok {
			t.Fatal("XRAY_URL or JFROG_URL must be set for acceptance tests")
		}
	}
	restyClient, err := client.Build(xrayUrl, "")
	if err != nil {
		t.Error(err)
	}

	var accessToken string
	if accessToken, ok = os.LookupEnv("XRAY_ACCESS_TOKEN"); !ok {
		if accessToken, ok = os.LookupEnv("JFROG_ACCESS_TOKEN"); !ok {
			t.Fatal("XRAY_ACCESS_TOKEN or JFROG_ACCESS_TOKEN must be set for acceptance tests")
		}
	}
	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		t.Error(err)
	}
	return restyClient
}

func testAccPreCheck(t *testing.T) {
	ctx := context.Background()
	provider, _ := testAccProviders()["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Error(oldErr)
	}
}

// Create a repository with Xray indexing enabled. It will be used in the tests
func testAccCreateRepos(t *testing.T, repo, repoType string) {
	restyClient := getTestResty(t)

	type Repository struct {
		Rclass    string `json:"rclass"`
		XrayIndex bool   `json:"xrayIndex"`
		Url       string `json:"url,omitempty"`
	}

	repository := Repository{
		Rclass:    repoType,
		XrayIndex: true,
	}

	if repoType == "remote" {
		repository.Url = "http://tempurl.org"
	}

	response, errRepo := restyClient.R().SetBody(repository).Put("artifactory/api/repositories/" + repo)
	//Artifactory can return 400 for several reasons, this is why we are checking the response body
	repoExists := strings.Contains(fmt.Sprint(errRepo), "Case insensitive repository key already exists")
	if !repoExists && response.StatusCode() != http.StatusOK {
		t.Error(errRepo)
	}
}

func testAccDeleteRepo(t *testing.T, repo string) {
	restyClient := getTestResty(t)

	response, errRepo := restyClient.R().Delete("artifactory/api/repositories/" + repo)
	if errRepo != nil || response.StatusCode() != http.StatusOK {
		t.Logf("The repository %s wasn't removed", repo)
	}
}

// Create a project. It will be used in the tests
func testAccCreateProject(t *testing.T, projectKey string, projectName string) {
	restyClient := getTestResty(t)

	type Project struct {
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
		ProjectKey  string `json:"project_key"`
	}

	project := Project{}
	project.DisplayName = projectName
	project.Description = "Project created by TF provider test"
	project.ProjectKey = projectKey
	response, errProject := restyClient.R().SetBody(project).Post("/access/api/v1/projects")

	if errProject != nil || response.IsError() {
		t.Error(fmt.Errorf("failed to created project %s - %s", response, errProject))
	}
}

// Delete test projects after testing
func testAccDeleteProject(t *testing.T, projectKey string) (*resty.Response, error) {
	restyClient := getTestResty(t)
	return restyClient.R().Delete("/access/api/v1/projects/" + projectKey)
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
			t.Error(errCreateBuild)
		}
	}

	xrayIndexBody := XrayIndexBody{
		Names: builds,
	}

	respAddIndexBody, errAddIndexBody := restyClient.R().SetBody(xrayIndexBody).Post("xray/api/v1/binMgr/builds")
	if respAddIndexBody.StatusCode() != http.StatusOK {
		t.Error(errAddIndexBody)
	}

}
