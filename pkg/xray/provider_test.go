package xray

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
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

func testAccPreCheck(t *testing.T) {
	ctx := context.Background()
	provider, _ := testAccProviders()["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Error(oldErr)
	}
}

// Create a repository with Xray indexing enabled. It will be used in the tests
func testAccCreateRepos(t *testing.T, repo, repoType string, projectKey string) {
	restyClient := GetTestResty(t)

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

	req := restyClient.R()

	res, err := req.SetBody(repository).Put("artifactory/api/repositories/" + repo)
	//Artifactory can return 400 for several reasons, this is why we are checking the response body
	repoExists := strings.Contains(fmt.Sprint(err), "Case insensitive repository key already exists")
	if !repoExists && res.StatusCode() != http.StatusOK {
		t.Error(err)
	}

	if len(projectKey) > 0 {
		path := fmt.Sprintf("access/api/v1/projects/_/attach/repositories/%s/%s", repo, projectKey)
		res, err = req.Put(path)
		if err != nil {
			t.Error(err)
		}
	}
}

func testAccDeleteRepo(t *testing.T, repo string) {
	restyClient := GetTestResty(t)

	response, errRepo := restyClient.R().Delete("artifactory/api/repositories/" + repo)
	if errRepo != nil || response.StatusCode() != http.StatusOK {
		t.Logf("The repository %s wasn't removed", repo)
	}
}

// Create a project. It will be used in the tests
func testAccCreateProject(t *testing.T, projectKey string, projectName string) {
	restyClient := GetTestResty(t)

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
	restyClient := GetTestResty(t)
	return restyClient.R().Delete("/access/api/v1/projects/" + projectKey)
}

// Create a set of builds or a single build, add the build into the Xray indexing configuration, to be able to add it to
// the xray watch
func testAccCreateBuilds(t *testing.T, builds []string, projectKey string) {
	restyClient := GetTestResty(t)

	type BuildBody struct {
		Version string `json:"version"`
		Name    string `json:"name"`
		Number  string `json:"number"`
		Started string `json:"started"`
	}

	for _, build := range builds {
		buildBody := BuildBody{
			Version: "1.0.1",
			Name:    build,
			Number:  "28",
			Started: "2021-10-30T12:00:19.893+0300",
		}
		req := restyClient.R().SetBody(buildBody)
		if len(projectKey) > 0 {
			req = req.SetQueryParam("project", projectKey)
		}
		respCreateBuild, errCreateBuild := req.Put("artifactory/api/build")
		if respCreateBuild.StatusCode() != http.StatusNoContent {
			t.Error(errCreateBuild)
		}
	}

	type XrayIndexBody struct {
		IndexedBuilds []string `json:"indexed_builds"`
	}

	xrayIndexBody := XrayIndexBody{
		IndexedBuilds: builds,
	}

	req := restyClient.R().SetBody(xrayIndexBody)
	if len(projectKey) > 0 {
		req = req.SetQueryParam("projectKey", projectKey)
	}
	respAddIndexBody, errAddIndexBody := req.Put("xray/api/v1/binMgr/default/builds")
	if respAddIndexBody.StatusCode() != http.StatusOK {
		t.Error(errAddIndexBody)
	}
}
