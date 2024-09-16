package acctest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-xray/pkg/xray"
)

// Provider PreCheck(t) must be called before using this provider instance.
var Provider provider.Provider

var ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"xray": providerserver.NewProtocol6WithError(xray.NewProvider()()),
}

func init() {
	Provider = xray.NewProvider()()

	ProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"xray": providerserver.NewProtocol6WithError(Provider),
	}
}

type CheckFun func(id string, request *resty.Request) (*resty.Response, error)

func VerifyDeleted(id, identifierAttribute string, check CheckFun) func(*terraform.State) error {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[id]
		if !ok {
			return fmt.Errorf("error: Resource id [%s] not found", id)
		}

		if Provider == nil {
			return fmt.Errorf("provider is not initialized. Please PreCheck() is included in your acceptance test")
		}

		identifier := rs.Primary.ID
		if identifierAttribute != "" {
			identifier = rs.Primary.Attributes[identifierAttribute]
		}

		client := Provider.(*xray.XrayProvider).Meta.Client
		resp, err := check(identifier, client.R())
		if err != nil {
			return err
		}

		switch resp.StatusCode() {
		case http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError:
			return nil
		}

		return fmt.Errorf("error: %s still exists", identifier)
	}
}

func GetTestResty(t *testing.T) *resty.Client {
	artifactoryUrl := testutil.GetEnvVarWithFallback(t, "XRAY_URL", "JFROG_URL")
	restyClient, err := client.Build(artifactoryUrl, "")
	if err != nil {
		t.Fatal(err)
	}

	accessToken := testutil.GetEnvVarWithFallback(t, "XRAY_ACCESS_TOKEN", "JFROG_ACCESS_TOKEN")
	restyClient, err = client.AddAuth(restyClient, "", accessToken)
	if err != nil {
		t.Fatal(err)
	}
	return restyClient
}

func CreateProject(t *testing.T, projectKey string) {
	type AdminPrivileges struct {
		ManageMembers   bool `json:"manage_members"`
		ManageResources bool `json:"manage_resources"`
		IndexResources  bool `json:"index_resources"`
	}

	type Project struct {
		Key             string          `json:"project_key"`
		DisplayName     string          `json:"display_name"`
		Description     string          `json:"description"`
		AdminPrivileges AdminPrivileges `json:"admin_privileges"`
	}

	restyClient := GetTestResty(t)

	project := Project{
		Key:         projectKey,
		DisplayName: projectKey,
		Description: fmt.Sprintf("%s description", projectKey),
		AdminPrivileges: AdminPrivileges{
			ManageMembers:   true,
			ManageResources: true,
			IndexResources:  true,
		},
	}

	_, err := restyClient.R().
		SetBody(project).
		Post("/access/api/v1/projects")
	if err != nil {
		t.Fatal(err)
	}
}

func DeleteProject(t *testing.T, projectKey string) {
	restyClient := GetTestResty(t)
	_, err := restyClient.R().Delete("/access/api/v1/projects/" + projectKey)
	if err != nil {
		t.Fatal(err)
	}
}

// Create a repository with Xray indexing enabled. It will be used in the tests
func CreateRepos(t *testing.T, repo, repoType, projectKey, packageType string) {
	restyClient := GetTestResty(t)

	type Repository struct {
		Rclass      string `json:"rclass"`
		PackageType string `json:"packageType"`
		XrayIndex   bool   `json:"xrayIndex"`
		Url         string `json:"url,omitempty"`
	}

	repository := Repository{
		Rclass:      repoType,
		PackageType: "generic",
		XrayIndex:   true,
	}

	if packageType != "" {
		repository.PackageType = packageType
	}

	if repoType == "remote" {
		repository.Url = "https://google.com"
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
		_, err = req.Put(path)
		if err != nil {
			t.Error(err)
		}
	}
}

func DeleteRepo(t *testing.T, repo string) {
	restyClient := GetTestResty(t)

	resp, err := restyClient.R().Delete("artifactory/api/repositories/" + repo)
	if err != nil || resp.StatusCode() != http.StatusOK {
		t.Logf("The repository %s wasn't removed", repo)
	}
}

func DummyError() *resty.Response {
	rawResponse := http.Response{
		StatusCode: http.StatusNotFound,
	}
	resp := resty.Response{
		RawResponse: &rawResponse,
	}

	return &resp
}

// Create a set of builds or a single build, add the build into the Xray indexing configuration, to be able to add it to
// the xray watch
func CreateBuilds(t *testing.T, builds []string, projectKey string) {
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

func checkPolicy(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v2/policies/" + id)
}

func CheckPolicy(id string, request *resty.Request) (*resty.Response, error) {
	return checkPolicy(id, request.AddRetryCondition(client.NeverRetry))
}

func CheckPolicyDeleted(id string, t *testing.T, request *resty.Request) *resty.Response {
	resp, err := checkPolicy(id, request.AddRetryCondition(client.NeverRetry))
	if err == nil || resp.IsSuccess() {
		t.Logf("Policy %s still exists!", id)
	}
	return nil
}
