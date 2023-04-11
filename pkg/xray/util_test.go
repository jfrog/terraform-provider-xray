package xray

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/test"
	"github.com/jfrog/terraform-provider-shared/util"
)

func checkPolicy(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v2/policies/" + id)
}

func testCheckPolicy(id string, request *resty.Request) (*resty.Response, error) {
	return checkPolicy(id, request.AddRetryCondition(client.NeverRetry))
}

func testCheckPolicyDeleted(id string, t *testing.T, request *resty.Request) *resty.Response {
	_, err := checkPolicy(id, request.AddRetryCondition(client.NeverRetry))
	if err == nil {
		t.Logf("Policy %s still exists!", id)
	}
	return nil
}

type CheckFun func(id string, request *resty.Request) (*resty.Response, error)

func verifyDeleted(id string, check CheckFun) func(*terraform.State) error {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[id]
		if !ok {
			return fmt.Errorf("error: Resource id [%s] not found", id)
		}
		provider, _ := testAccProviders()["xray"]()
		provider.Configure(context.Background(), terraform.NewResourceConfigRaw(nil))
		c := provider.Meta().(util.ProvderMetadata).Client
		resp, err := check(rs.Primary.ID, c.R())
		if err != nil {
			if resp != nil {
				switch resp.StatusCode() {
				case http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError:
					return nil
				}
			}
			return err
		}
		return fmt.Errorf("error: %s still exists", rs.Primary.ID)
	}
}

func GetTestResty(t *testing.T) *resty.Client {
	artifactoryUrl := test.GetEnvVarWithFallback(t, "XRAY_URL", "JFROG_URL")
	restyClient, err := client.Build(artifactoryUrl, "")
	if err != nil {
		t.Fatal(err)
	}

	accessToken := test.GetEnvVarWithFallback(t, "XRAY_ACCESS_TOKEN", "JFROG_ACCESS_TOKEN")
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

func generateListOfNames(prefix string, number int) string {
	var CVEs []string
	n := 1
	for n < number {
		CVEs = append(CVEs, fmt.Sprintf("\"%s%d\",", prefix, test.RandomInt()))
		n++
	}
	return fmt.Sprintf("%s", CVEs)
}
