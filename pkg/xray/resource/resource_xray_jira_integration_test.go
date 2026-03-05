package xray_test

import (
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

func TestAccJiraIntegration_basic(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-jira-", "xray_jira_integration")

	const tmpl = `
	resource "xray_jira_integration" "{{ .name }}" {
		connection_name   = "{{ .name }}"
		jira_server_url   = "{{ .jiraServerURL }}"
		installation_type = "{{ .installationType }}"
		username          = "{{ .username }}"
		password          = "{{ .password }}"
	}`

	testData := map[string]string{
		"name":             resourceName,
		"jiraServerURL":    "https://myorg.atlassian.net",
		"installationType": "cloud",
		"username":         "test-user@myorg.com",
		"password":         "test-api-token",
	}

	config := util.ExecuteTemplate(fqrn, tmpl, testData)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "connection_name", testCheckJiraIntegration),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "connection_name", testData["name"]),
					resource.TestCheckResourceAttr(fqrn, "jira_server_url", testData["jiraServerURL"]),
					resource.TestCheckResourceAttr(fqrn, "installation_type", testData["installationType"]),
					resource.TestCheckResourceAttr(fqrn, "auth_type", "basic"),
					resource.TestCheckResourceAttr(fqrn, "username", testData["username"]),
					resource.TestCheckResourceAttr(fqrn, "password", testData["password"]),
					resource.TestCheckResourceAttr(fqrn, "skip_proxy", "false"),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "connection_name",
				ImportStateVerifyIgnore:              []string{"password"},
			},
		},
	})
}

func TestAccJiraIntegration_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("test-jira-", "xray_jira_integration")

	const tmpl = `
	resource "xray_jira_integration" "{{ .name }}" {
		connection_name   = "{{ .name }}"
		jira_server_url   = "{{ .jiraServerURL }}"
		installation_type = "{{ .installationType }}"
		auth_type         = "{{ .authType }}"
		username          = "{{ .username }}"
		password          = "{{ .password }}"
		skip_proxy        = {{ .skipProxy }}
	}`

	testData := map[string]string{
		"name":             resourceName,
		"jiraServerURL":    "https://jira.internal.myorg.com",
		"installationType": "server",
		"authType":         "basic",
		"username":         "xray-service",
		"password":         "test-password",
		"skipProxy":        "true",
	}

	config := util.ExecuteTemplate(fqrn, tmpl, testData)

	updatedTestData := map[string]string{
		"name":             resourceName,
		"jiraServerURL":    "https://jira-v2.internal.myorg.com",
		"installationType": "server",
		"authType":         "basic",
		"username":         "xray-service-v2",
		"password":         "test-password-v2",
		"skipProxy":        "false",
	}

	updatedConfig := util.ExecuteTemplate(fqrn, tmpl, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "connection_name", testCheckJiraIntegration),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "connection_name", testData["name"]),
					resource.TestCheckResourceAttr(fqrn, "jira_server_url", testData["jiraServerURL"]),
					resource.TestCheckResourceAttr(fqrn, "installation_type", testData["installationType"]),
					resource.TestCheckResourceAttr(fqrn, "auth_type", testData["authType"]),
					resource.TestCheckResourceAttr(fqrn, "username", testData["username"]),
					resource.TestCheckResourceAttr(fqrn, "password", testData["password"]),
					resource.TestCheckResourceAttr(fqrn, "skip_proxy", testData["skipProxy"]),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "connection_name", updatedTestData["name"]),
					resource.TestCheckResourceAttr(fqrn, "jira_server_url", updatedTestData["jiraServerURL"]),
					resource.TestCheckResourceAttr(fqrn, "installation_type", updatedTestData["installationType"]),
					resource.TestCheckResourceAttr(fqrn, "auth_type", updatedTestData["authType"]),
					resource.TestCheckResourceAttr(fqrn, "username", updatedTestData["username"]),
					resource.TestCheckResourceAttr(fqrn, "password", updatedTestData["password"]),
					resource.TestCheckResourceAttr(fqrn, "skip_proxy", updatedTestData["skipProxy"]),
				),
			},
			{
				ResourceName:                         fqrn,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "connection_name",
				ImportStateVerifyIgnore:              []string{"password"},
			},
		},
	})
}

func testCheckJiraIntegration(id string, request *resty.Request) (*resty.Response, error) {
	return request.
		SetPathParam("connection_name", id).
		Get("xray/api/v1/ticketing/jira-integrations/{connection_name}/details")
}
