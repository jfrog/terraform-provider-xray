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

func testAccPreCheck(t *testing.T) {
	restyClient := getTestResty(t)
	resp, errLicense := restyClient.R().Get("/artifactory/api/system/licenses/")
	s := fmt.Sprintf("%s", resp.Body())
	if errLicense != nil {
		t.Fatal(errLicense)
	}
	if !strings.Contains(fmt.Sprint(s), "Enterprise") {
		t.Fatal(s, "\nArtifactory requires Enterprise license to work with Terraform!")
	}
	ctx := context.Background()
	provider, _ := testAccProviders["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Fatal(oldErr)
	}
}

func testAccPreCheckWatch(t *testing.T) {
	restyClient := getTestResty(t)
	resp, errLicense := restyClient.R().Get("/artifactory/api/system/licenses/")
	s := fmt.Sprintf("%s", resp.Body())
	if errLicense != nil {
		t.Fatal(errLicense)
	}
	if !strings.Contains(fmt.Sprint(s), "Enterprise") {
		t.Fatal(s, "\nArtifactory requires Enterprise license to work with Terraform!")
	}

	// Create a local repository with Xray indexing enabled. It will be used in the tests
	body := "{\n\"rclass\":\"local\",\n\"xrayIndex\":true\n}"
	for _, repo := range []string{"libs-release-local", "libs-release-local-1"} {
		_, errRepo := restyClient.R().SetBody(body).Put("artifactory/api/repositories/" + repo)
		repoExists := strings.Contains(fmt.Sprint(errRepo), "Case insensitive repository key already exists")
		repoCreated := strings.Contains(fmt.Sprint(errRepo), "Successfully created repository")
		if !repoExists && !repoCreated {
			t.Fatal(errRepo)
		}
	}
	ctx := context.Background()
	provider, _ := testAccProviders["xray"]()
	oldErr := provider.Configure(ctx, terraform.NewResourceConfigRaw(nil))
	if oldErr != nil {
		t.Fatal(oldErr)
	}
}
