package xray

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jfrog/terraform-provider-shared/client"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
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
		c := provider.Meta().(*resty.Client)
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
