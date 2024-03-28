package xray_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

func TestAccWorkersCount_create(t *testing.T) {
	_, _, resourceName := testutil.MkNames("workers-count-", "xray_workers_count")

	params := map[string]interface{}{
		"workersCountName": resourceName,
	}
	workersCountConfig := util.ExecuteTemplate("TestAccWorkersCount_create", `
		resource "xray_workers_count" "{{ .workersCountName }}" {
		  index {
		    new_content      = 4
		    existing_content = 2
		  }
		  persist {
		    new_content      = 4
		    existing_content = 2
		  }
		  analysis {
		    new_content      = 4
		    existing_content = 2
		  }
		  alert {
		    new_content      = 4
		    existing_content = 2
		  }
		  impact_analysis {
		    new_content = 2
		  }
		  notification {
		    new_content = 2
		  }
		}
	`, params)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      workersCountConfig,
				ExpectError: regexp.MustCompile(`Workers Count resource does not support create`),
			},
		},
	})
}
