package xray_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

// policyAndWatchTemplate creates a security policy and a watch with no inline
// assigned_policy block - the policy is attached via xray_watch_policy_attachment.
const policyAndWatchTemplate = `
resource "xray_security_policy" "security" {
  name        = "{{ .policy_name }}"
  description = "Security policy description"
  type        = "security"
  rule {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}

resource "xray_watch" "watch" {
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = true

  watch_resource {
    type = "all-repos"
  }
}
`

const watchPolicyAttachmentTemplate = policyAndWatchTemplate + `
resource "xray_watch_policy_attachment" "{{ .resource_name }}" {
  watch_name  = xray_watch.watch.name
  policy_name = xray_security_policy.security.name
  policy_type = "security"
}
`

func TestAccWatchPolicyAttachment_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("attachment-", "xray_watch_policy_attachment")

	testData := map[string]string{
		"resource_name": resourceName,
		"watch_name":    fmt.Sprintf("xray-watch-%d", testutil.RandomInt()),
		"policy_name":   fmt.Sprintf("xray-policy-%d", testutil.RandomInt()),
		"description":   "Watch managed via attachment resource",
	}

	config := util.ExecuteTemplate(fqrn, watchPolicyAttachmentTemplate, testData)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "watch_name", testData["watch_name"]),
					resource.TestCheckResourceAttr(fqrn, "policy_name", testData["policy_name"]),
					resource.TestCheckResourceAttr(fqrn, "policy_type", "security"),
				),
			},
			{
				ResourceName: fqrn,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return fmt.Sprintf("%s:%s:security", testData["watch_name"], testData["policy_name"]), nil
				},
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWatchPolicyAttachment_detachAndDeletePolicy verifies the core fix for
// https://github.com/jfrog/terraform-provider-xray/issues/358: removing the
// attachment and the policy in a single apply must detach the policy from the
// watch first, then delete the policy, while leaving the watch intact.
func TestAccWatchPolicyAttachment_detachAndDeletePolicy(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("attachment-", "xray_watch_policy_attachment")

	testData := map[string]string{
		"resource_name": resourceName,
		"watch_name":    fmt.Sprintf("xray-watch-%d", testutil.RandomInt()),
		"policy_name":   fmt.Sprintf("xray-policy-%d", testutil.RandomInt()),
		"description":   "Watch managed via attachment resource",
	}

	withAttachment := util.ExecuteTemplate(fqrn, watchPolicyAttachmentTemplate, testData)
	// Watch only - the policy and attachment have been removed from config.
	watchOnly := util.ExecuteTemplate(fqrn, `
resource "xray_watch" "watch" {
  name        = "{{ .watch_name }}"
  description = "{{ .description }}"
  active      = true

  watch_resource {
    type = "all-repos"
  }
}
`, testData)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: withAttachment,
				Check:  resource.TestCheckResourceAttr(fqrn, "policy_name", testData["policy_name"]),
			},
			{
				// Drops both the policy and the attachment; the watch must survive.
				Config: watchOnly,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("xray_watch.watch", "name", testData["watch_name"]),
					resource.TestCheckResourceAttr("xray_watch.watch", "assigned_policy.#", "0"),
				),
			},
		},
	})
}
