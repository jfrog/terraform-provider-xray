package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

var testDataLicense = map[string]string{
	"resource_name":                     "",
	"policy_name":                       "terraform-license-policy",
	"policy_description":                "policy created by xray acceptance tests",
	"rule_name":                         "test-license-rule",
	"license_0":                         "Apache-1.0",
	"license_1":                         "Apache-2.0",
	"mails_0":                           "test0@email.com",
	"mails_1":                           "test1@email.com",
	"allow_unknown":                     "true",
	"multi_license_permissive":          "false",
	"block_release_bundle_distribution": "true",
	"block_release_bundle_promotion":    "true",
	"fail_build":                        "true",
	"notify_watch_recipients":           "true",
	"notify_deployer":                   "true",
	"create_ticket_enabled":             "false",
	"custom_severity":                   "High",
	"grace_period_days":                 "5",
	"block_unscanned":                   "true",
	"block_active":                      "true",
	"allowedOrBanned":                   "banned_licenses",
}

// License policy criteria are different from the security policy criteria
// Test will try to post a new license policy with incorrect body of security policy
// with specified cvss_range. The function unpackLicenseCriteria will ignore all the
// fields except of "allow_unknown", "banned_licenses" and "allowed_licenses" if the Policy type is "license"
func TestAccLicensePolicy_badLicenseCriteria(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	policyName := fmt.Sprintf("terraform-license-policy-1-%d", testutil.RandomInt())
	policyDesc := "policy created by xray acceptance tests"
	ruleName := fmt.Sprintf("test-license-rule-1-%d", testutil.RandomInt())
	rangeTo := 5

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccXrayLicensePolicy_badLicense(resourceName, policyName, policyDesc, ruleName, rangeTo),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

// This test will try to create a license policy with failure grace period set, but without fail build turned on
func TestAccLicensePolicy_badGracePeriod(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-2-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-2-%d", testutil.RandomInt())
	testData["fail_build"] = "false"
	testData["grace_period_days"] = "5"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

func TestAccLicensePolicy_withProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	projectKey := fmt.Sprintf("testproj%d", testutil.RandSelect(1, 2, 3, 4, 5))

	testData := sdk.MergeMaps(testDataLicense)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-3-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-3-%d", testutil.RandomInt())
	testData["multi_license_permissive"] = "true"
	testData["allowedOrBanned"] = "allowed_licenses"

	template := `resource "xray_license_policy" "{{ .resource_name }}" {
		name        = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type        = "license"
		project_key = "{{ .project_key }}"

		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
	          {{ .allowedOrBanned }} = ["{{ .license_0 }}","{{ .license_1 }}"]
	          allow_unknown = {{ .allow_unknown }}
	          multi_license_permissive = {{ .multi_license_permissive }}
			}
			actions {
	          webhooks = []
	          mails = ["{{ .mails_0 }}", "{{ .mails_1 }}"]
	          block_download {
					unscanned = {{ .block_unscanned }}
					active = {{ .block_active }}
	          }
	          block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
	          block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
	          fail_build = {{ .fail_build }}
	          notify_watch_recipients = {{ .notify_watch_recipients }}
	          notify_deployer = {{ .notify_deployer }}
	          create_ticket_enabled = {{ .create_ticket_enabled }}
	          custom_severity = "{{ .custom_severity }}"
	          build_failure_grace_period_in_days = {{ .grace_period_days }}
			}
		}
	}`

	config := util.ExecuteTemplate(fqrn, template, testData)

	updatedTestData := sdk.MergeMaps(testData)
	updatedTestData["policy_description"] = "New description"
	updatedConfig := util.ExecuteTemplate(fqrn, template, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			acctest.CreateProject(t, projectKey)
		},
		CheckDestroy: acctest.VerifyDeleted(fqrn, "", func(id string, request *resty.Request) (*resty.Response, error) {
			acctest.DeleteProject(t, projectKey)
			return acctest.CheckPolicy(id, request)
		}),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				Config: updatedConfig,
				Check:  verifyLicensePolicy(fqrn, updatedTestData, updatedTestData["allowedOrBanned"]),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("%s:%s", testData["policy_name"], projectKey),
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccLicensePolicy_createAllowedLic(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-3-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-3-%d", testutil.RandomInt())
	testData["multi_license_permissive"] = "true"
	testData["allowedOrBanned"] = "allowed_licenses"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccLicensePolicy_createAllowedLicCustom(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-3-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-3-%d", testutil.RandomInt())
	testData["multi_license_permissive"] = "true"
	testData["allowedOrBanned"] = "allowed_licenses"
	testData["license_1"] = "Custom-License"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccLicensePolicy_createBannedLic(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-4-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-4-%d", testutil.RandomInt())
	testData["allowedOrBanned"] = "banned_licenses"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"project_key"},
			},
		},
	})
}

func TestAccLicensePolicy_createBannedLicCustom(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-4-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-4-%d", testutil.RandomInt())
	testData["allowedOrBanned"] = "banned_licenses"
	testData["license_1"] = "Custom-License"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"project_key"},
			},
		},
	})
}

func TestAccLicensePolicy_createMultiLicensePermissiveFalse(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-5-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-5-%d", testutil.RandomInt())
	testData["allowedOrBanned"] = "banned_licenses"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"project_key"},
			},
		},
	})
}

func TestAccLicensePolicy_createBlockFalse(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_license_policy")
	testData := sdk.MergeMaps(testDataLicense)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-license-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-license-rule-6-%d", testutil.RandomInt())
	testData["block_unscanned"] = "true"
	testData["block_active"] = "true"
	testData["allowedOrBanned"] = "banned_licenses"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, licensePolicyTemplate, testData),
				Check:  verifyLicensePolicy(fqrn, testData, testData["allowedOrBanned"]),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccXrayLicensePolicy_badLicense(resourceName, name, description, ruleName string, rangeTo int) string {
	return fmt.Sprintf(`
resource "xray_security_policy" "%s" {
	name = "%s"
	description = "%s"
	type = "license"
	rule {
		name = "%s"
		priority = 1
		criteria {
			cvss_range {
				from = 1
				to = %d
			}
		}
		actions {
			block_download {
				unscanned = true
				active = true
			}
		}
	}
}
`, resourceName, name, description, ruleName, rangeTo)
}

func verifyLicensePolicy(fqrn string, testData map[string]string, allowedOrBanned string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", testData["policy_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", testData["policy_description"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.name", testData["rule_name"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.allow_unknown", testData["allow_unknown"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.multi_license_permissive", testData["multi_license_permissive"]),
		resource.TestCheckResourceAttr(fqrn, fmt.Sprintf("rule.0.criteria.0.%s.0", allowedOrBanned), testData["license_0"]),
		resource.TestCheckResourceAttr(fqrn, fmt.Sprintf("rule.0.criteria.0.%s.1", allowedOrBanned), testData["license_1"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.mails.0", testData["mails_0"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.mails.1", testData["mails_1"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_release_bundle_distribution", testData["block_release_bundle_distribution"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_release_bundle_promotion", testData["block_release_bundle_promotion"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.fail_build", testData["fail_build"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_watch_recipients", testData["notify_watch_recipients"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_deployer", testData["notify_deployer"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.create_ticket_enabled", testData["create_ticket_enabled"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.build_failure_grace_period_in_days", testData["grace_period_days"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.active", testData["block_active"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.unscanned", testData["block_unscanned"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.custom_severity", testData["custom_severity"]),
	)
}

const licensePolicyTemplate = `resource "xray_license_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "license"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
          {{ .allowedOrBanned }} = ["{{ .license_0 }}","{{ .license_1 }}"]
          allow_unknown = {{ .allow_unknown }}
          multi_license_permissive = {{ .multi_license_permissive }}
		}
		actions {
          webhooks = []
          mails = ["{{ .mails_0 }}", "{{ .mails_1 }}"]
          block_download {
				unscanned = {{ .block_unscanned }}
				active = {{ .block_active }}
          }
          block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
          block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
          fail_build = {{ .fail_build }}
          notify_watch_recipients = {{ .notify_watch_recipients }}
          notify_deployer = {{ .notify_deployer }}
          create_ticket_enabled = {{ .create_ticket_enabled }}
          custom_severity = "{{ .custom_severity }}"
          build_failure_grace_period_in_days = {{ .grace_period_days }}
		}
	}
}`
