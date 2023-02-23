package xray

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/jfrog/terraform-provider-shared/test"
	"github.com/jfrog/terraform-provider-shared/util"
)

var testDataOperationalRisk = map[string]string{
	"resource_name":                     "",
	"policy_name":                       "terraform-operational-risk-policy",
	"policy_description":                "policy created by xray acceptance tests",
	"rule_name":                         "test-operational-risk-rule",
	"min_severity":                      "Medium",
	"block_release_bundle_distribution": "true",
	"fail_build":                        "true",
	"notify_watch_recipients":           "true",
	"notify_deployer":                   "true",
	"create_ticket_enabled":             "false",
	"grace_period_days":                 "5",
	"block_unscanned":                   "true",
	"block_active":                      "true",
}

func TestAccOperationalRiskPolicy_withProjectKey(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_operational_risk_policy")
	projectKey := fmt.Sprintf("testproj%d", test.RandSelect(1, 2, 3, 4, 5))

	template := `resource "xray_operational_risk_policy" "{{ .resource_name }}" {
		name        = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type        = "operational_risk"
		project_key = "{{ .project_key }}"

		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				op_risk_min_risk = "{{ .op_risk_min_risk }}"
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				fail_build = {{ .fail_build }}
				notify_watch_recipients = {{ .notify_watch_recipients }}
				notify_deployer = {{ .notify_deployer }}
				create_ticket_enabled = {{ .create_ticket_enabled }}
				build_failure_grace_period_in_days = {{ .grace_period_days }}
				block_download {
					unscanned = {{ .block_unscanned }}
					active = {{ .block_active }}
				}
			}
		}
	}`

	testData := util.MergeMaps(testDataOperationalRisk)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["op_risk_min_risk"] = "Medium"

	config := util.ExecuteTemplate(fqrn, template, testData)

	updatedTestData := util.MergeMaps(testData)
	updatedTestData["policy_description"] = "New description"
	updatedConfig := util.ExecuteTemplate(fqrn, template, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			CreateProject(t, projectKey)
		},
		CheckDestroy: verifyDeleted(fqrn, func(id string, request *resty.Request) (*resty.Response, error) {
			DeleteProject(t, projectKey)
			return testCheckPolicy(id, request)
		}),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifyOpertionalRiskPolicy(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "project_key", projectKey),
				),
			},
			{
				Config: updatedConfig,
				Check:  verifyOpertionalRiskPolicy(fqrn, updatedTestData),
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

func TestAccOperationalRiskPolicy_minRiskCriteria(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_operational_risk_policy")

	const opertionalRiskPolicyMinRisk = `resource "xray_operational_risk_policy" "{{ .resource_name }}" {
		name = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type = "operational_risk"
		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				op_risk_min_risk = "{{ .op_risk_min_risk }}"
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				fail_build = {{ .fail_build }}
				notify_watch_recipients = {{ .notify_watch_recipients }}
				notify_deployer = {{ .notify_deployer }}
				create_ticket_enabled = {{ .create_ticket_enabled }}
				build_failure_grace_period_in_days = {{ .grace_period_days }}
				block_download {
					unscanned = {{ .block_unscanned }}
					active = {{ .block_active }}
				}
			}
		}
	}`

	testData := util.MergeMaps(testDataOperationalRisk)
	testData["resource_name"] = resourceName
	testData["op_risk_min_risk"] = "Medium"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, opertionalRiskPolicyMinRisk, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyOpertionalRiskPolicy(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_min_risk", testData["op_risk_min_risk"]),
				),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccOperationalRiskPolicy_customCriteria(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_operational_risk_policy")

	const opertionalRiskPolicyCustom = `resource "xray_operational_risk_policy" "{{ .resource_name }}" {
		name = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type = "operational_risk"
		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				op_risk_custom {
					use_and_condition                  = {{ .op_risk_custom_use_and_condition }}
					is_eol                             = {{ .op_risk_custom_is_eol }}
					release_date_greater_than_months   = {{ .op_risk_custom_release_date_greater_than_months }}
					newer_versions_greater_than        = {{ .op_risk_custom_newer_versions_greater_than }}
					release_cadence_per_year_less_than = {{ .op_risk_custom_release_cadence_per_year_less_than }}
					commits_less_than                  = {{ .op_risk_custom_commits_less_than }}
					committers_less_than               = {{ .op_risk_custom_committers_less_than }}
					risk                               = "{{ .op_risk_custom_risk }}"
				}
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				fail_build = {{ .fail_build }}
				notify_watch_recipients = {{ .notify_watch_recipients }}
				notify_deployer = {{ .notify_deployer }}
				create_ticket_enabled = {{ .create_ticket_enabled }}
				build_failure_grace_period_in_days = {{ .grace_period_days }}
				block_download {
					unscanned = {{ .block_unscanned }}
					active = {{ .block_active }}
				}
			}
		}
	}`

	testData := util.MergeMaps(testDataOperationalRisk)
	testData["resource_name"] = resourceName
	testData["op_risk_custom_use_and_condition"] = "true"
	testData["op_risk_custom_is_eol"] = "false"
	testData["op_risk_custom_release_date_greater_than_months"] = test.RandSelect("6", "12", "18", "24", "30", "36").(string)
	testData["op_risk_custom_newer_versions_greater_than"] = test.RandSelect("1", "2", "3", "4", "5").(string)
	testData["op_risk_custom_release_cadence_per_year_less_than"] = test.RandSelect("1", "2", "3", "4", "5").(string)
	testData["op_risk_custom_commits_less_than"] = test.RandSelect("10", "25", "50", "100").(string)
	testData["op_risk_custom_committers_less_than"] = test.RandSelect("1", "2", "3", "4", "5").(string)
	testData["op_risk_custom_risk"] = test.RandSelect("high", "medium", "low").(string)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, opertionalRiskPolicyCustom, testData),
				Check: resource.ComposeTestCheckFunc(
					verifyOpertionalRiskPolicy(fqrn, testData),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.use_and_condition", testData["op_risk_custom_use_and_condition"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.is_eol", testData["op_risk_custom_is_eol"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.release_date_greater_than_months", testData["op_risk_custom_release_date_greater_than_months"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.newer_versions_greater_than", testData["op_risk_custom_newer_versions_greater_than"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.release_cadence_per_year_less_than", testData["op_risk_custom_release_cadence_per_year_less_than"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.commits_less_than", testData["op_risk_custom_commits_less_than"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.committers_less_than", testData["op_risk_custom_committers_less_than"]),
					resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.op_risk_custom.0.risk", testData["op_risk_custom_risk"]),
				),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func verifyOpertionalRiskPolicy(fqrn string, testData map[string]string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", testData["policy_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", testData["policy_description"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.name", testData["rule_name"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_release_bundle_distribution", testData["block_release_bundle_distribution"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.fail_build", testData["fail_build"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_watch_recipients", testData["notify_watch_recipients"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_deployer", testData["notify_deployer"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.create_ticket_enabled", testData["create_ticket_enabled"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.build_failure_grace_period_in_days", testData["grace_period_days"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.active", testData["block_active"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.unscanned", testData["block_unscanned"]),
	)
}

func TestAccOperationalRiskPolicy_criteriaValidation(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_operational_risk_policy")

	testData := util.MergeMaps(testDataOperationalRisk)
	testData["resource_name"] = resourceName

	template := `
	resource "xray_operational_risk_policy" "{{ .resource_name }}" {
		name = "{{ .policy_name }}"
		description = ""
		type = "operational_risk"
		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				op_risk_min_risk = "Low"
				op_risk_custom {
					use_and_condition                  = false
					is_eol                             = true
				}
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				fail_build = {{ .fail_build }}
				notify_watch_recipients = {{ .notify_watch_recipients }}
				notify_deployer = {{ .notify_deployer }}
				create_ticket_enabled = {{ .create_ticket_enabled }}
				build_failure_grace_period_in_days = {{ .grace_period_days }}
				block_download {
					unscanned = {{ .block_unscanned }}
					active = {{ .block_active }}
				}
			}
		}
	}`

	config := util.ExecuteTemplate(fqrn, template, testData)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),

		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile("attribute 'op_risk_min_risk' cannot be set together with 'op_risk_custom'"),
			},
		},
	})
}
