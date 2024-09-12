package xray_test

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

const criteriaTypeCvss = "cvss"
const criteriaTypeSeverity = "severity"
const criteriaTypeMaliciousPkg = "malicious_package"
const criteriaTypeVulnerabilityIds = "vulnerability_ids"
const criteriaTypeExposures = "exposures"
const criteriaTypePackageName = "package_name"

var testDataSecurity = map[string]string{
	"resource_name":                     "",
	"policy_name":                       "terraform-security-policy",
	"policy_description":                "policy created by xray acceptance tests",
	"rule_name":                         "test-security-rule",
	"cvss_from":                         "1", // conflicts with min_severity
	"cvss_to":                           "5", // conflicts with min_severity
	"applicable_cves_only":              fmt.Sprintf("%t", testutil.RandBool()),
	"min_severity":                      "High", // conflicts with cvss_from/cvss_to
	"block_release_bundle_distribution": "true",
	"block_release_bundle_promotion":    "true",
	"fail_build":                        "true",
	"notify_watch_recipients":           "true",
	"notify_deployer":                   "true",
	"create_ticket_enabled":             "false",
	"grace_period_days":                 "5",
	"block_unscanned":                   "true",
	"block_active":                      "true",
	"criteriaType":                      "cvss",
}

func TestAccSecurityPolicy_UpgradeFromSDKv2(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")

	testData := sdk.MergeMaps(testDataSecurity)
	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-4-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-4-%d", testutil.RandomInt())

	template := `
	resource "xray_security_policy" "{{ .resource_name }}" {
		name        = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type        = "security"

		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				cvss_range {
					from = {{ .cvss_from }}
					to = {{ .cvss_to }}
				}
				applicable_cves_only = {{ .applicable_cves_only }}
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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
		CheckDestroy: acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"xray": {
						Source:            "jfrog/xray",
						VersionConstraint: "2.11.0",
					},
				},
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifySecurityPolicy(fqrn, testData, criteriaTypeCvss),
				),
			},
			{
				Config:                   config,
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func TestAccSecurityPolicy_multipleRules(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-3-%d", testutil.RandomInt())
	testData["rule_name_1"] = fmt.Sprintf("test-security-rule-3-%d", testutil.RandomInt())
	testData["rule_name_2"] = fmt.Sprintf("test-security-rule-3-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyTwoRules, testData),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", testData["policy_name"]),
					resource.TestCheckResourceAttr(fqrn, "description", testData["policy_description"]),
					resource.TestCheckResourceAttr(fqrn, "rule.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "rule.*", map[string]string{
						"name": testData["rule_name_1"],
					}),
					resource.TestCheckTypeSetElemNestedAttrs(fqrn, "rule.*", map[string]string{
						"name": testData["rule_name_2"],
					}),
				),
			},
		},
	})
}

func TestAccSecurityPolicy_unknownMinSeveritySecurityPolicy_beforeVersion3602(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")

	testData := sdk.MergeMaps(testDataSecurity)
	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-%d", testutil.RandomInt())
	testData["min_severity"] = "All severities"

	var onOrAfterVersion3602 = func() (bool, error) {
		type Version struct {
			Version  string `json:"xray_version"`
			Revision string `json:"xray_revision"`
		}

		restyClient := acctest.GetTestResty(t)
		ver := Version{}

		_, err := restyClient.R().
			SetResult(&ver).
			Get("/xray/api/v1/system/version")
		if err != nil {
			return false, err
		}

		fixedVersion, err := version.NewVersion("3.60.2")
		if err != nil {
			return false, err
		}

		runtimeVersion, err := version.NewVersion(ver.Version)
		if err != nil {
			return false, err
		}

		skipTest := runtimeVersion.GreaterThanOrEqual(fixedVersion)
		if skipTest {
			fmt.Printf("Test skip because: runtime version %s is same or later than %s\n", runtimeVersion.String(), fixedVersion.String())
		}
		return skipTest, nil
	}

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				SkipFunc: onOrAfterVersion3602,
				Config:   util.ExecuteTemplate(fqrn, securityPolicyMinSeverity, testData),
				Check:    verifySecurityPolicy(fqrn, testData, criteriaTypeSeverity),
			},
		},
	})
}

// The test will try to create a security policy with the type of "license"
// The Policy criteria will be ignored in this case
func TestAccSecurityPolicy_badTypeInSecurityPolicy(t *testing.T) {
	policyName := fmt.Sprintf("terraform-security-policy-1-%d", testutil.RandomInt())
	policyDesc := "policy created by xray acceptance tests"
	ruleName := fmt.Sprintf("test-security-rule-1-%d", testutil.RandomInt())
	rangeTo := 5
	resourceName := "policy-" + strconv.Itoa(testutil.RandomInt())
	fqrn := "xray_security_policy." + resourceName
	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccXraySecurityPolicy_badSecurityType(policyName, policyDesc, ruleName, rangeTo),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

// The test will try to use "allowed_licenses" in the security policy criteria
// That field is acceptable only in license policy. No API call, expected to fail on the TF resource verification
func TestAccSecurityPolicy_badSecurityCriteria(t *testing.T) {
	policyName := fmt.Sprintf("terraform-security-policy-2-%d", testutil.RandomInt())
	policyDesc := "policy created by xray acceptance tests"
	ruleName := fmt.Sprintf("test-security-rule-2-%d", testutil.RandomInt())
	allowedLicense := "BSD-4-Clause"
	resourceName := "policy-" + strconv.Itoa(testutil.RandomInt())
	fqrn := "xray_security_policy." + resourceName
	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccXraySecurityPolicy_badSecurity(policyName, policyDesc, ruleName, allowedLicense),
				ExpectError: regexp.MustCompile("An argument named \"allow_unknown\" is not expected here."),
			},
		},
	})
}

// This test will try to create a security policy with "build_failure_grace_period_in_days" set,
// but with "fail_build" set to false, which conflicts with the field mentioned above.
func TestAccSecurityPolicy_badGracePeriod(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-3-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-3-%d", testutil.RandomInt())
	testData["fail_build"] = "false"
	testData["grace_period_days"] = "5"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

func TestAccSecurityPolicy_withProjectKey(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	projectKey := fmt.Sprintf("testproj%d", testutil.RandomInt())

	testData := sdk.MergeMaps(testDataSecurity)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-4-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-4-%d", testutil.RandomInt())

	template := `
	resource "project" "{{ .project_key }}" {
		key          = "{{ .project_key }}"
		display_name = "{{ .project_key }}"
		admin_privileges {
			manage_members   = true
			manage_resources = true
			index_resources  = true
		}
	}

	resource "xray_security_policy" "{{ .resource_name }}" {
		name        = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type        = "security"
		project_key = project.{{ .project_key }}.key

		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				cvss_range {
					from = {{ .cvss_from }}
					to = {{ .cvss_to }}
				}
				applicable_cves_only = {{ .applicable_cves_only }}
			}
			actions {
				block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
				block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

	updatedTestData := sdk.MergeMaps(testData)
	updatedTestData["policy_description"] = "New description"
	updatedConfig := util.ExecuteTemplate(fqrn, template, updatedTestData)

	resource.Test(t, resource.TestCase{
		CheckDestroy: acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ExternalProviders: map[string]resource.ExternalProvider{
			"project": {
				Source: "jfrog/project",
			},
		},
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					verifySecurityPolicy(fqrn, testData, criteriaTypeCvss),
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

// CVSS criteria, block downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadTrueCVSS(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-4-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-4-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeCvss),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"author", "created", "modified"},
			},
		},
	})
}

// CVSS criteria, allow downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadFalseCVSS(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-5-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-5-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeCvss),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Min severity criteria, block downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadTrueMinSeverity(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyMinSeverity, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeSeverity),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Min severity criteria, block downloading of unscanned and active, fix_version_dependant = true
func TestAccSecurityPolicy_createFixVersionDepMinSeverity(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["min_severity"] = "High"
	testData["fix_version_dependant"] = "true"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyFixVersionDep, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeSeverity),
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

// Malicious package criteria, block downloading of unscanned and active, fix_version_dependant = false
func TestAccSecurityPolicy_createMaliciousPackage(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["malicious_package"] = "true"
	testData["fix_version_dependant"] = "false"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyMaliciousPkgFixVersionDep, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeMaliciousPkg),
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

func TestAccSecurityPolicy_createMaliciousPackageFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["malicious_package"] = "true"
	testData["fix_version_dependant"] = "true"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyMaliciousPkgFixVersionDep, testData),
				ExpectError: regexp.MustCompile("fix_version_dependant must be set to 'false' if malicious_package is 'true'"),
			},
		},
	})
}

func TestAccSecurityPolicy_createMaliciousPackageCvssMinSeverityFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["malicious_package"] = "true"
	testData["min_severity"] = "High"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSSMinSeverityMaliciousPkg, testData),
				ExpectError: regexp.MustCompile("(?s).*Invalid Attribute Combination.*cvss_range.*cannot be specified when.*malicious_package.*is specified.*"),
			},
		},
	})
}

func TestAccSecurityPolicy_createCvssMinSeverityFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["malicious_package"] = "false"
	testData["min_severity"] = "High"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSSMinSeverityMaliciousPkg, testData),
				ExpectError: regexp.MustCompile("(?s).*Invalid Attribute Combination.*cvss_range.*cannot be specified when.*min_severity.*is specified.*"),
			},
		},
	})
}

// Min severity criteria, allow downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadFalseMinSeverity(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-7-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-7-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyMinSeverity, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeSeverity),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// CVSS criteria, use float values for CVSS range
func TestAccSecurityPolicy_createCVSSFloat(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-8-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-8-%d", testutil.RandomInt())
	testData["cvss_from"] = "1.5"
	testData["cvss_to"] = "5.3"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeCvss),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"author", "created", "modified"},
			},
		},
	})
}

// Negative test, block unscanned cannot be set without blocking of download
func TestAccSecurityPolicy_blockMismatchCVSS(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
	testData["block_unscanned"] = "true"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

func TestAccSecurityPolicy_noActions(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["CVE_1"] = "CVE-2022-12345"
	testData["CVE_2"] = "CVE-2014-111111111111111111111111"
	testData["CVE_3"] = "XRAY-1234"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyNoActions, testData),
				ExpectError: regexp.MustCompile(".*must have a configuration value as the provider has marked it as required.*"),
			},
		},
	})
}

func TestAccSecurityPolicy_vulnerabilityIds(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["CVE_1"] = "CVE-2022-12345"
	testData["CVE_2"] = "CVE-2014-111111111111111111111111"
	testData["CVE_3"] = "XRAY-1234"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyVulnIds, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeVulnerabilityIds),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccSecurityPolicy_vulnerabilityIdsIncorrectCVEFails(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	for _, invalidCVE := range []string{"CVE-20211-67890", "CVE-2021-678", "Xray-12345", "cve-2021-67890", "CVE-11-67890", "XRAY-1"} {
		testData["resource_name"] = resourceName
		testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
		testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
		testData["block_unscanned"] = "false"
		testData["block_active"] = "false"
		testData["CVE_1"] = invalidCVE
		testData["CVE_2"] = "CVE-2021-67890"
		testData["CVE_3"] = "XRAY-1234"

		resource.Test(t, resource.TestCase{
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIds, testData),
					ExpectError: regexp.MustCompile(".*invalid Vulnerability, must be a valid CVE or Xray ID.*"),
				},
			},
		})
	}
}

func TestAccSecurityPolicy_conflictingAttributesFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testAttributes := []string{
		"vulnerability_ids = [\"CVE-2022-12345\", \"CVE-2021-67890\", \"XRAY-1234\"]",
		"cvss_range {\nfrom = 1 \nto = 3\n}",
		"malicious_package = true",
		"min_severity = \"High\"",
		"exposures {\nmin_severity = \"High\" \nsecrets = true \n applications = true \n services = true \n iac = true\n}",
	}

	for _, testAttribute := range testAttributes {
		for _, conflictingAttribute := range testAttributes {
			if testAttribute == conflictingAttribute {
				continue
			}
			testData["resource_name"] = resourceName
			testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
			testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
			testData["block_unscanned"] = "false"
			testData["block_active"] = "false"
			testData["test_attribute"] = testAttribute
			testData["malicious_package"] = "true"
			testData["conflicting_attribute"] = conflictingAttribute

			resource.Test(t, resource.TestCase{
				CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIdsConflict, testData),
						ExpectError: regexp.MustCompile("(?s).*Invalid Attribute Combination.*cvss_range.*cannot be specified when.*vulnerability_ids.*is specified.*"),
					},
				},
			})
		}
	}
}

func generateListOfNames(prefix string, number int) string {
	var CVEs []string
	n := 0
	for n < number {
		CVEs = append(CVEs, fmt.Sprintf("\"%s%d\",", prefix, testutil.RandomInt()))
		n++
	}
	return fmt.Sprintf("%s", CVEs)
}

func TestAccSecurityPolicy_vulnerabilityIdsLimitFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)
	CVEString := generateListOfNames("CVE-2022-", 101)
	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["CVEs"] = CVEString

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIdsLimit, testData),
				ExpectError: regexp.MustCompile(".*set must contain at least 1 elements and at most 100 elements.*"),
			},
		},
	})
}

func TestAccSecurityPolicy_exposures(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["exposures_min_severity"] = "high"
	testData["exposures_secrets"] = "true"
	testData["exposures_applications"] = "true"
	testData["exposures_services"] = "true"
	testData["exposures_iac"] = "true"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyExposures, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeExposures),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"author", "created", "modified"},
			},
		},
	})
}

func TestAccSecurityPolicy_Packages(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-10-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-10-%d", testutil.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["package_name"] = "nuget:RazorEngine"
	testData["package_type"] = "NuGet"
	testData["package_version_1"] = "(1.2.3,3.10.2)"
	testData["package_version_2"] = "[3.11,)"
	testData["package_version_3"] = "[4.0.0]"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyPackages, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypePackageName),
			},
			{
				ResourceName:            fqrn,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"author", "created", "modified"},
			},
		},
	})
}

func TestAccSecurityPolicy_PackagesIncorrectVersionRangeFails(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	for _, invalidVersionRange := range []string{"3.10.0", "[3,,4]", "(1,latest)", "[1.0.0.0]"} {
		testData["resource_name"] = resourceName
		testData["policy_name"] = fmt.Sprintf("terraform-security-policy-10-%d", testutil.RandomInt())
		testData["rule_name"] = fmt.Sprintf("test-security-rule-10-%d", testutil.RandomInt())
		testData["block_unscanned"] = "false"
		testData["block_active"] = "false"
		testData["package_name"] = "nuget://RazorEngine"
		testData["package_type"] = "nuget"
		testData["package_version_1"] = invalidVersionRange
		testData["package_version_2"] = "(3.2.1,)"
		testData["package_version_3"] = "[3.2.1,]"

		resource.Test(t, resource.TestCase{
			CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
			ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config:      util.ExecuteTemplate(fqrn, securityPolicyPackages, testData),
					ExpectError: regexp.MustCompile(`.*invalid Range, must be one of the follows: Any Version: \(,\) or Specific\n.*Version: \[1\.2\], \[3\] or Range: \(1,\), \[,1\.2\.3\], \(4\.5\.0,6\.5\.2\].*`),
				},
			},
		})
	}
}

func TestAccSecurityPolicy_createPackagesFail(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("policy-", "xray_security_policy")
	testData := sdk.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", testutil.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", testutil.RandomInt())
	testData["package_name"] = "nuget:RazorEngine"
	testData["package_type"] = "NuGet"
	testData["package_version_1"] = "(1.2.3,3.10.2)"
	testData["package_version_2"] = "[3.11,)"
	testData["package_version_3"] = "[4.0.0]"
	testData["fix_version_dependant"] = "true"

	resource.Test(t, resource.TestCase{
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckPolicy),
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyPackagesFixVersionDep, testData),
				ExpectError: regexp.MustCompile("fix_version_dependant must be set to 'false' if any package attribute is set"),
			},
		},
	})
}

func testAccXraySecurityPolicy_badSecurityType(name, description, ruleName string, rangeTo int) string {
	return fmt.Sprintf(`
resource "xray_security_policy" "test" {
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
`, name, description, ruleName, rangeTo)
}

func testAccXraySecurityPolicy_badSecurity(name, description, ruleName, allowedLicense string) string {
	return fmt.Sprintf(`
resource "xray_security_policy" "test" {
	name = "%s"
	description = "%s"
	type = "security"
	rule {
		name = "%s"
		priority = 1
		criteria {
			allow_unknown = true
			allowed_licenses = ["%s"]
		}
		actions {
			block_download {
				unscanned = true
				active = true
			}
		}
	}
}
`, name, description, ruleName, allowedLicense)
}

func verifySecurityPolicy(fqrn string, testData map[string]string, criteriaType string) resource.TestCheckFunc {
	var commonCheckList = resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(fqrn, "name", testData["policy_name"]),
		resource.TestCheckResourceAttr(fqrn, "description", testData["policy_description"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.name", testData["rule_name"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_release_bundle_distribution", testData["block_release_bundle_distribution"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_release_bundle_promotion", testData["block_release_bundle_promotion"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.fail_build", testData["fail_build"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_watch_recipients", testData["notify_watch_recipients"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.notify_deployer", testData["notify_deployer"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.create_ticket_enabled", testData["create_ticket_enabled"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.build_failure_grace_period_in_days", testData["grace_period_days"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.active", testData["block_active"]),
		resource.TestCheckResourceAttr(fqrn, "rule.0.actions.0.block_download.0.unscanned", testData["block_unscanned"]),
	)
	if criteriaType == criteriaTypeCvss {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.cvss_range.0.from", testData["cvss_from"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.cvss_range.0.to", testData["cvss_to"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.applicable_cves_only", testData["applicable_cves_only"]),
		)
	}
	if criteriaType == criteriaTypeSeverity {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.min_severity", testData["min_severity"]),
		)
	}
	if criteriaType == criteriaTypeMaliciousPkg {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.malicious_package", testData["malicious_package"]),
		)
	}
	if criteriaType == criteriaTypeVulnerabilityIds {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckTypeSetElemAttr(fqrn, "rule.0.criteria.0.vulnerability_ids.*", testData["CVE_1"]),
		)
	}
	if criteriaType == criteriaTypeExposures {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.exposures.0.min_severity", testData["exposures_min_severity"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.exposures.0.secrets", testData["exposures_secrets"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.exposures.0.applications", testData["exposures_applications"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.exposures.0.services", testData["exposures_services"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.exposures.0.iac", testData["exposures_iac"]),
		)
	}
	if criteriaType == criteriaTypePackageName {
		return resource.ComposeTestCheckFunc(
			commonCheckList,
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.package_name", testData["package_name"]),
			resource.TestCheckResourceAttr(fqrn, "rule.0.criteria.0.package_type", testData["package_type"]),
			resource.TestCheckTypeSetElemAttr(fqrn, "rule.0.criteria.0.package_versions.*", testData["package_version_1"]),
		)
	}
	return nil
}

const securityPolicyNoActions = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			vulnerability_ids = ["{{ .CVE_1 }}", "{{ .CVE_2 }}", "{{ .CVE_3 }}"]
		}
	}
}`

const securityPolicyVulnIds = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			vulnerability_ids = ["{{ .CVE_1 }}", "{{ .CVE_2 }}", "{{ .CVE_3 }}"]
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyVulnIdsLimit = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			vulnerability_ids = {{ .CVEs }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyVulnIdsConflict = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			{{ .test_attribute }}
			{{ .conflicting_attribute }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyCVSS = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			cvss_range {
				from = {{ .cvss_from }}
				to = {{ .cvss_to }}
			}
			applicable_cves_only = {{ .applicable_cves_only }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyTwoRules = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"

	rule {
		name = "{{ .rule_name_1 }}"
		priority = 1
		criteria {
			cvss_range {
				from = {{ .cvss_from }}
				to = {{ .cvss_to }}
			}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

	rule {
		name = "{{ .rule_name_2 }}"
		priority = 2
		criteria {
			cvss_range {
				from = {{ .cvss_from }}
				to = {{ .cvss_to }}
			}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyCVSSMinSeverityMaliciousPkg = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name 		= "{{ .rule_name }}"
		priority 	= 1
		criteria {
			min_severity 	  = "{{ .min_severity }}"
			malicious_package = {{ .malicious_package }}
			cvss_range {
				from = {{ .cvss_from }}
				to 	 = {{ .cvss_to }}
			}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyMinSeverity = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			min_severity = "{{ .min_severity }}"
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyExposures = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			exposures {
				min_severity 	= "{{ .exposures_min_severity }}"
				secrets 		= {{ .exposures_secrets }}
				applications 	= {{ .exposures_applications }}
				services 		= {{ .exposures_services }}
				iac 			= {{ .exposures_iac }}
			}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyFixVersionDep = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			min_severity		  = "{{ .min_severity }}"
			fix_version_dependant = {{ .fix_version_dependant }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyMaliciousPkgFixVersionDep = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
            malicious_package	  = "{{ .malicious_package }}"
			fix_version_dependant = {{ .fix_version_dependant }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyPackagesFixVersionDep = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			package_name = "{{ .package_name }}"
			package_type = "{{ .package_type }}"
			package_versions = ["{{ .package_version_1 }}", "{{ .package_version_2 }}", "{{ .package_version_3 }}"]
			fix_version_dependant = {{ .fix_version_dependant }}
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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

const securityPolicyPackages = `resource "xray_security_policy" "{{ .resource_name }}" {
	name = "{{ .policy_name }}"
	description = "{{ .policy_description }}"
	type = "security"
	rule {
		name = "{{ .rule_name }}"
		priority = 1
		criteria {
			package_name = "{{ .package_name }}"
			package_type = "{{ .package_type }}"
			package_versions = ["{{ .package_version_1 }}", "{{ .package_version_2 }}", "{{ .package_version_3 }}"]
		}
		actions {
			block_release_bundle_distribution = {{ .block_release_bundle_distribution }}
			block_release_bundle_promotion = {{ .block_release_bundle_promotion }}
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
