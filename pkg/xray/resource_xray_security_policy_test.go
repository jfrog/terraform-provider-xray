package xray

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/jfrog/terraform-provider-shared/test"
	"github.com/jfrog/terraform-provider-shared/util"
)

const criteriaTypeCvss = "cvss"
const criteriaTypeSeverity = "severity"
const criteriaTypeMaliciousPkg = "malicious_package"
const criteriaTypeVulnerabilityIds = "vulnerability_ids"
const criteriaTypeExposures = "exposures"

var testDataSecurity = map[string]string{
	"resource_name":                     "",
	"policy_name":                       "terraform-security-policy",
	"policy_description":                "policy created by xray acceptance tests",
	"rule_name":                         "test-security-rule",
	"cvss_from":                         "1",    // conflicts with min_severity
	"cvss_to":                           "5",    // conflicts with min_severity
	"min_severity":                      "High", // conflicts with cvss_from/cvss_to
	"block_release_bundle_distribution": "true",
	"fail_build":                        "true",
	"notify_watch_recipients":           "true",
	"notify_deployer":                   "true",
	"create_ticket_enabled":             "false",
	"grace_period_days":                 "5",
	"block_unscanned":                   "true",
	"block_active":                      "true",
	"criteriaType":                      "cvss",
}

func TestAccSecurityPolicy_unknownMinSeveritySecurityPolicy_beforeVersion3602(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")

	testData := util.MergeMaps(testDataSecurity)
	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-%d", test.RandomInt())
	testData["min_severity"] = "All severities"

	var onOrAfterVersion3602 = func() (bool, error) {
		type Version struct {
			Version  string `json:"xray_version"`
			Revision string `json:"xray_revision"`
		}

		restyClient := GetTestResty(t)
		ver := Version{}

		_, err := restyClient.R().
			SetResult(&ver).
			Get("/xray/api/v1/system/version")
		if err != nil {
			return false, err
		}

		fmt.Printf("Ver: %v\n", ver)

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
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	policyName := fmt.Sprintf("terraform-security-policy-1-%d", test.RandomInt())
	policyDesc := "policy created by xray acceptance tests"
	ruleName := fmt.Sprintf("test-security-rule-1-%d", test.RandomInt())
	rangeTo := 5
	resourceName := "policy-" + strconv.Itoa(test.RandomInt())
	fqrn := "xray_security_policy." + resourceName
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	policyName := fmt.Sprintf("terraform-security-policy-2-%d", test.RandomInt())
	policyDesc := "policy created by xray acceptance tests"
	ruleName := fmt.Sprintf("test-security-rule-2-%d", test.RandomInt())
	allowedLicense := "BSD-4-Clause"
	resourceName := "policy-" + strconv.Itoa(test.RandomInt())
	fqrn := "xray_security_policy." + resourceName
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-3-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-3-%d", test.RandomInt())
	testData["fail_build"] = "false"
	testData["grace_period_days"] = "5"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

func TestAccSecurityPolicy_withProjectKey(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	projectKey := fmt.Sprintf("testproj%d", test.RandSelect(1, 2, 3, 4, 5))

	testData := util.MergeMaps(testDataSecurity)
	testData["resource_name"] = resourceName
	testData["project_key"] = projectKey
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-4-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-4-%d", test.RandomInt())

	template := `resource "xray_security_policy" "{{ .resource_name }}" {
		name        = "{{ .policy_name }}"
		description = "{{ .policy_description }}"
		type        = "security"
		project_key = "{{ .project_key }}"

		rule {
			name = "{{ .rule_name }}"
			priority = 1
			criteria {
				cvss_range {
					from = {{ .cvss_from }}
					to = {{ .cvss_to }}
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-4-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-4-%d", test.RandomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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

// CVSS criteria, allow downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadFalseCVSS(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-5-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-5-%d", test.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["min_severity"] = "High"
	testData["fix_version_dependant"] = "true"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["malicious_package"] = "true"
	testData["fix_version_dependant"] = "false"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["malicious_package"] = "true"
	testData["fix_version_dependant"] = "true"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyMaliciousPkgFixVersionDep, testData),
				ExpectError: regexp.MustCompile("fix_version_dependant must be set to false if malicious_package is true"),
			},
		},
	})
}

func TestAccSecurityPolicy_createMaliciousPackageCvssMinSeverityFail(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["malicious_package"] = "true"
	testData["min_severity"] = "High"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSSMinSeverityMaliciousPkg, testData),
				ExpectError: regexp.MustCompile("malicious_package can't be set together with min_severity and/or cvss_range"),
			},
		},
	})
}

func TestAccSecurityPolicy_createCvssMinSeverityFail(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["malicious_package"] = "false"
	testData["min_severity"] = "High"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSSMinSeverityMaliciousPkg, testData),
				ExpectError: regexp.MustCompile("min_severity can't be set together with cvss_range"),
			},
		},
	})
}

// Min severity criteria, allow downloading of unscanned and active
func TestAccSecurityPolicy_createBlockDownloadFalseMinSeverity(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-7-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-7-%d", test.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-8-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-8-%d", test.RandomInt())
	testData["cvss_from"] = "1.5"
	testData["cvss_to"] = "5.3"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
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

// Negative test, block unscanned cannot be set without blocking of download
func TestAccSecurityPolicy_blockMismatchCVSS(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", test.RandomInt())
	testData["block_unscanned"] = "true"
	testData["block_active"] = "false"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyCVSS, testData),
				ExpectError: regexp.MustCompile("Found Invalid Policy"),
			},
		},
	})
}

func TestAccSecurityPolicy_vulnerabilityIds(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", test.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["CVE_1"] = "CVE-2022-12345"
	testData["CVE_2"] = "CVE-2014-111111111111111111111111"
	testData["CVE_3"] = "XRAY-1234"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyVulnIds, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeVulnerabilityIds),
			},
		},
	})
}

func TestAccSecurityPolicy_vulnerabilityIdsIncorrectCVEFails(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	for _, invalidCVE := range []string{"CVE-20211-67890", "CVE-2021-678", "Xray-12345", "cve-2021-67890", "CVE-11-67890", "XRAY-1"} {
		testData["resource_name"] = resourceName
		testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", test.RandomInt())
		testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", test.RandomInt())
		testData["block_unscanned"] = "false"
		testData["block_active"] = "false"
		testData["CVE_1"] = invalidCVE
		testData["CVE_2"] = "CVE-2021-67890"
		testData["CVE_3"] = "XRAY-1234"

		resource.Test(t, resource.TestCase{
			PreCheck:          func() { testAccPreCheck(t) },
			CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
			ProviderFactories: testAccProviders(),
			Steps: []resource.TestStep{
				{
					Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIds, testData),
					ExpectError: regexp.MustCompile("invalid value for vulnerability_ids"),
				},
			},
		})
	}
}

func TestAccSecurityPolicy_conflictingAttributesFail(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

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
			testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", test.RandomInt())
			testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", test.RandomInt())
			testData["block_unscanned"] = "false"
			testData["block_active"] = "false"
			testData["test_attribute"] = testAttribute
			testData["malicious_package"] = "true"
			testData["conflicting_attribute"] = conflictingAttribute

			resource.Test(t, resource.TestCase{
				PreCheck:          func() { testAccPreCheck(t) },
				CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
				ProviderFactories: testAccProviders(),
				Steps: []resource.TestStep{
					{
						Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIdsConflict, testData),
						ExpectError: regexp.MustCompile("can't be set together"),
					},
				},
			})
		}
	}
}
func TestAccSecurityPolicy_vulnerabilityIdsLimitFail(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)
	CVEString := generateListOfNames("CVE-2022-", 101)
	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-9-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-9-%d", test.RandomInt())
	testData["block_unscanned"] = "false"
	testData["block_active"] = "false"
	testData["CVEs"] = CVEString

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config:      util.ExecuteTemplate(fqrn, securityPolicyVulnIdsLimit, testData),
				ExpectError: regexp.MustCompile("Too many list items"),
			},
		},
	})
}

func TestAccSecurityPolicy_exposures(t *testing.T) {
	_, fqrn, resourceName := test.MkNames("policy-", "xray_security_policy")
	testData := util.MergeMaps(testDataSecurity)

	testData["resource_name"] = resourceName
	testData["policy_name"] = fmt.Sprintf("terraform-security-policy-6-%d", test.RandomInt())
	testData["rule_name"] = fmt.Sprintf("test-security-rule-6-%d", test.RandomInt())
	testData["exposures_min_severity"] = "High"
	testData["exposures_secrets"] = "true"
	testData["exposures_applications"] = "true"
	testData["exposures_services"] = "true"
	testData["exposures_iac"] = "true"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      verifyDeleted(fqrn, testCheckPolicy),
		ProviderFactories: testAccProviders(),
		Steps: []resource.TestStep{
			{
				Config: util.ExecuteTemplate(fqrn, securityPolicyExposures, testData),
				Check:  verifySecurityPolicy(fqrn, testData, criteriaTypeExposures),
			},
			{
				ResourceName:      fqrn,
				ImportState:       true,
				ImportStateVerify: true,
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
	return nil
}

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
//vulnerability_ids = ["{{ .CVE_1 }}", "{{ .CVE_2 }}", "{{ .CVE_3 }}"]
			{{ .conflicting_attribute }}
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
