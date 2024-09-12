package xray_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/client"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-xray/pkg/acctest"
)

var licenseFilterFields = map[string]interface{}{
	"filters": map[string]interface{}{
		"component":     "component-name",
		"artifact":      "impacted-artifact",
		"unknown":       false,
		"unrecognized":  true,
		"license_names": []interface{}{"Apache", "MIT"}, // conflicts with 'license_patterns'
		"scan_date": map[string]interface{}{
			"start": "2020-06-29T12:22:16Z",
			"end":   "2020-07-29T12:22:16Z",
		},
	},
}

var opRisksFilterFields = map[string]interface{}{
	"filters": map[string]interface{}{
		"component": "component-name",
		"artifact":  "impacted-artifact",
		"risks":     []interface{}{"Medium", "High"},
		"scan_date": map[string]interface{}{
			"start": "2020-06-29T12:22:16Z",
			"end":   "2020-07-29T12:22:16Z",
		},
	},
}

var violationsFilterFields = []map[string]interface{}{
	{
		"filters": map[string]interface{}{
			"type":         "security",
			"watch_names":  []interface{}{"NameOfWatch1", "NameOfWatch2"}, // Conflicts with 'watch_patterns'
			"component":    "*vulnerable:component*",
			"artifact":     "some://impacted*artifact",
			"policy_names": []interface{}{"policy1", "policy2"},
			"severities":   []interface{}{"High", "Medium"},
			"updated": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
			"security_filters": map[string]interface{}{
				"issue_id": "XRAY-87343",
				"cvss_score": map[string]interface{}{ // Conflicts with 'cve'
					"min_score": 6.3,
					"max_score": 9,
				},
				"summary_contains": "kernel",
				"has_remediation":  true,
			},
			"license_filters": map[string]interface{}{
				"unknown":       false,
				"unrecognized":  true,
				"license_names": []interface{}{"Apache", "MIT"}, // conflicts with license_patterns
			},
		},
	},
	{
		"filters": map[string]interface{}{
			"type":         "security",
			"watch_names":  []interface{}{"NameOfWatch1", "NameOfWatch2"}, // Conflicts with 'watch_patterns'
			"component":    "*vulnerable:component*",
			"artifact":     "some://impacted*artifact",
			"policy_names": []interface{}{"policy1", "policy2"},
			"severities":   []interface{}{"High", "Medium"},
			"security_filters": map[string]interface{}{
				"cve":              "CVE-2020-10693",
				"issue_id":         "XRAY-87343",
				"summary_contains": "kernel",
				"has_remediation":  true,
			},
			"license_filters": map[string]interface{}{
				"unknown":          false,
				"unrecognized":     true,
				"license_patterns": []interface{}{"*Apache*", "The Apache*"},
			},
		},
	},
	{
		"filters": map[string]interface{}{
			"type":         "security",
			"watch_names":  []interface{}{"NameOfWatch1", "NameOfWatch2"}, // Conflicts with 'watch_patterns'
			"component":    "*vulnerable:component*",
			"artifact":     "some://impacted*artifact",
			"policy_names": []interface{}{"policy1", "policy2"},
			"severities":   []interface{}{"High", "Medium"},
			"updated": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
			"license_filters": map[string]interface{}{
				"unknown":       false,
				"unrecognized":  true,
				"license_names": []interface{}{"Apache", "MIT"}, // conflicts with license_patterns
			},
		},
	},
	{
		"filters": map[string]interface{}{
			"type":         "security",
			"watch_names":  []interface{}{"NameOfWatch1", "NameOfWatch2"}, // Conflicts with 'watch_patterns'
			"component":    "*vulnerable:component*",
			"artifact":     "some://impacted*artifact",
			"policy_names": []interface{}{"policy1", "policy2"},
			"severities":   []interface{}{"High", "Medium"},
			"updated": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
			"security_filters": map[string]interface{}{
				"issue_id": "XRAY-87343",
				"cvss_score": map[string]interface{}{ // Conflicts with 'cve'
					"min_score": 6.3,
					"max_score": 9,
				},
				"summary_contains": "kernel",
				"has_remediation":  true,
			},
		},
	},
	{
		"filters": map[string]interface{}{
			"type":         "security",
			"watch_names":  []interface{}{"NameOfWatch1", "NameOfWatch2"}, // Conflicts with 'watch_patterns'
			"component":    "*vulnerable:component*",
			"artifact":     "some://impacted*artifact",
			"policy_names": []interface{}{"policy1", "policy2"},
			"severities":   []interface{}{"High", "Medium"},
		},
	},
}

var vulnerabilitiesFilterFields = map[string]interface{}{
	"filters": map[string]interface{}{
		"vulnerable_component": "component-name",
		"impacted_artifact":    "impacted-artifact",
		"has_remediation":      false,
		"cve":                  "CVE-1234-1234", // conflicts with 'issue_id'
		"cvss_score": map[string]interface{}{ // conflicts with 'severities'
			"min_score": 6.3,
			"max_score": 9,
		},
		"published": map[string]interface{}{
			"start": "2020-06-29T12:22:16Z",
			"end":   "2020-07-29T12:22:16Z",
		},
		"scan_date": map[string]interface{}{
			"start": "2020-06-29T12:22:16Z",
			"end":   "2020-07-29T12:22:16Z",
		},
	},
}

var resourcesList = []map[string]interface{}{
	{
		"name": "repository_by_name_and_pattern",
		"resources": map[string]interface{}{
			"repository": map[string]interface{}{
				"name":                  "repository-name",
				"include_path_patterns": []interface{}{"pattern1", "pattern12"},
				"exclude_path_patterns": []interface{}{"pattern1", "pattern12"},
			},
		},
	},
	{
		"name": "builds_by_names",
		"resources": map[string]interface{}{
			"builds": map[string]interface{}{
				"names":                     []interface{}{"build1", "build2"},
				"number_of_latest_versions": 2,
			},
		},
	},
	{
		"name": "builds_by_patterns",
		"resources": map[string]interface{}{
			"builds": map[string]interface{}{
				"include_patterns":          []interface{}{"pattern1", "pattern12"},
				"exclude_patterns":          []interface{}{"pattern1", "pattern12"},
				"number_of_latest_versions": 2,
			},
		},
	},
	{
		"name": "release_bundles_by_names",
		"resources": map[string]interface{}{
			"release_bundles": map[string]interface{}{
				"names":                     []interface{}{"release_bundle1", "release_bundle2"},
				"number_of_latest_versions": 2,
			},
		},
	},
	{
		"name": "release_bundles_by_patterns",
		"resources": map[string]interface{}{
			"release_bundles": map[string]interface{}{
				"include_patterns":          []interface{}{"pattern1", "pattern2"},
				"exclude_patterns":          []interface{}{"exclude_pattern1", "exclude_pattern2"},
				"number_of_latest_versions": 2,
			},
		},
	},
	{
		"name": "projects_by_names",
		"resources": map[string]interface{}{
			"projects": map[string]interface{}{
				"names":                     []interface{}{"project_key1", "project_key2"},
				"number_of_latest_versions": 2,
			},
		},
	},
	{
		"name": "projects_by_patterns",
		"resources": map[string]interface{}{
			"projects": map[string]interface{}{
				"include_key_patterns":      []interface{}{"include_pattern1", "include_pattern2"},
				"number_of_latest_versions": 2,
			},
		},
	},
}

var resourcesListNegative = []map[string]interface{}{
	{
		"name": "builds_by_names_and_patterns_should_fail",
		"resources": map[string]interface{}{
			"builds": map[string]interface{}{
				"names":                     []interface{}{"build1", "build2"},
				"include_patterns":          []interface{}{"pattern1", "pattern12"},
				"exclude_patterns":          []interface{}{"pattern1", "pattern12"},
				"number_of_latest_versions": 2,
			},
		},
		"errorMessage": "(?s).*Invalid Attribute Combination.*names.*cannot be specified when.*include_patterns.*is specified.*",
	},
	{
		"name": "release_bundles_by_names_and_patterns_should_fail",
		"resources": map[string]interface{}{
			"release_bundles": map[string]interface{}{
				"names":                     []interface{}{"release_bundle1", "release_bundle2"},
				"include_patterns":          []interface{}{"pattern1", "pattern2"},
				"exclude_patterns":          []interface{}{"exclude_pattern1", "exclude_pattern2"},
				"number_of_latest_versions": 2,
			},
		},
		"errorMessage": "(?s).*Invalid Attribute Combination.*names.*cannot be specified when.*include_patterns.*is specified.*",
	},
	{
		"name": "projects_by_names_and_patterns_should_fail",
		"resources": map[string]interface{}{
			"projects": map[string]interface{}{
				"names":                     []interface{}{"project_key1", "project_key2"},
				"include_key_patterns":      []interface{}{"include_pattern1", "include_pattern2"},
				"number_of_latest_versions": 2,
			},
		},
		"errorMessage": "(?s).*Invalid Attribute Combination.*names.*cannot be specified when.*include_key_patterns.*is specified.*",
	},
}

func TestAccReport_Licenses(t *testing.T) {
	terraformReportName := "terraform-licenses-report"
	terraformResourceName := "xray_licenses_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase(t, reportResource, licenseFilterFields, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_Licenses_UpgradeFromSDKv2(t *testing.T) {
	terraformReportName := "terraform-licenses-report"
	terraformResourceName := "xray_licenses_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase_UpgradeFromSDKv2(t, reportResource, licenseFilterFields, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_OperationalRisks(t *testing.T) {
	terraformReportName := "terraform-operational-risks-report"
	terraformResourceName := "xray_operational_risks_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase(t, reportResource, opRisksFilterFields, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_Violations(t *testing.T) {
	terraformReportName := "terraform-violations-report"
	terraformResourceName := "xray_violations_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase(t, reportResource, violationsFilterFields[0], terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_Violations_UpgradeFromSDKv2(t *testing.T) {
	terraformReportName := "terraform-violations-report"
	terraformResourceName := "xray_violations_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase_UpgradeFromSDKv2(t, reportResource, violationsFilterFields[0], terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccViolationsReportFilters(t *testing.T) {
	terraformReportName := "terraform-violations-report"
	terraformResourceName := "xray_violations_report"

	for _, violationsFilter := range violationsFilterFields {
		t.Run("various_violations_filters", func(t *testing.T) {
			resource.Test(mkFilterTestCase(t, resourcesList[0], violationsFilter, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_Vulnerabilities(t *testing.T) {
	terraformReportName := "terraform-vulnerabilities-report"
	terraformResourceName := "xray_vulnerabilities_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase(t, reportResource, vulnerabilitiesFilterFields, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_Vulnerabilities_UpgradeFromSDKv2(t *testing.T) {
	terraformReportName := "terraform-vulnerabilities-report"
	terraformResourceName := "xray_vulnerabilities_report"

	for _, reportResource := range resourcesList {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterTestCase_UpgradeFromSDKv2(t, reportResource, vulnerabilitiesFilterFields, terraformReportName,
				terraformResourceName))
		})
	}
}

func TestAccReport_BadResource(t *testing.T) {
	terraformReportName := "terraform-licenses-report"
	terraformResourceName := "xray_licenses_report"

	for _, reportResource := range resourcesListNegative {
		resourceNameInReport := reportResource["name"].(string)
		t.Run(resourceNameInReport, func(t *testing.T) {
			resource.Test(mkFilterNegativeTestCase(t, reportResource, licenseFilterFields, terraformReportName,
				terraformResourceName, reportResource["errorMessage"].(string)))
		})
	}
}

func TestAccReport_BadLicenseFilter(t *testing.T) {
	terraformReportName := "terraform-licenses-report"
	terraformResourceName := "xray_licenses_report"
	expectedErrorMessage := "(?s).*Invalid Attribute Combination.*license_patterns.*cannot be specified when.*license_names.*is specified.*"

	var filterFieldsConflict = map[string]interface{}{
		"filters": map[string]interface{}{
			"component":        "component-name",
			"artifact":         "impacted-artifact",
			"unknown":          false,
			"unrecognized":     true,
			"license_names":    []interface{}{"Apache", "MIT"}, // conflicts with 'license_patterns'
			"license_patterns": []interface{}{"*Apache*", "The Apache*"},
			"scan_date": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
		},
	}

	resourceNameInReport := resourcesList[0]["name"].(string)
	t.Run(resourceNameInReport, func(t *testing.T) {
		resource.Test(mkFilterNegativeTestCase(t, resourcesList[0], filterFieldsConflict, terraformReportName,
			terraformResourceName, expectedErrorMessage))
	})

}

func TestAccReport_BadViolationsFilter(t *testing.T) {
	terraformReportName := "terraform-violations-report"
	terraformResourceName := "xray_violations_report"
	expectedErrorMessage := "(?s).*Invalid Attribute Combination.*watch_patterns.*cannot be specified when.*watch_names.*is specified.*"

	var filterFieldsConflict = map[string]interface{}{
		"filters": map[string]interface{}{
			"type":           "security",
			"watch_names":    []interface{}{"NameOfWatch1", "NameOfWatch2"},
			"watch_patterns": []interface{}{"WildcardWatch*", "WildcardWatch1*"},
			"component":      "*vulnerable:component*",
			"artifact":       "some://impacted*artifact",
			"policy_names":   []interface{}{"policy1", "policy2"},
			"severities":     []interface{}{"High", "Medium"},
			"updated": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
			"security_filters": map[string]interface{}{
				"cve":      "CVE-2020-10693", // Conflicts with cvss_score
				"issue_id": "XRAY-87343",
				"cvss_score": map[string]interface{}{
					"min_score": 6.3,
					"max_score": 9,
				},
				"summary_contains": "kernel",
				"has_remediation":  true,
			},
			"license_filters": map[string]interface{}{
				"unknown":          false,
				"unrecognized":     true,
				"license_names":    []interface{}{"Apache", "MIT"}, // conflicts with license_patterns
				"license_patterns": []interface{}{"*Apache*", "The Apache*"},
			},
		},
	}

	resourceNameInReport := resourcesList[0]["name"].(string)
	t.Run(resourceNameInReport, func(t *testing.T) {
		resource.Test(mkFilterNegativeTestCase(t, resourcesList[0], filterFieldsConflict, terraformReportName,
			terraformResourceName, expectedErrorMessage))
	})
}

func TestAccReport_BadVulnerabilitiesFilter(t *testing.T) {
	terraformReportName := "terraform-vulnerabilities-report"
	terraformResourceName := "xray_vulnerabilities_report"
	expectedErrorMessage := "(?s).*Invalid Attribute Combination.*severities.*cannot be specified when.*cvss_score.*is specified.*"

	var filterFieldsConflict = map[string]interface{}{
		"filters": map[string]interface{}{
			"vulnerable_component": "component-name",
			"impacted_artifact":    "impacted-artifact",
			"has_remediation":      false,
			"cve":                  "CVE-1234-1234",
			"severities":           []interface{}{"High", "Medium"}, // conflicts with cvss_score
			"cvss_score": map[string]interface{}{
				"min_score": 6.3,
				"max_score": 9,
			},
			"published": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
			"scan_date": map[string]interface{}{
				"start": "2020-06-29T12:22:16Z",
				"end":   "2020-07-29T12:22:16Z",
			},
		},
	}

	resourceNameInReport := resourcesList[0]["name"].(string)
	t.Run(resourceNameInReport, func(t *testing.T) {
		resource.Test(mkFilterNegativeTestCase(t, resourcesList[0], filterFieldsConflict, terraformReportName,
			terraformResourceName, expectedErrorMessage))
	})
}

func mkFilterTestCase(t *testing.T, resourceFields map[string]interface{}, filterFields map[string]interface{},
	reportName string, resourceName string) (*testing.T, resource.TestCase) {
	_, fqrn, name := testutil.MkNames(reportName, resourceName)

	allFields := sdk.MergeMaps(filterFields, resourceFields)
	allFieldsHcl := sdk.FmtMapToHcl(allFields)
	const remoteRepoFull = `
		resource "%s" "%s" {
%s
		}
	`
	extraChecks := testutil.MapToTestChecks(fqrn, resourceFields)
	defaultChecks := testutil.MapToTestChecks(fqrn, allFields)

	checks := append(defaultChecks, extraChecks...)
	config := fmt.Sprintf(remoteRepoFull, resourceName, name, allFieldsHcl)

	return t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", testCheckReport), // how to get ID?
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	}
}

func mkFilterTestCase_UpgradeFromSDKv2(t *testing.T, resourceFields map[string]interface{}, filterFields map[string]interface{},
	reportName string, resourceName string) (*testing.T, resource.TestCase) {
	_, fqrn, name := testutil.MkNames(reportName, resourceName)

	allFields := sdk.MergeMaps(filterFields, resourceFields)
	allFieldsHcl := sdk.FmtMapToHcl(allFields)
	const remoteRepoFull = `
		resource "%s" "%s" {
%s
		}
	`
	extraChecks := testutil.MapToTestChecks(fqrn, resourceFields)
	defaultChecks := testutil.MapToTestChecks(fqrn, allFields)

	checks := append(defaultChecks, extraChecks...)
	config := fmt.Sprintf(remoteRepoFull, resourceName, name, allFieldsHcl)

	return t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		CheckDestroy: acctest.VerifyDeleted(fqrn, "", testCheckReport), // how to get ID?
		Steps: []resource.TestStep{
			{
				Config: config,
				ExternalProviders: map[string]resource.ExternalProvider{
					"xray": {
						Source:            "jfrog/xray",
						VersionConstraint: "2.11.0",
					},
				},
				Check: resource.ComposeTestCheckFunc(checks...),
			},
			{
				Config:                   config,
				ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
				PlanOnly:                 true,
				ConfigPlanChecks:         testutil.ConfigPlanChecks(""),
				// ConfigPlanChecks: resource.ConfigPlanChecks{
				// 	PreApply: []plancheck.PlanCheck{
				// 		plancheck.ExpectEmptyPlan(),
				// 	},
				// },
			},
		},
	}
}

func mkFilterNegativeTestCase(t *testing.T, resourceFields map[string]interface{}, filterFields map[string]interface{},
	reportName string, resourceName string, expectedErrorMessage string) (*testing.T, resource.TestCase) {
	_, _, name := testutil.MkNames(reportName, resourceName)

	allFields := sdk.MergeMaps(filterFields, resourceFields)
	allFieldsHcl := sdk.FmtMapToHcl(allFields)
	const remoteRepoFull = `
		resource "%s" "%s" {
%s
		}
	`

	config := fmt.Sprintf(remoteRepoFull, resourceName, name, allFieldsHcl)

	return t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6MuxProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(expectedErrorMessage),
			},
		},
	}
}

func checkReport(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v1/reports/" + id)
}

func testCheckReport(id string, request *resty.Request) (*resty.Response, error) {
	return checkReport(id, request.AddRetryCondition(client.NeverRetry))
}
