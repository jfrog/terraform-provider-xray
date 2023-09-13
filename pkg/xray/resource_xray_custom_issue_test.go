package xray

import (
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
)

const template = `
	resource "xray_custom_issue" "{{ .name }}" {
		name          = "{{ .name }}"
		description   = "{{ .description }}"
		summary       = "{{ .summary }}"
		type          = "{{ .type }}"
		provider_name = "{{ .provider_name }}"
		package_type  = "{{ .package_type }}"
		severity      = "{{ .severity }}"

		component {
			id                  = "{{ .component_id }}"
			vulnerable_versions = ["{{ .component_vulnerable_versions }}"]
			vulnerable_ranges {
				vulnerable_versions = ["{{ .component_vulnerable_ranges_vulnerable_versions }}"]
			}
		}

		cve {
			cve     = "{{ .cve }}"
			cvss_v2 = "{{ .cve_cvss_v2 }}"
		}

		source {
			id = "{{ .source_id }}"
		}
	}
`

const fullTemplate = `
	resource "xray_custom_issue" "{{ .name }}" {
		name          = "{{ .name }}"
		description   = "{{ .description }}"
		summary       = "{{ .summary }}"
		type          = "{{ .type }}"
		provider_name = "{{ .provider_name }}"
		package_type  = "{{ .package_type }}"
		severity      = "{{ .severity }}"

		component {
			id                  = "{{ .component_id }}"
			vulnerable_versions = ["{{ .component_vulnerable_versions }}"]
			fixed_versions      = ["{{ .component_fixed_versions }}"]
			vulnerable_ranges {
				vulnerable_versions = ["{{ .component_vulnerable_ranges_vulnerable_versions }}"]
				fixed_versions      = ["{{ .component_vulnerable_ranges_fixed_versions }}"]
			}
		}

		cve {
			cve     = "{{ .cve }}"
			cvss_v2 = "{{ .cve_cvss_v2 }}"
			cvss_v3 = "{{ .cve_cvss_v3 }}"
		}

		source {
			id   = "{{ .source_id }}"
			name = "{{ .source_name }}"
			url  = "{{ .source_url }}"
		}
	}
`

func TestAccCustomIssue_full(t *testing.T) {
	_, fqrn, resourceName := testutil.MkNames("custom-issue-", "xray_custom_issue")

	testData := map[string]string{
		"name":                          resourceName,
		"description":                   "test description",
		"summary":                       "test summary",
		"type":                          "security",
		"provider_name":                 "test",
		"package_type":                  "generic",
		"severity":                      "Medium",
		"component_id":                  "aero:aero",
		"component_vulnerable_versions": "[0.2.3]",
		"component_vulnerable_ranges_vulnerable_versions": "[0.2.3]",
		"cve":         "CVE-2017-1000386",
		"cve_cvss_v2": "2.4",
		"source_id":   "CVE-2017-1000386",
	}

	config := sdk.ExecuteTemplate("TestAccCustomIssue_full", template, testData)

	updatedTestData := map[string]string{
		"name":                          resourceName,
		"description":                   "test description 2",
		"summary":                       "test summary 2",
		"type":                          "security",
		"provider_name":                 "test2",
		"package_type":                  "generic",
		"severity":                      "High",
		"component_id":                  "aero:aero",
		"component_vulnerable_versions": "[0.1.2]",
		"component_fixed_versions":      "[0.3.4]",
		"component_vulnerable_ranges_vulnerable_versions": "[0.1.2]",
		"component_vulnerable_ranges_fixed_versions":      "[0.3.4]",
		"cve":         "CVE-2017-1000386",
		"cve_cvss_v2": "3.4",
		"cve_cvss_v3": "5.6",
		"source_id":   "CVE-2017-1000386",
		"source_name": "CVE-2017-1000386",
		"source_url":  "https://nvd.nist.gov/vuln/detail/CVE-2017-1000386",
	}
	updatedConfig := sdk.ExecuteTemplate("TestAccCustomIssue_full", fullTemplate, updatedTestData)

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviders(),
		CheckDestroy:      verifyDeleted(fqrn, testCheckCustomIssue),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", testData["name"]),
					resource.TestCheckResourceAttr(fqrn, "name", testData["name"]),
					resource.TestCheckResourceAttr(fqrn, "description", testData["description"]),
					resource.TestCheckResourceAttr(fqrn, "summary", testData["summary"]),
					resource.TestCheckResourceAttr(fqrn, "type", testData["type"]),
					resource.TestCheckResourceAttr(fqrn, "provider_name", testData["provider_name"]),
					resource.TestCheckResourceAttr(fqrn, "package_type", testData["package_type"]),
					resource.TestCheckResourceAttr(fqrn, "severity", testData["severity"]),
					resource.TestCheckResourceAttr(fqrn, "component.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "component.0.id", testData["component_id"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_versions.0", testData["component_vulnerable_versions"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.fixed_versions.#", "0"),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_ranges.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_ranges.0.vulnerable_versions.0", testData["component_vulnerable_ranges_vulnerable_versions"]),
					resource.TestCheckResourceAttr(fqrn, "cve.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cve", testData["cve"]),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cvss_v2", testData["cve_cvss_v2"]),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cvss_v3.#", "0"),
					resource.TestCheckResourceAttr(fqrn, "source.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "source.0.id", testData["source_id"]),
					resource.TestCheckResourceAttr(fqrn, "source.0.name.#", "0"),
					resource.TestCheckResourceAttr(fqrn, "source.0.url.#", "0"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "id", updatedTestData["name"]),
					resource.TestCheckResourceAttr(fqrn, "name", updatedTestData["name"]),
					resource.TestCheckResourceAttr(fqrn, "description", updatedTestData["description"]),
					resource.TestCheckResourceAttr(fqrn, "summary", updatedTestData["summary"]),
					resource.TestCheckResourceAttr(fqrn, "type", updatedTestData["type"]),
					resource.TestCheckResourceAttr(fqrn, "provider_name", updatedTestData["provider_name"]),
					resource.TestCheckResourceAttr(fqrn, "package_type", updatedTestData["package_type"]),
					resource.TestCheckResourceAttr(fqrn, "severity", updatedTestData["severity"]),
					resource.TestCheckResourceAttr(fqrn, "component.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "component.0.id", updatedTestData["component_id"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_versions.0", updatedTestData["component_vulnerable_versions"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.fixed_versions.0", updatedTestData["component_fixed_versions"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_ranges.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_ranges.0.vulnerable_versions.0", updatedTestData["component_vulnerable_ranges_vulnerable_versions"]),
					resource.TestCheckResourceAttr(fqrn, "component.0.vulnerable_ranges.0.fixed_versions.0", updatedTestData["component_vulnerable_ranges_fixed_versions"]),
					resource.TestCheckResourceAttr(fqrn, "cve.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cve", updatedTestData["cve"]),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cvss_v2", updatedTestData["cve_cvss_v2"]),
					resource.TestCheckResourceAttr(fqrn, "cve.0.cvss_v3", updatedTestData["cve_cvss_v3"]),
					resource.TestCheckResourceAttr(fqrn, "source.#", "1"),
					resource.TestCheckResourceAttr(fqrn, "source.0.id", updatedTestData["source_id"]),
					resource.TestCheckResourceAttr(fqrn, "source.0.name", updatedTestData["source_name"]),
					resource.TestCheckResourceAttr(fqrn, "source.0.url", updatedTestData["source_url"]),
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

func TestAccCustomIssue_invalid(t *testing.T) {
	testCases := []struct {
		name       string
		extras     map[string]string
		errorRegex string
	}{
		{name: "name", extras: map[string]string{"name": "xray"}, errorRegex: `.*must not begin with 'xray' \(case insensitive\).*`},
		{name: "type", extras: map[string]string{"type": "foo"}, errorRegex: ".*Invalid string.*"},
		{name: "provider_name", extras: map[string]string{"provider_name": "jfrog"}, errorRegex: `.*must not be 'jfrog' \(case insensitive\).*`},
		{name: "package_type", extras: map[string]string{"package_type": "foo"}, errorRegex: ".*Invalid string.*"},
		{name: "severity", extras: map[string]string{"severity": "foo"}, errorRegex: ".*Invalid string.*"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, resourceName := testutil.MkNames("custom-issue-", "xray_custom_issue")

			testData := sdk.MergeMaps(
				map[string]string{
					"name":                          resourceName,
					"description":                   "test description",
					"summary":                       "test summary",
					"type":                          "security",
					"provider_name":                 "test",
					"package_type":                  "generic",
					"severity":                      "Medium",
					"component_id":                  "aero:aero",
					"component_vulnerable_versions": "[0.2.3]",
					"component_vulnerable_ranges_vulnerable_versions": "[0.2.3]",
					"cve":         "CVE-2017-1000386",
					"cve_cvss_v2": "2.4",
					"source_id":   "CVE-2017-1000386",
				},
				testCase.extras,
			)

			config := sdk.ExecuteTemplate("TestAccCustomIssue_invalid", template, testData)

			resource.Test(t, resource.TestCase{
				PreCheck:          func() { testAccPreCheck(t) },
				ProviderFactories: testAccProviders(),
				Steps: []resource.TestStep{
					{
						Config:      config,
						ExpectError: regexp.MustCompile(testCase.errorRegex),
					},
				},
			})
		})
	}
}

func testCheckCustomIssue(id string, request *resty.Request) (*resty.Response, error) {
	return request.
		SetPathParam("id", id).
		Get("xray/api/v2/events/{id}")
}
