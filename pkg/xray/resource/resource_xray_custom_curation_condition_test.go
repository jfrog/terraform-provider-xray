package xray_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

// Simple smoke test to verify basic resource creation works
func TestAccCustomCurationCondition_CVEName_Smoke(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cve-condition", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVEName(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(fqrn, "id"),
					resource.TestCheckResourceAttr(fqrn, "name", name),
				),
			},
		},
	})
}

// CVEName Tests
func TestAccCustomCurationCondition_CVEName_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cve-condition", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVEName(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVEName"),
					resource.TestCheckResourceAttrSet(fqrn, "id"),
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

func TestAccCustomCurationCondition_CVEName_Update(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cve-update", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVEName(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVEName"),
				),
			},
			{
				Config: testAccCustomCurationConditionCVENameUpdated(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name+"-updated"),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVEName"),
				),
			},
		},
	})
}

// CVECVSSRange Tests
func TestAccCustomCurationCondition_CVECVSSRange_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cvss-basic", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVECVSSRangeBasic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVECVSSRange"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_CVECVSSRange_Complete(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cvss-complete", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVECVSSRangeComplete(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVECVSSRange"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_CVECVSSRange_WithEPSSScore(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cvss-epss-score", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVECVSSRangeWithEPSSScore(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVECVSSRange"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_CVECVSSRange_WithEPSSPercentile(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-cvss-epss-percentile", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionCVECVSSRangeWithEPSSPercentile(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "CVECVSSRange"),
				),
			},
		},
	})
}

// SpecificVersions Tests
func TestAccCustomCurationCondition_SpecificVersions_Equals(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-versions-equals", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionSpecificVersionsEquals(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "SpecificVersions"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_SpecificVersions_ComparisonOperators(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-versions-comparison", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionSpecificVersionsComparison(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "SpecificVersions"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_SpecificVersions_Any(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-versions-any", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionSpecificVersionsAny(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "SpecificVersions"),
				),
			},
		},
	})
}

// License Tests
func TestAccCustomCurationCondition_BannedLicenses_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-banned-licenses", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionBannedLicenses(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "BannedLicenses"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_BannedLicenses_WithPermissiveApproach(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-banned-licenses-permissive", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionBannedLicensesPermissive(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "BannedLicenses"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_AllowedLicenses_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-allowed-licenses", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionAllowedLicenses(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "AllowedLicenses"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_AllowedLicenses_WithPermissiveApproach(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-allowed-licenses-permissive", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionAllowedLicensesPermissive(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "AllowedLicenses"),
				),
			},
		},
	})
}

// Custom Label Tests using Terraform resource-created labels
func TestAccCustomCurationCondition_BannedLabels_WithCustomLabels(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-banned-custom-labels", "xray_custom_curation_condition")
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create custom labels via Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)
	labelsRes := "xray_catalog_labels.labels_" + labelPrefix

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: labelsCfg + testAccCustomCurationConditionBannedLabelsCustom(name, labelNames, labelsRes),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "BannedLabels"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_AllowedLabels_WithCustomLabels(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-allowed-custom-labels", "xray_custom_curation_condition")
	labelPrefix := fmt.Sprintf("test%d", testutil.RandomInt())

	// Create custom labels via Terraform resource
	labelNames := computePolicyLabelNames(labelPrefix)
	labelsCfg := createCatalogLabelsConfig("labels_"+labelPrefix, labelPrefix)
	labelsRes := "xray_catalog_labels.labels_" + labelPrefix

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: labelsCfg + testAccCustomCurationConditionAllowedLabelsCustom(name, labelNames, labelsRes),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "AllowedLabels"),
				),
			},
		},
	})
}

// OpenSSF Tests (using underscore format to avoid inconsistent result errors)
func TestAccCustomCurationCondition_OpenSSF_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-openssf-basic", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionOpenSSFBasic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "OpenSSF"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_OpenSSF_MultipleChecks(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-openssf-multiple", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionOpenSSFMultiple(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "OpenSSF"),
				),
			},
		},
	})
}

// isImmature Tests
func TestAccCustomCurationCondition_isImmature_Basic(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-immature-basic", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionImmatureBasic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "isImmature"),
				),
			},
		},
	})
}

func TestAccCustomCurationCondition_isImmature_WithCVSSScore(t *testing.T) {
	_, fqrn, name := testutil.MkNames("test-immature-cvss", "xray_custom_curation_condition")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             acctest.VerifyDeleted(fqrn, "", acctest.CheckCurationCondition),
		Steps: []resource.TestStep{
			{
				Config: testAccCustomCurationConditionImmatureWithCVSS(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(fqrn, "name", name),
					resource.TestCheckResourceAttr(fqrn, "condition_template_id", "isImmature"),
				),
			},
		},
	})
}

// Test configuration functions

func testAccCustomCurationConditionCVEName(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVEName", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "CVEName"
  
  param_values = jsonencode([
    {
      param_id = "cve_name"
      value    = "CVE-2021-45105"
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionCVENameUpdated(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVENameUpdated", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}-updated"
  condition_template_id = "CVEName"
  
  param_values = jsonencode([
    {
      param_id = "cve_name"
      value    = "CVE-2025-25193"
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionCVECVSSRangeBasic(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVECVSSRangeBasic", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [9, 10]
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionCVECVSSRangeComplete(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVECVSSRangeComplete", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [0, 10]
    },
    {
      param_id = "apply_only_if_fix_is_available"
      value    = false
    },
    {
      param_id = "do_not_apply_for_already_existing_vulnerabilities"
      value    = true
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionCVECVSSRangeWithEPSSScore(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVECVSSRangeWithEPSSScore", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [7, 10]
    },
    {
      param_id = "apply_only_if_fix_is_available"
      value    = true
    },
    {
      param_id = "epss"
      value    = {
        score = 0.8
      }
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionCVECVSSRangeWithEPSSPercentile(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionCVECVSSRangeWithEPSSPercentile", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [8, 10]
    },
    {
      param_id = "do_not_apply_for_already_existing_vulnerabilities"
      value    = false
    },
    {
      param_id = "epss"
      value    = {
        percentile = 95.50
      }
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionSpecificVersionsEquals(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionSpecificVersionsEquals", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "npm"
    },
    {
      param_id = "package_name"
      value    = "lodash"
    },
    {
      param_id = "package_versions"
      value    = {
        equals = ["4.17.19", "4.17.20"]
      }
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionSpecificVersionsComparison(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionSpecificVersionsComparison", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "npm"
    },
    {
      param_id = "package_name"
      value    = "express"
    },
    {
      param_id = "package_versions"
      value    = {
        gte = ["4.18.0"]
        lte = ["4.16.0"]
      }
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionSpecificVersionsAny(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionSpecificVersionsAny", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "npm"
    },
    {
      param_id = "package_name"
      value    = "react"
    },
    {
      param_id = "package_versions"
      value    = {
        any = true
      }
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionBannedLicenses(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionBannedLicenses", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "BannedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["GPL-3.0", "AGPL-3.0", "LGPL-3.0"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = false
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionBannedLicensesPermissive(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionBannedLicensesPermissive", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "BannedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["GPL-2.0", "GPL-3.0"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = true
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionAllowedLicenses(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionAllowedLicenses", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "AllowedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["MIT", "Apache-2.0", "BSD-3-Clause"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = false
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionAllowedLicensesPermissive(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionAllowedLicensesPermissive", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "AllowedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["MIT", "Apache-2.0"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = true
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionOpenSSFBasic(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionOpenSSFBasic", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "OpenSSF"
  
  param_values = jsonencode([
    {
      param_id = "list_of_scorecard_checks"
      value    = {
        "code_review" = 5
        "maintained" = 3
      }
    },
    {
      param_id = "block_in_case_check_value_is_missing"
      value    = true
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionOpenSSFMultiple(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionOpenSSFMultiple", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "OpenSSF"
  
  param_values = jsonencode([
    {
      param_id = "list_of_scorecard_checks"
      value    = {
        "code_review" = 7
        "maintained" = 5
        "sast" = 8
        "vulnerabilities" = 9
        "license" = 6
      }
    },
    {
      param_id = "block_in_case_check_value_is_missing"
      value    = false
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionImmatureBasic(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionImmatureBasic", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "isImmature"
  
  param_values = jsonencode([
    {
      param_id = "package_age_days"
      value    = 30
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionImmatureWithCVSS(name string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionImmatureWithCVSS", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "isImmature"
  
  param_values = jsonencode([
    {
      param_id = "package_age_days"
      value    = 14
    },
    {
      param_id = "vulnerability_cvss_score"
      value    = 7.5
    }
  ])
}
`, map[string]interface{}{
		"name": name,
	})
}

func testAccCustomCurationConditionBannedLabelsCustom(name string, labelNames []string, labelsResource string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionBannedLabelsCustom", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "BannedLabels"
  
  param_values = jsonencode([
    {
      param_id = "list_of_labels"
      value    = [{{ range $index, $label := .labels }}{{ if $index }}, {{ end }}"{{ $label }}"{{ end }}]
    }
  ])
  depends_on = [{{ .labels_resource }}]
}
`, map[string]interface{}{
		"name":            name,
		"labels":          labelNames,
		"labels_resource": labelsResource,
	})
}

func testAccCustomCurationConditionAllowedLabelsCustom(name string, labelNames []string, labelsResource string) string {
	return util.ExecuteTemplate("TestAccCustomCurationConditionAllowedLabelsCustom", `
resource "xray_custom_curation_condition" "{{ .name }}" {
  name                 = "{{ .name }}"
  condition_template_id = "AllowedLabels"
  
  param_values = jsonencode([
    {
      param_id = "list_of_labels"
      value    = [{{ range $index, $label := .labels }}{{ if $index }}, {{ end }}"{{ $label }}"{{ end }}]
    }
  ])
  depends_on = [{{ .labels_resource }}]
}
`, map[string]interface{}{
		"name":            name,
		"labels":          labelNames,
		"labels_resource": labelsResource,
	})
}
