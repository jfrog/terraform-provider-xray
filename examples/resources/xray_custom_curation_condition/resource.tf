terraform {
  required_providers {
    xray = {
      source  = "jfrog/xray"
      version = "~> 3.0"
    }
  }
}

provider "xray" {
  url          = "https://your-instance.jfrog.io"
  access_token = "your-access-token"
}

# ============================================================================
# CVEName - Block specific CVE vulnerabilities
# ============================================================================
resource "xray_custom_curation_condition" "cve_name_condition" {
  name                 = "block-log4j-cve"
  condition_template_id = "CVEName"
  
  param_values = jsonencode([
    {
      param_id = "cve_name"
      value    = "CVE-2021-45105"
    }
  ])
}

# ============================================================================
# CVECVSSRange - Block vulnerabilities based on CVSS score range and EPSS
# ============================================================================
resource "xray_custom_curation_condition" "cvss_range_condition" {
  name                 = "high-severity-vulnerabilities"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [7.0, 10.0]  # High and Critical severity
    },
    {
      param_id = "apply_only_if_fix_is_available"
      value    = true
    },
    {
      param_id = "do_not_apply_for_already_existing_vulnerabilities"
      value    = false
    },
    {
      param_id = "epss"
      value    = {
        percentile = 90.0  # High exploitation probability
      }
    }
  ])
}

# CVECVSSRange with EPSS score instead of percentile
resource "xray_custom_curation_condition" "cvss_range_epss_score" {
  name                 = "critical-exploitable-vulnerabilities"
  condition_template_id = "CVECVSSRange"
  
  param_values = jsonencode([
    {
      param_id = "vulnerability_cvss_score_range"
      value    = [9.0, 10.0]  # Critical severity only
    },
    {
      param_id = "epss"
      value    = {
        score = 0.8  # High exploitation score (0.0-1.0)
      }
    }
  ])
}

# CVECVSSRange with default values (empty param_values)
resource "xray_custom_curation_condition" "cvss_range_defaults" {
  name                 = "default-vulnerability-blocking"
  condition_template_id = "CVECVSSRange"
  
  # Uses defaults: vulnerability_cvss_score_range=[0,10], apply_only_if_fix_is_available=false, 
  # do_not_apply_for_already_existing_vulnerabilities=true
  param_values = jsonencode([])
}

# ============================================================================
# SpecificVersions - Block or allow specific package versions
# ============================================================================

# SpecificVersions with equals operator (exact version matches)
resource "xray_custom_curation_condition" "specific_versions_equals" {
  name                 = "block-vulnerable-log4j-versions"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "Maven"
    },
    {
      param_id = "package_name"
      value    = "log4j-core"
    },
    {
      param_id = "package_versions"
      value    = {
        equals = ["2.14.0", "2.15.0", "2.16.0"]  # Exact vulnerable versions
      }
    }
  ])
}

# SpecificVersions with comparison operators
resource "xray_custom_curation_condition" "specific_versions_comparison" {
  name                 = "block-outdated-lodash"
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
        lte = ["4.17.20"]    # Less than or equal to 4.17.20
        gte = ["5.0.0"]      # Greater than or equal to 5.0.0
        lt  = ["3.0.0"]      # Less than 3.0.0
        gt  = ["6.0.0"]      # Greater than 6.0.0
      }
    }
  ])
}

# SpecificVersions with ranges
resource "xray_custom_curation_condition" "specific_versions_ranges" {
  name                 = "block-vulnerable-requests-ranges"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "PyPI"
    },
    {
      param_id = "package_name"
      value    = "requests"
    },
    {
      param_id = "package_versions"
      value    = {
        ranges = [
          {"gte" = "2.0.0", "lte" = "2.19.0"},  # Range 2.0.0 to 2.19.0
          {"gt" = "2.25.0", "lt" = "2.27.0"}    # Range 2.25.0 to 2.27.0 (exclusive)
        ]
      }
    }
  ])
}

# SpecificVersions with combined operators
resource "xray_custom_curation_condition" "specific_versions_combined" {
  name                 = "comprehensive-version-blocking"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "Go"
    },
    {
      param_id = "package_name"
      value    = "github.com/gin-gonic/gin"
    },
    {
      param_id = "package_versions"
      value    = {
        equals = ["1.7.4", "1.7.3"]              # Exact versions
        gte    = ["1.8.0"]                       # Greater than or equal
        lte    = ["1.6.0"]                       # Less than or equal
        ranges = [
          {"gte" = "1.5.0", "lte" = "1.6.9"}    # Range constraint
        ]
      }
    }
  ])
}

# SpecificVersions with any operator (allow all versions)
resource "xray_custom_curation_condition" "specific_versions_any" {
  name                 = "allow-all-newtonsoft-versions"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "NuGet"
    },
    {
      param_id = "package_name"
      value    = "Newtonsoft.Json"
    },
    {
      param_id = "package_versions"
      value    = {
        any = true  # Allow all versions
      }
    }
  ])
}

# SpecificVersions with default behavior (package_versions omitted)
resource "xray_custom_curation_condition" "specific_versions_default" {
  name                 = "default-boost-behavior"
  condition_template_id = "SpecificVersions"
  
  param_values = jsonencode([
    {
      param_id = "package_type"
      value    = "Conan"
    },
    {
      param_id = "package_name"
      value    = "boost"
    }
    # package_versions omitted - defaults to {"any": true}
  ])
}

# ============================================================================
# License-based conditions
# ============================================================================

# BannedLicenses - Block packages with prohibited licenses
resource "xray_custom_curation_condition" "banned_licenses_condition" {
  name                 = "block-copyleft-licenses"
  condition_template_id = "BannedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["GPL-3.0", "AGPL-3.0", "LGPL-3.0", "GPL-2.0"]
    }
  ])
}

# BannedLicenses with permissive approach
resource "xray_custom_curation_condition" "banned_licenses_permissive" {
  name                 = "block-gpl-licenses-permissive"
  condition_template_id = "BannedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["GPL-2.0", "GPL-3.0"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = true  # Allow if package has other non-banned licenses
    }
  ])
}

# AllowedLicenses - Only allow packages with approved licenses
resource "xray_custom_curation_condition" "allowed_licenses_condition" {
  name                 = "allow-permissive-licenses-only"
  condition_template_id = "AllowedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
    }
  ])
}

# AllowedLicenses with strict approach
resource "xray_custom_curation_condition" "allowed_licenses_strict" {
  name                 = "strict-license-allowlist"
  condition_template_id = "AllowedLicenses"
  
  param_values = jsonencode([
    {
      param_id = "list_of_package_licenses"
      value    = ["MIT", "Apache-2.0"]
    },
    {
      param_id = "multiple_license_permissive_approach"
      value    = false  # Package must have ONLY allowed licenses
    }
  ])
}

# ============================================================================
# Label-based conditions
# ============================================================================

# BannedLabels - Block packages with specific security labels
resource "xray_custom_curation_condition" "banned_labels_condition" {
  name                 = "block-malicious-packages"
  condition_template_id = "BannedLabels"
  
  param_values = jsonencode([
    {
      param_id = "list_of_labels"
      value    = ["malware", "suspicious", "deprecated", "compromised"]
    }
  ])
}

# AllowedLabels - Only allow packages with approved labels  
resource "xray_custom_curation_condition" "allowed_labels_condition" {
  name                 = "allow-verified-packages-only"
  condition_template_id = "AllowedLabels"
  
  param_values = jsonencode([
    {
      param_id = "list_of_labels"
      value    = ["approved", "secure", "verified", "trusted"]
    }
  ])
}

# ============================================================================
# OpenSSF Scorecard conditions
# ============================================================================

# OpenSSF with basic scorecard checks
resource "xray_custom_curation_condition" "openssf_basic" {
  name                 = "basic-security-scorecard"
  condition_template_id = "OpenSSF"
  
  param_values = jsonencode([
    {
      param_id = "list_of_scorecard_checks"
      value    = {
        "Code-Review" = 5    # Minimum score of 5 for code review
        "Maintained" = 3     # Minimum score of 3 for maintenance
      }
    },
    {
      param_id = "block_in_case_check_value_is_missing"
      value    = true
    }
  ])
}

# OpenSSF with comprehensive security checks
resource "xray_custom_curation_condition" "openssf_comprehensive" {
  name                 = "comprehensive-security-scorecard"
  condition_template_id = "OpenSSF"
  
  param_values = jsonencode([
    {
      param_id = "list_of_scorecard_checks"
      value    = {
        "Code-Review"        = 7
        "Maintained"         = 5
        "SAST"              = 8
        "Vulnerabilities"   = 9
        "License"           = 6
        "Security-Policy"   = 7
        "Branch-Protection" = 6
        "Binary-Artifacts"  = 9
      }
    },
    {
      param_id = "block_in_case_check_value_is_missing"
      value    = false  # Don't block if check data is missing
    }
  ])
}

# OpenSSF with user-friendly names (underscore format)
resource "xray_custom_curation_condition" "openssf_friendly_names" {
  name                 = "user-friendly-scorecard"
  condition_template_id = "OpenSSF"
  
  param_values = jsonencode([
    {
      param_id = "list_of_scorecard_checks"
      value    = {
        "code_review"       = 7
        "maintained"        = 5
        "security_policy"   = 8
        "branch_protection" = 6
        "binary_artifacts"  = 9
        "vulnerabilities"   = 8
      }
    },
    {
      param_id = "block_in_case_check_value_is_missing"
      value    = true
    }
  ])
}

# ============================================================================
# Package maturity conditions
# ============================================================================

# isImmature - Block packages that are too new
resource "xray_custom_curation_condition" "immature_packages_basic" {
  name                 = "block-new-packages"
  condition_template_id = "isImmature"
  
  param_values = jsonencode([
    {
      param_id = "package_age_days"
      value    = 30  # Block packages newer than 30 days
    }
  ])
}

# isImmature with CVSS score threshold
resource "xray_custom_curation_condition" "immature_packages_with_cvss" {
  name                 = "block-new-vulnerable-packages"
  condition_template_id = "isImmature"
  
  param_values = jsonencode([
    {
      param_id = "package_age_days"
      value    = 14  # Block packages newer than 14 days
    },
    {
      param_id = "vulnerability_cvss_score"
      value    = 7.5  # If package has vulnerabilities with CVSS >= 7.5
    }
  ])
}