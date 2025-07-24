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

# Valid curation policy with manual waiver requests
resource "xray_curation_policy" "example_manual" {
  name                  = "example-manual-policy"
  condition_id          = "3"
  scope                 = "all_repos"
  policy_action         = "block"
  waiver_request_config = "manual"
  decision_owners       = ["admin-group", "security-team"]

  waivers = [
    {
      pkg_type      = "npm"
      pkg_name      = "lodash"
      all_versions  = false
      pkg_versions  = ["4.17.20", "4.17.21"]  # Required when all_versions = false
      justification = "Required for legacy system compatibility"
    },
    {
      pkg_type      = "npm"
      pkg_name      = "moment"
      all_versions  = true  # When true, pkg_versions can be omitted
      justification = "Legacy dependency - all versions allowed"
    }
  ]

  label_waivers = [
    {
      label         = "high-risk"
      justification = "Approved by security team for specific use case"
    }
  ]

  notify_emails = ["security@company.com"]
}

# Valid policy with forbidden waiver requests
resource "xray_curation_policy" "example_forbidden" {
  name                  = "example-forbidden-policy"
  condition_id          = "3"
  scope                 = "pkg_types"
  pkg_types_include     = ["npm", "PyPI"]
  policy_action         = "block"
  waiver_request_config = "forbidden"
  # decision_owners not needed when waiver_request_config is "forbidden"
}

# Policy with auto-approved waiver requests
resource "xray_curation_policy" "example_auto_approved" {
  name                  = "auto-approved-policy"
  condition_id          = "5"
  scope                 = "all_repos"
  policy_action         = "block"
  waiver_request_config = "auto_approved"
  notify_emails         = ["devops@company.com", "security@company.com"]

  waivers = [
    {
      pkg_type      = "Maven"
      pkg_name      = "log4j-core"
      all_versions  = false
      pkg_versions  = ["2.17.0", "2.17.1", "2.17.2"]  # Only allow specific safe versions
      justification = "Approved safe versions after security review"
    },
    {
      pkg_type      = "Go"
      pkg_name      = "github.com/gin-gonic/gin"
      all_versions  = true
      justification = "Framework approved for all projects"
    }
  ]

  label_waivers = [
    {
      label         = "approved-internal"
      justification = "Internal packages pre-approved by security team"
    }
  ]
}

# Dry run policy for testing
resource "xray_curation_policy" "example_dry_run" {
  name          = "dry-run-test-policy"
  condition_id  = "7"
  scope         = "pkg_types"
  pkg_types_include = ["Docker", "Gems"]
  policy_action = "dry_run"  # Only logs, doesn't block
  notify_emails = ["audit@company.com"]
}

# Policy targeting specific repositories
resource "xray_curation_policy" "example_specific_repos" {
  name                  = "production-repos-policy"
  condition_id          = "4"
  scope                 = "specific_repos"
  repo_include          = ["prod-npm-local", "prod-maven-local", "prod-docker-local"]
  policy_action         = "block"
  waiver_request_config = "manual"
  decision_owners       = ["prod-security-team", "release-managers"]
  
  waivers = [
    {
      pkg_type      = "npm"
      pkg_name      = "express"
      pkg_versions  = ["4.18.0", "4.18.1", "4.18.2"]
      all_versions  = false
      justification = "Core framework - specific versions approved for production"
    },
    {
      pkg_type      = "Docker"
      pkg_name      = "alpine"
      all_versions  = true
      justification = "Base image approved for all production containers"
    }
  ]

  notify_emails = ["prod-alerts@company.com"]
}

# Policy with repo exclusions
resource "xray_curation_policy" "example_with_exclusions" {
  name                  = "company-wide-except-dev"
  condition_id          = "6"
  scope                 = "all_repos"
  repo_exclude          = ["dev-sandbox", "test-playground", "experimental-repo"]
  policy_action         = "block"
  waiver_request_config = "auto_approved"

  waivers = [
    {
      pkg_type      = "PyPI"
      pkg_name      = "requests"
      all_versions  = false
      pkg_versions  = ["2.28.0", "2.28.1", "2.28.2", "2.29.0"]
      justification = "HTTP library - approved versions only"
    },
    {
      pkg_type      = "NuGet"
      pkg_name      = "Newtonsoft.Json"
      all_versions  = true
      justification = "JSON library widely used across projects"
    }
  ]

  label_waivers = [
    {
      label         = "security-approved"
      justification = "Packages with security team approval"
    },
    {
      label         = "legacy-supported"
      justification = "Legacy packages still supported by vendor"
    }
  ]

  notify_emails = ["compliance@company.com"]
}

# Comprehensive policy with multiple package types
resource "xray_curation_policy" "example_comprehensive" {
  name                  = "multi-ecosystem-policy"
  condition_id          = "8"
  scope                 = "pkg_types"
  pkg_types_include     = ["npm", "PyPI", "Maven", "Go", "NuGet", "Docker"]
  policy_action         = "block"
  waiver_request_config = "manual"
  decision_owners       = ["architecture-council", "security-team"]

  waivers = [
    {
      pkg_type      = "npm"
      pkg_name      = "lodash"
      pkg_versions  = ["4.17.21"]
      all_versions  = false
      justification = "Utility library - only latest secure version allowed"
    },
    {
      pkg_type      = "PyPI"
      pkg_name      = "django"
      pkg_versions  = ["4.1.0", "4.2.0", "4.2.1"]
      all_versions  = false
      justification = "Web framework - LTS and recent versions only"
    },
    {
      pkg_type      = "Maven"
      pkg_name      = "springframework"
      all_versions  = true
      justification = "Enterprise framework - all versions pre-approved"
    },
    {
      pkg_type      = "Go"
      pkg_name      = "github.com/gorilla/mux"
      all_versions  = true
      justification = "Router library approved for all Go projects"
    },
    {
      pkg_type      = "Docker"
      pkg_name      = "nginx"
      pkg_versions  = ["1.20", "1.21", "1.22", "latest"]
      all_versions  = false
      justification = "Web server - approved stable versions and latest"
    }
  ]

  label_waivers = [
    {
      label         = "cncf-graduated"
      justification = "CNCF graduated projects are pre-approved"
    },
    {
      label         = "enterprise-support"
      justification = "Packages with enterprise support contracts"
    }
  ]

  notify_emails = ["architecture@company.com", "devsecops@company.com"]
}
