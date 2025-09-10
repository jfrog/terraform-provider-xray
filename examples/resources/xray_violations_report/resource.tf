# Example: Create a security violations report for repositories
resource "xray_violations_report" "security-report" {
  name = "security-violations-report"
  resources {
    repository {
      name                  = "docker-local"
      include_path_patterns = ["folder1/path/*", "folder2/path*"]
      exclude_path_patterns = ["folder1/path2/*", "folder2/path2*"]
    }
    repository {
      name                  = "libs-release-local"
      include_path_patterns = ["**/*.jar", "**/*.war"]
    }
  }
  filters {
    type             = "security"
    watch_names      = ["security-watch"]
    policy_names     = ["security-policy"]
    component        = "*log4j*"
    artifact         = "*spring*"
    violation_status = "Active"
    severities       = ["Critical", "High"]

    security_filters {
      issue_id         = "XRAY-87343"
      summary_contains = "remote code execution"
      has_remediation  = true
      cvss_score {
        min_score = 7.0
        max_score = 10.0
      }
      published {
        start = "2023-01-01T00:00:00Z"
        end   = "2023-12-31T23:59:59Z"
      }
    }

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create a license violations report for builds
resource "xray_violations_report" "license-report" {
  name = "license-violations-report"
  resources {
    builds {
      names                     = ["build-1", "build-2"]
      number_of_latest_versions = 5
    }
  }
  filters {
    type             = "license"
    watch_patterns   = ["license-watch-*"]
    policy_names     = ["license-policy"]
    component        = "*commons*"
    artifact         = "*utils*"
    violation_status = "Active"
    severities       = ["High"]

    license_filters {
      unknown         = true
      license_names   = ["GPL-2.0", "AGPL-3.0"]
      license_patterns = ["*GPL*"]
    }

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an operational risk violations report for projects
resource "xray_violations_report" "operational-risk-report" {
  name = "operational-risk-violations-report"
  resources {
    projects {
      names                     = ["project-1", "project-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    type             = "operational_risk"
    watch_names      = ["ops-risk-watch"]
    policy_names     = ["ops-risk-policy"]
    component        = "*node*"
    artifact         = "*web-app*"
    violation_status = "Active"
    severities       = ["Critical", "High", "Medium"]

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}