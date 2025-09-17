# Example: Create a security violations report for repositories with all features
resource "xray_violations_report" "security-report" {
  name = "security-violations-report"
  
  cron_schedule          = "30 09 * * MON" # requires Xray 3.130.0 or higher
  cron_schedule_timezone = "America/New_York" # requires Xray 3.130.0 or higher
  emails                 = ["security-team@example.com", "devops@example.com"] # requires Xray 3.130.0 or higher

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
    severities       = ["Critical", "High", "Medium"]

    # Contextual Analysis Filter (requires Xray 3.130.0 or higher)
    ca_filter {
      allowed_ca_statuses = [
        "applicable",
        "not_applicable",
        "undetermined",
        "not_scanned"
      ]
    }

    # Runtime Filter (requires Xray 3.130.0 or higher)
    runtime_filter {
      time_period = "7 days"
    }

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

# Example: Create a license violations report for builds with scheduled reporting
resource "xray_violations_report" "license-report" {
  name = "license-violations-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "00 23 * * SUN" # requires Xray 3.130.0 or higher
  cron_schedule_timezone = "Europe/London" # requires Xray 3.130.0 or higher
  emails                 = ["legal-team@example.com", "compliance@example.com"] # requires Xray 3.130.0 or higher

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

    # Contextual Analysis Filter (requires Xray 3.130.0 or higher)
    ca_filter {
      allowed_ca_statuses = [
        "applicable",
        "technology_unsupported",
        "upgrade_required"
      ]
    }

    # Runtime Filter (requires Xray 3.130.0 or higher)
    runtime_filter {
      time_period = "30 days"
    }

    license_filters {
      unknown          = true
      license_names    = ["GPL-2.0", "AGPL-3.0"]
    }

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an operational risk violations report for projects with daily updates
resource "xray_violations_report" "operational-risk-report" {
  name = "operational-risk-violations-report"

  # Automated report generation
  cron_schedule          = "15 06 * * *" # requires Xray 3.130.0 or higher
  cron_schedule_timezone = "Asia/Tokyo" # requires Xray 3.130.0 or higher
  emails                 = ["ops-team@example.com", "risk-management@example.com"] # requires Xray 3.130.0 or higher

  resources {
    projects {
      keys = ["project-1", "project-2"]
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

    # Contextual Analysis Filter (requires Xray 3.130.0 or higher)
    ca_filter {
      allowed_ca_statuses = [
        "applicable",
        "rescan_required",
        "not_covered"
      ]
    }

    # Runtime Filter (requires Xray 3.130.0 or higher)
    runtime_filter {
      time_period = "24 hours"
    }

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create a malicious violations report for release bundles with weekly schedule
resource "xray_violations_report" "malicious-report" {
  name = "malicious-violations-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "45 12 * * FRI"
  cron_schedule_timezone = "UTC"
  emails                 = ["security-alerts@example.com"]

  resources {
    release_bundles {
      names                     = ["release-1", "release-2"]
      number_of_latest_versions = 2
    }
  }

  filters {
    type             = "malicious"
    watch_names      = ["malware-watch"]
    policy_names     = ["malware-policy"]
    component        = "*npm*"
    artifact         = "*package*"
    violation_status = "Active"
    severities       = ["Critical"]

    # Contextual Analysis Filter (requires Xray 3.130.0 or higher)
    ca_filter {
      allowed_ca_statuses = [
        "applicable",
        "not_scanned",
        "undetermined"
      ]
    }

    # Runtime Filter (requires Xray 3.130.0 or higher)
    runtime_filter {
      time_period = "3 days"
    }

    updated {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}