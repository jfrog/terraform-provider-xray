# Example: Create a vulnerabilities report for repositories with CVE
resource "xray_vulnerabilities_report" "repository-report" {
  name = "repository-vulnerabilities-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "30 09 * * MON"
  cron_schedule_timezone = "America/New_York"
  emails                 = ["security-team@example.com", "devops@example.com"]
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
    vulnerable_component = "*log4j*"
    impacted_artifact   = "*spring*"
    has_remediation     = true
    cve                = "CVE-2021-44228"
    cvss_score {
      min_score = 7.0
      max_score = 10.0
    }
    published {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }

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
  }
}

# Example: Create a vulnerabilities report for builds with patterns
resource "xray_vulnerabilities_report" "build-report" {
  name = "build-vulnerabilities-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "00 23 * * SUN"
  cron_schedule_timezone = "Europe/London"
  emails                 = ["build-team@example.com", "ci-cd@example.com"]
  resources {
    builds {
      include_patterns         = ["build-*", "release-*"]
      exclude_patterns         = ["test-*", "dev-*"]
      number_of_latest_versions = 5
    }
  }
  filters {
    vulnerable_component = "*node*"
    impacted_artifact   = "*web-app*"
    has_remediation     = false
    issue_id           = "XRAY-87343"
    severities         = ["High", "Medium"]
    published {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }

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
  }
}

# Example: Create a vulnerabilities report for projects
resource "xray_vulnerabilities_report" "project-report" {
  name = "project-vulnerabilities-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "15 06 * * *"
  cron_schedule_timezone = "Asia/Tokyo"
  emails                 = ["project-team@example.com", "managers@example.com"]
  resources {
    projects {
      keys = ["project-1", "project-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    vulnerable_component = "*commons*"
    impacted_artifact   = "*utils*"
    has_remediation     = true
    severities         = ["Critical", "High", "Medium"]
    published {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }

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
  }
}

# Example: Create a vulnerabilities report for release bundles
resource "xray_vulnerabilities_report" "release-bundle-report" {
  name = "release-bundle-vulnerabilities-report"

  # Automated report generation (requires Xray 3.130.0 or higher)
  cron_schedule          = "45 12 * * FRI"
  cron_schedule_timezone = "UTC"
  emails                 = ["release-team@example.com", "qa@example.com"]
  resources {
    release_bundles {
      names                     = ["release-1", "release-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    vulnerable_component = "*maven*"
    impacted_artifact   = "*core*"
    has_remediation     = true
    cvss_score {
      min_score = 8.0
      max_score = 10.0
    }
    published {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }

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
  }
}