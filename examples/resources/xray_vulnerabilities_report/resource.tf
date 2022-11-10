resource "xray_vulnerabilities_report" "report" {
  name = "test-vulnerabilities-report"

  resources {
    repository {
      name                  = "reponame"
      include_path_patterns = ["pattern1", "pattern2"]
      exclude_path_patterns = ["pattern2", "pattern2"]
    }

    repository {
      name                  = "reponame1"
      include_path_patterns = ["pattern1", "pattern2"]
      exclude_path_patterns = ["pattern1", "pattern2"]
    }
  }

  filters {
    vulnerable_component = "component-name"
    impacted_artifact    = "impacted-artifact"
    has_remediation      = false
    cve                  = "CVE-1234-1234"

    cvss_score {
      min_score = 6.3
      max_score = 9
    }

    published {
      start = "2020-06-29T12:22:16Z"
      end   = "2020-07-29T12:22:16Z"
    }

    scan_date {
      start = "2020-06-29T12:22:16Z"
      end   = "2020-07-29T12:22:16Z"
    }
  }
}