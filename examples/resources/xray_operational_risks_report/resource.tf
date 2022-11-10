resource "xray_operational_risks_report" "report" {
  name = "test-operational-risks-report"

  resources {
    repository {
      name                  = "reponame"
      include_path_patterns = ["pattern1", "pattern2"]
      exclude_path_patterns = ["pattern2", "pattern2"]
    }

    repository {
      name                  = "reponame1"
      include_path_patterns = ["pattern1"]
      exclude_path_patterns = ["pattern3", "pattern4"]
    }
  }

  filters {
    component = "component-name"
    artifact  = "impacted-artifact"
    risks     = ["High", "Medium"]

    scan_date {
      start = "2020-06-29T12:22:16Z"
      end   = "2020-07-29T12:22:16Z"
    }
  }
}