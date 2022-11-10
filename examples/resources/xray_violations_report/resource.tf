resource "xray_violations_report" "report" {
  name = "test-violations-report"

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
    type           = "security"
    watch_names    = ["NameOfWatch1", "NameOfWatch2"]
    watch_patterns = ["WildcardWatch*", "WildcardWatch1*"]
    component      = "*vulnerable:component*"
    artifact       = "some://impacted*artifact"
    policy_names   = ["policy1", "policy2"]
    severities     = ["High", "Medium"]

    updated {
      start = "2020-06-29T12:22:16Z"
      end   = "2020-07-29T12:22:16Z"
    }

    security_filters {
      issue_id = "XRAY-87343"
      summary_contains = "kernel"
      has_remediation  = true

      cvss_score {
        min_score = 6.3
        max_score = 9
      }
    }

    license_filters {
      unknown       = false
      unrecognized  = true
      license_names = ["Apache", "MIT"]
    }
  }
}