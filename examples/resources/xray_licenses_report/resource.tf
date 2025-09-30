# Example: Create a licenses report for repositories
resource "xray_licenses_report" "repository-report" {
  name = "repository-licenses-report"
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
    component    = "*log4j*"
    artifact     = "*spring*"
    unknown      = true
    license_names = ["Apache-2.0", "MIT"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create a licenses report for builds with patterns
resource "xray_licenses_report" "build-report" {
  name = "build-licenses-report"
  resources {
    builds {
      include_patterns         = ["build-*", "release-*"]
      exclude_patterns         = ["test-*", "dev-*"]
      number_of_latest_versions = 5
    }
  }
  filters {
    component       = "*node*"
    artifact        = "*web-app*"
    unknown         = false
    unrecognized    = false
    license_patterns = ["*GPL*", "*MIT*"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create a licenses report for projects
resource "xray_licenses_report" "project-report" {
  name = "project-licenses-report"
  resources {
    projects {
      keys = ["project-1", "project-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    component    = "*commons*"
    artifact     = "*utils*"
    unknown      = true
    unrecognized = true
    license_names = ["BSD-3-Clause", "LGPL-2.1"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}