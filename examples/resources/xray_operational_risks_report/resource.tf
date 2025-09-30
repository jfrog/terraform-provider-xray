# Example: Create an operational risks report for repositories
resource "xray_operational_risks_report" "repository-report" {
  name = "repository-operational-risks-report"
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
    component = "*log4j*"
    artifact  = "*spring*"
    risks     = ["High", "Medium", "Low"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an operational risks report for builds with patterns
resource "xray_operational_risks_report" "build-report" {
  name = "build-operational-risks-report"
  resources {
    builds {
      include_patterns         = ["build-*", "release-*"]
      exclude_patterns         = ["test-*", "dev-*"]
      number_of_latest_versions = 5
    }
  }
  filters {
    component = "*node*"
    artifact  = "*web-app*"
    risks     = ["Critical", "High"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an operational risks report for projects
resource "xray_operational_risks_report" "project-report" {
  name = "project-operational-risks-report"
  resources {
    projects {
      keys = ["project-1", "project-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    component = "*commons*"
    artifact  = "*utils*"
    risks     = ["None", "Low", "Medium", "High"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an operational risks report for release bundles
resource "xray_operational_risks_report" "release-bundle-report" {
  name = "release-bundle-operational-risks-report"
  resources {
    release_bundles {
      names                     = ["release-1", "release-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    component = "*maven*"
    artifact  = "*core*"
    risks     = ["Critical", "High", "Medium"]
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}