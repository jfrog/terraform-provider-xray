# Example: Create an exposures report for repositories with secrets category
resource "xray_exposures_report" "secrets-report" {
  name = "secrets-exposure-report"
  resources {
    repository {
      name = "docker-local"
      include_path_patterns = ["folder1/path/*", "folder2/path*"]
      exclude_path_patterns = ["folder1/path2/*", "folder2/path2*"]
    }
    repository {
      name = "libs-release-local"
      include_path_patterns = ["**/*.jar", "**/*.war"]
    }
  }
  filters {
    category          = "secrets"
    impacted_artifact = "*spring*"
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an exposures report for builds with services category
resource "xray_exposures_report" "services-report" {
  name = "services-exposure-report"
  resources {
    builds {
      names = ["build-1", "build-2"]
      number_of_latest_versions = 5
    }
  }
  filters {
    category          = "services"
    impacted_artifact = "*nginx*"
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an exposures report for projects with applications category
resource "xray_exposures_report" "applications-report" {
  name = "applications-exposure-report"
  resources {
    projects {
      keys = ["test-project-1", "test-project-2"]
      number_of_latest_versions = 3
    }
  }
  filters {
    category          = "applications"
    impacted_artifact = "*web-app*"
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}

# Example: Create an exposures report for release bundles with IaC category
resource "xray_exposures_report" "iac-report" {
  name = "iac-exposure-report"
  resources {
    release_bundles {
      names = ["release-1", "release-2"]
      number_of_latest_versions = 2
    }
  }
  filters {
    category          = "iac"
    impacted_artifact = "*terraform*"
    scan_date {
      start = "2023-01-01T00:00:00Z"
      end   = "2023-12-31T23:59:59Z"
    }
  }
}
