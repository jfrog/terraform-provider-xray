resource "xray_watch" "all-repos" {
  name        = "all-repos-watch"
  description = "Watch for all repositories, matching the filter"
  active      = true
  project_key = "testproj"

  watch_resource {
    type = "all-repos"

    filter {
      type  = "regex"
      value = ".*"
    }
  }

  assigned_policy {
    name = xray_security_policy.allowed_licenses.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.banned_licenses.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "repository" {
  name        = "repository-watch"
  description = "Watch a single repo or a list of repositories"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-repository-name"
    repo_type  = "local"

    filter {
      type  = "regex"
      value = ".*"
    }
  }

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-other-repository-name"
    repo_type  = "remote"

    filter {
      type  = "regex"
      value = ".*"
    }
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "repository-ant-filter" {
  name        = "repository-watch"
  description = "Watch a single repo or a list of repositories, using ant pattern"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-repository-name"
    repo_type  = "local"

    path_ant_filter {
      exclude_patterns = ["**/*.md"]
      include_patterns = ["**/*.js"]
    }
  }

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-repository-name1"
    repo_type  = "local"

    path_ant_filter {
      exclude_patterns = ["**/*.md"]
    }
  }

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-other-repository-name"
    repo_type  = "remote"

    filter {
      type  = "regex"
      value = ".*"
    }
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "all-builds-with-filters" {
  name        = "build-watch"
  description = "Watch all builds with Ant patterns filter"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "all-builds"
    bin_mgr_id = "default"

    ant_filter {
      exclude_patterns = ["a*", "b*"]
      include_patterns = ["ab*"]
    }
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "build" {
  name        = "build-watch"
  description = "Watch a single build or a list of builds"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "build"
    bin_mgr_id = "default"
    name       = "your-build-name"
  }

  watch_resource {
    type       = "build"
    bin_mgr_id = "default"
    name       = "your-other-build-name"
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "all-projects" {
  name        = "projects-watch"
  description = "Watch all the projects"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "all-projects"
    bin_mgr_id = "default"
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "all-projects-with-filters" {
  name        = "projects-watch"
  description = "Watch all the projects with Ant patterns filter"
  active      = true
  project_key = "testproj"

  watch_resource {
    type       = "all-projects"
    bin_mgr_id = "default"

    ant_filter {
      exclude_patterns = ["a*", "b*"]
      include_patterns = ["ab*"]
    }
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "project" {
  name        = "project-watch"
  description = "Watch selected projects"
  active      = true
  project_key = "testproj"

  watch_resource {
    type = "project"
    name = "test"
  }
  watch_resource {
    type = "project"
    name = "test1"
  }

  assigned_policy {
    name = xray_security_policy.min_severity.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.cvss_range.name
    type = "license"
  }

  assigned_policy {
    name = xray_operational_risk_policy.op_risk.name
    type = "operational_risk"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}
