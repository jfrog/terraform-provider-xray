resource "xray_repository_config" "xray-repo-config-pattern" {
  repo_name = "example-repo-local"

  paths_config {
    pattern {
      include             = "core/**"
      exclude             = "core/internal/**"
      index_new_artifacts = true
      retention_in_days   = 60
    }

    pattern {
      include             = "core/**"
      exclude             = "core/external/**"
      index_new_artifacts = true
      retention_in_days   = 45
    }

    all_other_artifacts {
      index_new_artifacts = true
      retention_in_days   = 60
    }
  }
}

resource "xray_repository_config" "xray-repo-config" {
  repo_name = "example-repo-local"

  config {
    vuln_contextual_analysis = true
    retention_in_days        = 90
  }
}