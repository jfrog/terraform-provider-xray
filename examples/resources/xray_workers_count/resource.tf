resource "xray_workers_count" "workers-count" {
  index {
    new_content      = 4
    existing_content = 2
  }
  persist {
    new_content      = 4
    existing_content = 2
  }
  analysis {
    new_content      = 4
    existing_content = 2
  }
  policy_enforcer {
    new_content      = 4
    existing_content = 2
  }
  impact_analysis {
    new_content = 2
  }
  notification {
    new_content = 2
  }
  user_catalog {
    new_content      = 4
    existing_content = 2
  }
  sbom_impact_analysis {
    new_content      = 4
    existing_content = 2
  }
  migration_sbom {
    new_content      = 4
    existing_content = 2
  }
  sbom {
    new_content      = 4
    existing_content = 2
  } 
  panoramic {
    new_content      = 4
  }
  sbom_enricher {
    new_content      = 4
    existing_content = 2
  }
  sbom_dependencies {
    new_content      = 4
    existing_content = 2
  }
  sbom_deleter {
    new_content      = 4
    existing_content = 2
  }
}