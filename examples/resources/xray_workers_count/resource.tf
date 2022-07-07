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
  alert {
    new_content      = 4
    existing_content = 2
  }
  impact_analysis {
    new_content = 2
  }
  notification {
    new_content = 2
  }
}
