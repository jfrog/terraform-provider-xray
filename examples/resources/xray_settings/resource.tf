resource "xray_settings" "db_sync" {
  enabled                        = true
  allow_blocked                  = true
  allow_when_unavailable         = true
  block_unscanned_timeout        = 120
  block_unfinished_scans_timeout = 3600
  db_sync_updates_time           = "18:40"
}