data "xray_artifacts_scan" "my_artifacts_scan" {
  repo = "my-docker-local"
  order_by = "repo_path"
  offset = 15
}

output "my_artifacts_scan" {
  value = data.xray_artifacts_scan.my_artifacts_scan.results
}