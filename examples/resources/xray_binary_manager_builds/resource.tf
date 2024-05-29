resource "xray_binary_manager_builds" "my-indexed-builds" {
  id = "default"
  indexed_builds = ["my-build-1", "my-build-2"]
}