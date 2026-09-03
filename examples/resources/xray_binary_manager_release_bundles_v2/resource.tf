# Default indexer (no project). Use this only for default-scope Release Bundles V2.
resource "xray_binary_manager_release_bundles_v2" "my-indexed-release-bundles" {
  id                        = "default"
  indexed_release_bundle_v2 = ["my-release-bundle-1", "my-release-bundle-2"]
}

# Release Bundle V2 names are unique per project. The same name in two projects
# requires a separate resource with project_key for each project.
resource "xray_binary_manager_release_bundles_v2" "project-a" {
  id                        = "default"
  project_key               = "project-a"
  indexed_release_bundle_v2 = ["my-release-bundle"]
}

resource "xray_binary_manager_release_bundles_v2" "project-b" {
  id                        = "default"
  project_key               = "project-b"
  indexed_release_bundle_v2 = ["my-release-bundle"]
}
