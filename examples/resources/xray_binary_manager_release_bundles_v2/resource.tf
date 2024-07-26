resource "xray_binary_manager_release_bundles_v2" "my-indexed-release-bundles" {
  id = "default"
  indexed_release_bundle_v2 = ["my-release-bundle-1", "my-release-bundle-2"]
}