resource "xray_binary_manager_repos" "my-indexed-repos" {
  id = "default"
  indexed_repos = [
    {
      name = "my-generic-local"
      type = "local"
      package_type = "Generic"
    },
    {
      name = "my-npm-remote"
      type = "remote"
      package_type = "Npm"
    }
  ]
}