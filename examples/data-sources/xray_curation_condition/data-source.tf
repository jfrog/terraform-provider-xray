# Look up a built-in Curation condition by its exact name (case-sensitive), as
# shown in the Curation UI.
data "xray_curation_condition" "malicious_package" {
  name = "Malicious package"
}

# Use the resolved ID instead of hard-coding a numeric condition ID.
resource "xray_curation_policy" "block_malicious_packages" {
  name                  = "block-malicious-packages"
  condition_id          = data.xray_curation_condition.malicious_package.id
  scope                 = "all_repos"
  policy_action         = "block"
  waiver_request_config = "forbidden"
}

# Custom conditions can be looked up the same way, for example to reference a
# condition which is managed outside of this Terraform configuration.
data "xray_curation_condition" "immature_packages" {
  name = "my-immature-packages-condition"
}

output "immature_packages_condition_id" {
  value = data.xray_curation_condition.immature_packages.id
}
