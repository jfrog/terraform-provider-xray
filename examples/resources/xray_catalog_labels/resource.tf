resource "xray_catalog_labels" "basic" {
  labels = [
    { name = "lbl_basic_1", description = "Basic label 1" },
    { name = "lbl_basic_2", description = "Basic label 2" }
  ]
}

resource "xray_catalog_labels" "with_package_assignments" {
  labels = [
    { name = "pkg_label", description = "Label for packages" }
  ]

  package_assignments = [
    { label_name = "pkg_label", package_name = "express", package_type = "npm" },
    { label_name = "pkg_label", package_name = "lodash",  package_type = "npm" }
  ]
}

resource "xray_catalog_labels" "with_version_assignments_single" {
  labels = [
    { name = "ver_label_one", description = "Label for a single package version" }
  ]

  version_assignments = [
    { label_name = "ver_label_one", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}

resource "xray_catalog_labels" "with_version_assignments_bulk" {
  labels = [
    { name = "ver_label_bulk", description = "Label for multiple package versions" }
  ]

  version_assignments = [
    { label_name = "ver_label_bulk", package_name = "express", package_type = "npm", versions = ["4.17.0", "4.18.2"] }
  ]
}

resource "xray_catalog_labels" "combined" {
  labels = [
    { name = "combined_lbl", description = "Label used in both package and version assignments" },
    { name = "doc_label",     description = "Another label to demonstrate multiple labels" }
  ]

  package_assignments = [
    { label_name = "combined_lbl", package_name = "express", package_type = "npm" }
  ]

  version_assignments = [
    { label_name = "combined_lbl", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
} 