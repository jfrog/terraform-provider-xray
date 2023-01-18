resource "xray_ignore_rule" "ignore-rule-5649816" {
  notes           = "notes"
  cves            = ["fake-cves", "cves-1"]
  expiration_date = "2023-01-25"
}

resource "xray_ignore_rule" "ignore-rule-2195938" {
  notes           = "notes"
  expiration_date = "2023-01-19"
  vulnerabilities = ["any"]

  build {
    name    = "name"
    version = "version"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590577" {
  notes           = "notes"
  expiration_date = "2023-01-19"
  vulnerabilities = ["any"]

  component {
    name    = "name"
    version = "version"
  }
}