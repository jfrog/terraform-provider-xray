resource "xray_ignore_rule" "ignore-rule-5649816" {
  notes           = "notes"
  cves            = ["fake-cves", "cves-1"]
  expiration_date = "2023-10-25"
}

resource "xray_ignore_rule" "ignore-rule-2195938" {
  notes           = "notes"
  expiration_date = "2023-10-19"
  vulnerabilities = ["any"]

  build {
    name    = "name"
    version = "version"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590577" {
  notes           = "notes"
  expiration_date = "2023-10-19"
  vulnerabilities = ["any"]

  component {
    name    = "name"
    version = "version"
  }
}

resource "xray_ignore_rule" "ignore-111" {
  notes            = "fake notes"
  expiration_date  = "2024-01-02"
  vulnerabilities  = ["any"]

  artifact {
    name    = "fake-name"
    version = "fake-version"
    path    = "invalid-path/"
  }
}