resource "xray_ignore_rule" "ignore-rule-5649816" {
  notes           = "notes"
  cves            = ["fake-cves", "cves-1"]
  expiration_date = "2026-10-25"
}

resource "xray_ignore_rule" "ignore-rule-2195938" {
  notes           = "notes"
  expiration_date = "2026-10-19"
  vulnerabilities = ["any"]

  build {
    name    = "name"
    version = "version"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590577" {
  notes           = "notes"
  expiration_date = "2026-10-19"
  vulnerabilities = ["any"]

  component {
    name    = "name"
    version = "version"
  }
}

resource "xray_ignore_rule" "ignore-111" {
  notes            = "fake notes"
  expiration_date  = "2026-01-02"
  vulnerabilities  = ["any"]

  artifact {
    name    = "fake-name"
    version = "fake-version"
    path    = "invalid-path/"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590576" {
  notes           = "notes"
  expiration_date = "2026-04-05"
  cves = ["any"]
  vulnerabilities = ["any"]

	release_bundle {
		name    = "fake-name"
		version = "fake-version"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590577" {
  notes           = "notes"
  expiration_date = "2026-04-06"
  cves = ["any"]
  vulnerabilities = ["any"]

	release_bundles_v2 {
		name    = "releaseBundleV2://fake-name"
		version = "fake-version"
  }
}

resource "xray_ignore_rule" "ignore-rule-2590578" {
  notes           = "notes"
  expiration_date = "2026-04-06"

  exposures {
      scanners   = [ "EXP-123" ]
      categories = [ "secrets" , "applications" ]
      file_path  = ["/path/to/file"]
  }
}