resource "xray_custom_issue" "my-issue-1" {
    name          = "my-issue-1"
    description   = "My custom issue"
    summary       = "My issue"
    type          = "security"
    provider_name = "custom"
    package_type  = "generic"
    severity      = "High"

    component {
        id                  = "aero:aero"
        vulnerable_versions = ["[0.2.3]"]
        vulnerable_ranges {
            vulnerable_versions = ["[0.2.3]"]
        }
    }

    cve {
        cve     = "CVE-2017-1000386"
        cvss_v2 = "2.4"
    }

    source {
        id = "CVE-2017-1000386"
    }
}