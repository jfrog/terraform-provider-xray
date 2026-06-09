resource "xray_security_policy" "example" {
  name = "my-security-policy"
  type = "security"

  rule {
    name     = "min-severity-rule"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}

resource "xray_watch" "example" {
  name        = "my-watch"
  description = "My watch"
  active      = true

  watch_resource {
    type = "all-repos"
  }

  # Note: no `assigned_policy` block here - policies are attached via
  # xray_watch_policy_attachment below so they can be detached independently.
}

resource "xray_watch_policy_attachment" "example" {
  watch_name  = xray_watch.example.name
  policy_name = xray_security_policy.example.name
  policy_type = "security"
}
