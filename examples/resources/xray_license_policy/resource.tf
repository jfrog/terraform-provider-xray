resource "xray_license_policy" "license1" {
  name        = "test-license-policy-allowed"
  description = "License policy, allow certain licenses"
  type        = "license"
  rules {
    name     = "License_rule"
    priority = 1
    criteria {
      allowed_licenses         = ["Apache-1.0", "Apache-2.0"]
      allow_unknown            = false
      multi_license_permissive = true
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false   // set to true only if Jira integration is enabled
      custom_severity                    = "High"
      build_failure_grace_period_in_days = 5       // use only if fail_build is enabled

    }
  }
}

resource "xray_license_policy" "license2" {
  name        = "test-license-policy-banned"
  description = "License policy, block certain licenses"
  type        = "license"
  rules {
    name     = "License_rule"
    priority = 1
    criteria {
      banned_licenses          = ["Apache-3.0", "Apache-4.0"]
      allow_unknown            = false
      multi_license_permissive = false
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      custom_severity                    = "Medium"
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

    }
  }
}