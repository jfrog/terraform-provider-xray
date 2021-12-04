resource "xray_security_policy" "security1" {
  name        = "test-security-policy-severity"
  description = "Security policy description"
  type        = "security"
  rules {
    name     = "rule-name-severity"
    priority = 1
    criteria {
      min_severity = "High"
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = true
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      build_failure_grace_period_in_days = 5     // use only if fail_build is enabled
    }
  }
}

resource "xray_security_policy" "security2" {
  name        = "test-security-policy-cvss"
  description = "Security policy description"
  type        = "security"
  rules {
    name     = "rule-name-cvss"
    priority = 1
    criteria {
      cvss_range {
        from = 1.5
        to   = 5.3
      }
    }
    actions {
      webhooks = []
      mails    = ["test@email.com"]
      block_download {
        unscanned = true
        active    = true
      }
      block_release_bundle_distribution  = true
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      build_failure_grace_period_in_days = 5     // use only if fail_build is enabled
    }
  }
}