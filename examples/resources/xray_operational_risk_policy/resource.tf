resource "xray_operational_risk_policy" "min_risk" {
  name        = "test-operational-risk-policy-min-risk"
  description = "Operational Risk policy with a custom risk rule"
  type        = "Operational_Risk"
  project_key = "testproj"

  rule {
    name     = "op_risk_custom_rule"
    priority = 1

    criteria {
			op_risk_min_risk = "Medium"
		}

    actions {
      webhooks                           = []
      mails                              = ["test@email.com"]
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}

resource "xray_operational_risk_policy" "custom_criteria" {
  name        = "test-operational-risk-policy-custom-criteria"
  description = "Operational Risk policy with a custom risk rule"
  type        = "Operational_Risk"
  project_key = "testproj"

  rule {
    name     = "op_risk_custom_rule"
    priority = 1

    criteria {
			op_risk_custom {
        use_and_condition                  = true
        is_eol                             = false
        release_date_greater_than_months   = 6
        newer_versions_greater_than        = 1
        release_cadence_per_year_less_than = 1
        commits_less_than                  = 10
        committers_less_than               = 1
        risk                               = "medium"
      }
		}

    actions {
      webhooks                           = []
      mails                              = ["test@email.com"]
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}
