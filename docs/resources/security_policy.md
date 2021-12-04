---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "xray_security_policy Resource - terraform-provider-xray"
subcategory: ""
description: |-
  Creates an xray policy using V2 of the underlying APIs. Please note: It's only compatible with Bearer token auth method (Identity and Access => Access Tokens
---

# xray_security_policy (Resource)

Creates an xray policy using V2 of the underlying APIs. Please note: It's only compatible with Bearer token auth method (Identity and Access => Access Tokens

## Example Usage

```terraform
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
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **name** (String) Name of the policy (must be unique)
- **rules** (Block List, Min: 1) (see [below for nested schema](#nestedblock--rules))
- **type** (String) Type of the policy

### Optional

- **description** (String) More verbose description of the policy
- **id** (String) The ID of this resource.

### Read-Only

- **author** (String) User, who created the policy
- **created** (String) Creation timestamp
- **modified** (String) Modification timestamp

<a id="nestedblock--rules"></a>
### Nested Schema for `rules`

Required:

- **criteria** (Block List, Min: 1, Max: 1) Nested block describing the criteria for the policy. Described below. (see [below for nested schema](#nestedblock--rules--criteria))
- **name** (String) Name of the rule
- **priority** (Number) Integer describing the rule priority

Optional:

- **actions** (Block List, Max: 1) Nested block describing the actions to be applied by the policy. Described below. (see [below for nested schema](#nestedblock--rules--actions))

<a id="nestedblock--rules--criteria"></a>
### Nested Schema for `rules.criteria`

Optional:

- **cvss_range** (Block List, Max: 1) Nested block describing a CVS score range to be impacted. Defined below. (see [below for nested schema](#nestedblock--rules--criteria--cvss_range))
- **min_severity** (String) The minimum security vulnerability severity that will be impacted by the policy.

<a id="nestedblock--rules--criteria--cvss_range"></a>
### Nested Schema for `rules.criteria.cvss_range`

Required:

- **from** (Number) The beginning of the range of CVS scores (from 1-10, float) to flag.
- **to** (Number) The end of the range of CVS scores (from 1-10, float) to flag.



<a id="nestedblock--rules--actions"></a>
### Nested Schema for `rules.actions`

Required:

- **block_download** (Block List, Min: 1, Max: 1) Nested block describing artifacts that should be blocked for download if a violation is triggered. Described below. (see [below for nested schema](#nestedblock--rules--actions--block_download))

Optional:

- **block_release_bundle_distribution** (Boolean) Blocks Release Bundle distribution to Edge nodes if a violation is found.
- **build_failure_grace_period_in_days** (Number) Allow grace period for certain number of days. All violations will be ignored during this time. To be used only if `fail_build` is enabled.
- **create_ticket_enabled** (Boolean) Create Jira Ticket for this Policy Violation. Requires configured Jira integration.
- **fail_build** (Boolean) Whether or not the related CI build should be marked as failed if a violation is triggered. This option is only available when the policy is applied to an `xray_watch` resource with a `type` of `builds`.
- **mails** (List of String) A list of email addressed that will get emailed when a violation is triggered.
- **notify_deployer** (Boolean) Sends an email message to component deployer with details about the generated Violations.
- **notify_watch_recipients** (Boolean) Sends an email message to all configured recipients inside a specific watch with details about the generated Violations.
- **webhooks** (List of String) A list of Xray-configured webhook URLs to be invoked if a violation is triggered.

<a id="nestedblock--rules--actions--block_download"></a>
### Nested Schema for `rules.actions.block_download`

Required:

- **active** (Boolean) Whether or not to block download of artifacts that meet the artifact and severity `filters` for the associated `xray_watch` resource.
- **unscanned** (Boolean) Whether or not to block download of artifacts that meet the artifact `filters` for the associated `xray_watch` resource but have not been scanned yet.

