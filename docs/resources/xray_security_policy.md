# Xray Security Policy Resource

Provides an Xray security policy resource. This can be used to create and manage Xray v2 security policies.

## Example Usage

```hcl
# Create a new Xray security policy (minimum severity)
resource "xray_security_policy" "security" {
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
```

```hcl
# Create a new Xray security policy (cvss range)
resource "xray_security_policy" "security" {
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
      create_ticket_enabled              = false 
      build_failure_grace_period_in_days = 5     
    }
  }
}
```

## Attribute Reference

The following arguments are supported:

* `name` - (Required) Name of the policy (must be unique)
* `description` - (Optional) More verbose description of the policy
* `type` - (Required) Type of the policy
* `rules` - (Required) Nested block describing the policy rules. Described below.

### rules

The top-level `rules` block is a list of one or more rules that each supports the following:

* `name` - (Required) Name of the rule
* `priority` - (Required) Integer describing the rule priority
* `criteria` - (Required) Nested block describing the criteria for the policy. Described below.
* `actions` - (Required) Nested block describing the actions to be applied by the policy. Described below.

#### criteria

~> **NOTE:** Only one of security criteria (`min_severity` and `cvss_range`) may be specified. While all attributes are marked as optional, at least one
attribute from only one of these groups must be defined.
The nested `criteria` block is a list of one item, supporting the following:

##### Security criteria

* `min_severity` - (Optional) The minimum security vulnerability severity that will be impacted by the policy.
* `cvss_range` - (Optional) Nested block describing a CVS score range to be impacted. Defined below.

###### cvss_range

The nested `cvss_range` block is a list of one object that contains the following attributes:

* `to` - (Required) The end of the range of CVS scores (from 1-10, float) to flag. 
* `from` - (Required) The beginning of the range of CVS scores (from 1-10, float) to flag.

#### actions

~> **NOTE:** While all of the actions attributes are marked as optional, at least one action must be specified.

The nested `actions` block is a list of exactly one object with the following attributes:

* `webhooks` - (Optional) A list of Xray-configured webhook URLs to be invoked if a violation is triggered.
* `mails` - (Optional) A list of email addressed that will get emailed when a violation is triggered.
* `block_download` - (Optional) Nested block describing artifacts that should be blocked for download if a violation is triggered. Described below.
* `block_release_bundle_distribution` - (Optional) Blocks Release Bundle distribution to Edge nodes if a violation is found.
* `fail_build` - (Optional) Whether or not the related CI build should be marked as failed if a violation is triggered. This option is only available when the policy is applied to an `xray_watch` resource with a `type` of `builds`.
* `notify_watch_recipients` - (Optional) Sends an email message to all configured recipients inside a specific watch with details about the generated Violations.
* `notify_deployer` - (Optional) Sends an email message to component deployer with details about the generated Violations.
* `create_ticket_enabled` - (Optional) Create Jira Ticket for this Policy Violation.
* `custom_severity` - (Optional) The severity of violation to be triggered if the `criteria` are met.
* `build_failure_grace_period_in_days` - (Optional) Allow grace period for certain number of days. All violations will be ignored during this time. To be used only if `fail_build` is enabled.

###### block_download

~> **NOTE:** Only one of `unscanned` or `active` may be set to `true`.

The nested `block_download` block is a list of exactly one object with the following attributes:

* `unscanned` - Whether or not to block download of artifacts that meet the artifact `filters` for the associated `xray_watch` resource but have not been scanned yet.
* `active` - Whether or not to block download of artifacts that meet the artifact and severity `filters` for the associated `xray_watch` resource.


## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `created` - Timestamp of when the policy was first created
* `modified` - Timestamp of when the policy was last modified

## Import

A policy can be imported by using the name, e.g.

```
$ terraform import xray_security_policy.example policy-name
```
