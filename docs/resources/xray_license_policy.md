# Xray License Policy Resource

Provides an Xray license policy resource. This can be used to create and manage Xray v2 license policies.

## Example Usage

```hcl
# Create a new Xray license policy (allowed licenses)
resource "xray_license_policy" "license" {
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
      create_ticket_enabled              = false 
      custom_severity                    = "High"
      build_failure_grace_period_in_days = 5
    }
  }
}
```

```hcl
# Create a new Xray license policy (banned licenses)
resource "xray_license_policy" "license" {
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
      create_ticket_enabled              = false 
      custom_severity                    = "Medium"
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

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

~> **NOTE:** Only one of or license criteria (`allow_unknown`, `banned_licenses`, and `allowed_licenses`) may be specified. While all attributes are marked as optional, at least one
attribute from only one of these groups must be defined.
The nested `criteria` block is a list of one item, supporting the following:

##### License criteria

* `allow_unknown` - (Optional) Whether or not to allow components whose license cannot be determined (`true` or `false`).
* `banned_licenses` - (Optional) A list of OSS license names that may not be attached to a component.
* `allowed_licenses` - (Optional) A list of OSS license names that may be attached to a component.

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
$ terraform import xray_license_policy.example policy-name
```
