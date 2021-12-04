---
layout: ""
page_title: "JFrog Xray Provider"
description: |-
  The Xray provider is used to interact with the resources supported by JFrog Xray.
---

# JFrog Xray Provider

The [Xray](https://jfrog.com/xray/) provider is used to interact with the
resources supported by JFrog Xray. Xray is a part of JFrog Artifactory and can't be used separately.
The provider needs to be configured with the proper credentials before it can be used.
Xray API documentation can be found [here](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API)

Links to documentation for specific resources can be found in the table of contents to the left.

This provider requires access to Artifactory and Xray APIs, which are only available in the _licensed_ pro and enterprise editions.
You can determine which license you have by accessing the following URL
`${host}/artifactory/api/system/licenses/`

You can either access it via api, or web browser - it does require admin level credentials, but it's one of the few APIs that will work without a license (side node: you can also install your license here with a `POST`)

```bash
curl -sL ${host}/projects/api/system/licenses/ | jq .
{
  "type" : "Enterprise Plus Trial",
  "validThrough" : "Jan 29, 2022",
  "licensedTo" : "JFrog Ltd"
}
```

The following 3 license types (`jq .type`) do **NOT** support APIs:
- Community Edition for C/C++
- JCR Edition
- OSS

## Example Usage

```terraform
# Required for Terraform 0.13 and up (https://www.terraform.io/upgrade-guides/0-13.html)
terraform {
  required_providers {
    xray = {
      source  = "registry.terraform.io/jfrog/xray"
      version = "0.0.1"
    }
  }
}

provider "xray" {
  // Supply the following env vars:
  // ARTIFACTORY_URL (or JFROG_URL / PROJECTS_URL)
  // XRAY_ACCESS_TOKEN or JFROG_ACCESS_TOKEN
}

resource "random_id" "randid" {
  byte_length = 2
}

resource "xray_security_policy" "security1" {
  name        = "test-security-policy-severity-${random_id.randid.dec}"
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
  name        = "test-security-policy-cvss-${random_id.randid.dec}"
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

resource "xray_license_policy" "license1" {
  name        = "test-license-policy-allowed-${random_id.randid.dec}"
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
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      custom_severity                    = "High"
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

    }
  }
}

resource "xray_license_policy" "license2" {
  name        = "test-license-policy-banned-${random_id.randid.dec}"
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

resource "xray_watch" "all-repos" {
  name        = "all-repos-watch-${random_id.randid.dec}"
  description = "Watch for all repositories, matching the filter"
  active      = true
  watch_resource {
    type = "all-repos"
    filter {
      type  = "regex"
      value = ".*"
    }
  }
  assigned_policy {
    name = xray_security_policy.security1.name
    type = "security"
  }
  assigned_policy {
    name = xray_license_policy.license1.name
    type = "license"
  }
  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "repository" {
  name        = "repository-watch-${random_id.randid.dec}"
  description = "Watch a single repo or a list of repositories"
  active      = true

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-repository-name"
    filter {
      type  = "regex"
      value = ".*"
    }
  }

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "your-other-repository-name"
    filter {
      type  = "package-type"
      value = "Docker"
    }
  }

  assigned_policy {
    name = xray_security_policy.security1.name
    type = "security"
  }
  assigned_policy {
    name = xray_license_policy.license1.name
    type = "license"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "build" {
  name        = "build-watch-${random_id.randid.dec}"
  description = "Watch a single build or a list of builds"
  active      = true

  watch_resource {
    type       = "build"
    bin_mgr_id = "default"
    name       = "your-build-name"
  }

  watch_resource {
    type       = "build"
    bin_mgr_id = "default"
    name       = "your-other-build-name"
  }

  assigned_policy {
    name = xray_security_policy.security1.name
    type = "security"
  }
  assigned_policy {
    name = xray_license_policy.license1.name
    type = "license"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}
```

## Authentication

The Xray provider supports one type of authentication using Bearer token.

### Bearer Token
Artifactory access tokens may be used via the Authorization header by providing the `access_token` field to the provider
block. Getting this value from the environment is supported with the `XRAY_ACCESS_TOKEN`,
or `JFROG_ACCESS_TOKEN` variables.
Set `url` field to provide JFrog Xray URL. Alternatively you can set `ARTIFACTORY_URL`, `JFROG_URL` or `PROJECTS_URL` variables.

Usage:
```hcl
# Configure the Xray provider
provider "xray" {
  url = "artifactory.site.com/xray"
  access_token = "abc...xy"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **access_token** (String, Sensitive) This is a bearer token that can be given to you by your admin under `Identity and Access`
- **url** (String) URL of Artifactory. This can also be sourced from the `PROJECTS_URL`, `ARTIFACTORY_URL` or `JFROG_URL` environment variable. Default to 'http://localhost:8081' if not set.
