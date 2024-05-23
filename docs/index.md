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

## Terraform CLI version support

Current version support [Terraform Protocol v6](https://developer.hashicorp.com/terraform/plugin/terraform-plugin-protocol#protocol-version-6) which mean Terraform CLI version 1.0 and later. 

## Example Usage

```terraform
# Required for Terraform 0.13 and up (https://www.terraform.io/upgrade-guides/0-13.html)
terraform {
  required_providers {
    xray = {
      source  = "jfrog/xray"
      version = "0.0.1"
    }
  }
}

provider "xray" {
  url          = "artifactory.site.com/xray"
  access_token = "abc..xy"
  // Also user can supply the following env vars:
  // ARTIFACTORY_URL or JFROG_URL
  // XRAY_ACCESS_TOKEN or JFROG_ACCESS_TOKEN
}

resource "random_id" "randid" {
  byte_length = 2
}

resource "xray_security_policy" "security_policy" {
  name        = "test-security-policy-severity-${random_id.randid.dec}"
  description = "Security policy description"
  type        = "security"

  rule {
    name     = "rule-name-severity"
    priority = 1

    criteria {
      min_severity = "High"
    }

    actions {
      webhooks                           = []
      mails                              = ["test@email.com"]
      block_release_bundle_distribution  = true
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      build_failure_grace_period_in_days = 5     // use only if fail_build is enabled

      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}


resource "xray_license_policy" "license_policy" {
  name        = "test-license-policy-allowed-${random_id.randid.dec}"
  description = "License policy, allow certain licenses"
  type        = "license"

  rule {
    name     = "License_rule"
    priority = 1

    criteria {
      allowed_licenses         = ["Apache-1.0", "Apache-2.0"]
      allow_unknown            = false
      multi_license_permissive = true
    }

    actions {
      webhooks                           = []
      mails                              = ["test@email.com"]
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      custom_severity                    = "High"
      build_failure_grace_period_in_days = 5 // use only if fail_build is enabled

      block_download {
        unscanned = true
        active    = true
      }
    }
  }
}

resource "xray_operational_risk_policy" "min_risk" {
  name        = "test-operational-risk-policy-min-risk"
  description = "Operational Risk policy with a custom risk rule"
  type        = "operational_risk"

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
  type        = "operational_risk"

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
    name = xray_security_policy.security_policy.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.license_policy.name
    type = "license"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "all-projects" {
  name        = "all-projects-watch-${random_id.randid.dec}"
  description = "Watch all the projects"
  active      = true

  watch_resource {
    type       = "all-projects"
    bin_mgr_id = "default"
  }

  assigned_policy {
    name = xray_security_policy.security_policy.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.license_policy.name
    type = "license"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_watch" "project" {
  name        = "project-watch-${random_id.randid.dec}"
  description = "Watch selected projects"
  active      = true

  watch_resource {
    type = "project"
    name = "test"
  }
  watch_resource {
    type = "project"
    name = "test1"
  }

  assigned_policy {
    name = xray_security_policy.security_policy.name
    type = "security"
  }

  assigned_policy {
    name = xray_license_policy.license_policy.name
    type = "license"
  }

  watch_recipients = ["test@email.com", "test1@email.com"]
}

resource "xray_settings" "db_sync" {
  db_sync_updates_time = "18:40"
}

resource "xray_repository_config" "xray-repo-config-pattern" {
  repo_name  = "example-repo-local"

  paths_config {

    pattern {
      include              = "core/**"
      exclude              = "core/internal/**"
      index_new_artifacts  = true
      retention_in_days    = 60
    }

    pattern {
      include              = "core/**"
      exclude              = "core/external/**"
      index_new_artifacts  = true
      retention_in_days    = 45
    }

    all_other_artifacts {
      index_new_artifacts = true
      retention_in_days   = 60
    }
  }
}

resource "xray_repository_config" "xray-repo-config" {

  repo_name  = "example-repo-local"

  config {
    vuln_contextual_analysis  = true
    retention_in_days         = 90
  }
}

resource "xray_licenses_report" "report" {
  name 							= "test-license-report"
  resources {
    repository {
      name 					    = "reponame"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern2","pattern2"]
    }

    repository {
      name 					    = "reponame1"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern1","pattern2"]
    }
  }

  filters {
    component 			= "component-name"
    artifact 			= "impacted-artifact"
    unknown 			= false
    unrecognized 		= true
    license_names 		= ["Apache","MIT"]

    scan_date {
      start 			= "2020-06-29T12:22:16Z"
      end				= "2020-07-29T12:22:16Z"
    }
  }
}

resource "xray_operational_risks_report" "report" {
  name 							= "test-operational-risks-report"
  resources {
    repository {
      name 					    = "reponame"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern2","pattern2"]
    }

    repository {
      name 					    = "reponame1"
      include_path_patterns 	= ["pattern1"]
      exclude_path_patterns 	= ["pattern3","pattern4"]
    }
  }

  filters {
    component 			= "component-name"
    artifact 			= "impacted-artifact"
    risks 				= ["High","Medium"]

    scan_date {
      start 			= "2020-06-29T12:22:16Z"
      end				= "2020-07-29T12:22:16Z"
    }
  }
}

resource "xray_violations_report" "report" {
  name 							= "test-violations-report"
  resources {
    repository {
      name 					    = "reponame"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern2","pattern2"]
    }

    repository {
      name 					    = "reponame1"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern1","pattern2"]
    }
  }

  filters {
    type 					= "security"
    watch_names 			= ["NameOfWatch1","NameOfWatch2"]
    watch_patterns 			= ["WildcardWatch*","WildcardWatch1*"]
    component 				= "*vulnerable:component*"
    artifact 				= "some://impacted*artifact"
    policy_names 			= ["policy1","policy2"]
    severities 				= ["High","Medium"]

    updated {
      start 				= "2020-06-29T12:22:16Z"
      end					= "2020-07-29T12:22:16Z"
    }

    security_filters {
      issue_id			= "XRAY-87343"
      summary_contains 	= "kernel"
      has_remediation 	= true

      cvss_score {
        min_score 		= 6.3
        max_score		= 9
      }
    }

    license_filters {
      unknown 			= false
      unrecognized		= true
      license_names 	= ["Apache","MIT"]
    }
  }
}

resource "xray_vulnerabilities_report" "report" {
  name 							= "test-vulnerabilities-report"
  resources {
    repository {
      name 					    = "reponame"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern2","pattern2"]
    }

    repository {
      name 					    = "reponame1"
      include_path_patterns 	= ["pattern1","pattern2"]
      exclude_path_patterns 	= ["pattern1","pattern2"]
    }
  }

  filters {
    vulnerable_component 		= "component-name"
    impacted_artifact 			= "impacted-artifact"
    has_remediation 			= false
    cve 						= "CVE-1234-1234"

    cvss_score {
      min_score 				= 6.3
      max_score				    = 9
    }

    published {
      start 					= "2020-06-29T12:22:16Z"
      end						= "2020-07-29T12:22:16Z"
    }

    scan_date {
      start 					= "2020-06-29T12:22:16Z"
      end						= "2020-07-29T12:22:16Z"
    }
  }
}

resource "xray_ignore_rule" "ignore-rule-2590577" {
  notes           = "notes"
  expiration_date = "2023-01-19"
  vulnerabilities = ["any"]

  component {
    name    = "name"
    version = "version"
  }
}
```

## Authentication

The Xray provider supports supports two ways of authentication. The following methods are supported:
* Bearer Token
* Terraform Cloud OIDC provider

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

### Terraform Cloud OIDC Provider

If you are using this provider on Terraform Cloud and wish to use dynamic credentials instead of static access token for authentication with JFrog platform, you can leverage Terraform as the OIDC provider.

To setup dynamic credentials, follow these steps:
1. Configure Terraform Cloud as a generic OIDC provider
2. Set environment variable in your Terraform Workspace
3. Setup Terraform Cloud in your configuration

During the provider start up, if it finds env var `TFC_WORKLOAD_IDENTITY_TOKEN` it will use this token with your JFrog instance to exchange for a short-live access token. If that is successful, the provider will the access token for all subsequent API requests with the JFrog instance.

#### Configure Terraform Cloud as generic OIDC provider

Follow [confgure an OIDC integration](https://jfrog.com/help/r/jfrog-platform-administration-documentation/configure-an-oidc-integration). Enter a name for the provider, e.g. `terraform-cloud`. Use `https://app.terraform.io` for "Provider URL". Choose your own value for "Audience", e.g. `jfrog-terraform-cloud`.

Then [configure an identity mapping](https://jfrog.com/help/r/jfrog-platform-administration-documentation/configure-identity-mappings) with an empty "Claims JSON" (`{}`), and select the "Token scope", "User", and "Service" as desired.

#### Set environment variable in your Terraform Workspace

In your workspace, add an environment variable `TFC_WORKLOAD_IDENTITY_AUDIENCE` with audience value (e.g. `jfrog-terraform-cloud`) from JFrog OIDC integration above. See [Manually Generating Workload Identity Tokens](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials/manual-generation) for more details.

When a run starts on Terraform Cloud, it will create a workload identity token with the specified audience and assigns it to the environment variable `TFC_WORKLOAD_IDENTITY_TOKEN` for the provider to consume.

#### Setup Terraform Cloud in your configuration

Add `cloud` block to `terraform` block, and add `oidc_provider_name` attribute (from JFrog OIDC integration) to provider block:

```terraform
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      name = "my-workspace"
    }
  }

  required_providers {
    xray = {
      source  = "jfrog/xray"
      version = "2.5.1"
    }
  }
}

provider "xray" {
  url = "https://myinstance.jfrog.io"
  oidc_provider_name = "terraform-cloud"
}
```

**Note:** Ensure `access_token` attribute and `JFROG_ACCESS_TOKEN` env var are not set

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `access_token` (String, Sensitive) This is a bearer token that can be given to you by your admin under `Identity and Access`
- `check_license` (Boolean) Toggle for pre-flight checking of Artifactory Pro and Enterprise license. Default to `true`.
- `oidc_provider_name` (String) OIDC provider name. See [Configure an OIDC Integration](https://jfrog.com/help/r/jfrog-platform-administration-documentation/configure-an-oidc-integration) for more details.
- `url` (String) URL of Xray. This can also be sourced from the `XRAY_URL` or `JFROG_URL` environment variable. Default to 'http://localhost:8081' if not set.
