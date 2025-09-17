# Required for Terraform 0.13 and up (https://www.terraform.io/upgrade-guides/0-13.html)
terraform {
  required_providers {
    xray = {
      source  = "jfrog/xray"
      version = "3.1.1"
    }
  }
}

provider "xray" {
  url          = "artifactory.site.com/xray"
  access_token = "abc..xy"
  
  //optional: Skip xray version check, default is false.
  //skip_xray_version_check = true

  // Also user can supply the following env vars:
  // JFROG_URL or XRAY_URL
  // XRAY_ACCESS_TOKEN or JFROG_ACCESS_TOKEN
  // Optional: Skip version check, default is false.
  // SKIP_XRAY_VERSION_CHECK = true
}

resource "random_id" "randid" {
  byte_length = 2
}

resource "xray_webhook" "xraywebhooks1234" {
	name        = "xraywebhooks${random_id.randid.dec}"
	description = "My webhook description"
	url         = "https://tempurl.org"
	use_proxy   = false
	user_name   = "my_user_1"
	password    = "my_user_password"

	headers = {
		header1_name = "header1_value"
		header2_name = "header2_value"
	}
}

resource "xray_security_policy" "security1" {
  name        = "test-security-policy-severity-${random_id.randid.dec}"
  description = "Security policy description"
  type        = "security"

  rule {
    name     = "rule-name-severity"
    priority = 1

    criteria {
      min_severity          = "High"
      fix_version_dependant = false
    }

    actions {
      webhooks                           = ["xraywebhooks${random_id.randid.dec}"]
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

resource "xray_security_policy" "security2" {
  name        = "test-security-policy-cvss-${random_id.randid.dec}"
  description = "Security policy description"
  type        = "security"

  rule {
    name     = "rule-name-cvss"
    priority = 1

    criteria {

      cvss_range {
        from = 1.5
        to   = 5.3
      }
    }

    actions {
      webhooks                           = ["xraywebhooks${random_id.randid.dec}"]
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

resource "xray_license_policy" "license1" {
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
      webhooks                           = ["xraywebhooks${random_id.randid.dec}"]
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

resource "xray_license_policy" "license2" {
  name        = "test-license-policy-banned-${random_id.randid.dec}"
  description = "License policy, block certain licenses"
  type        = "license"

  rule {
    name     = "License_rule"
    priority = 1

    criteria {
      banned_licenses          = ["Apache-1.1", "APAFML"]
      allow_unknown            = false
      multi_license_permissive = false
    }

    actions {
      webhooks                           = ["xraywebhooks${random_id.randid.dec}"]
      mails                              = ["test@email.com"]
      block_release_bundle_distribution  = false
      fail_build                         = true
      notify_watch_recipients            = true
      notify_deployer                    = true
      create_ticket_enabled              = false // set to true only if Jira integration is enabled
      custom_severity                    = "Medium"
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

resource "xray_watch" "repository" {
  name        = "repository-watch-${random_id.randid.dec}"
  description = "Watch a single repo or a list of repositories"
  active      = true

  watch_resource {
    type       = "repository"
    bin_mgr_id = "default"
    name       = "example-repo-local"
    repo_type  = "local"

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

resource "xray_watch" "all-builds-with-filters" {
  name        = "all-builds-watch-${random_id.randid.dec}"
  description = "Watch all builds with Ant patterns filter"
  active      = true

  watch_resource {
    type       = "all-builds"
    bin_mgr_id = "default"

    ant_filter {
      exclude_patterns = ["a*", "b*"]
      include_patterns = ["ab*"]
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

resource "xray_watch" "all-projects" {
  name        = "all-projects-watch-${random_id.randid.dec}"
  description = "Watch all the projects"
  active      = true

  watch_resource {
    type       = "all-projects"
    bin_mgr_id = "default"
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

resource "xray_watch" "all-projects-with-filters" {
  name        = "all-projects-with-filters-watch-${random_id.randid.dec}"
  description = "Watch all the projects with Ant patterns filter"
  active      = true

  watch_resource {
    type       = "all-projects"
    bin_mgr_id = "default"

    ant_filter {
      exclude_patterns = ["a*", "b*"]
      include_patterns = ["ab*"]
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

resource "xray_watch" "project" {
  name        = "project-watch-${random_id.randid.dec}"
  description = "Watch selected projects"
  active      = true

  watch_resource {
    type = "project"
    name = "myproj"
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

resource "xray_workers_count" "workers-count" {
  index {
    new_content      = 4
    existing_content = 2
  }
  persist {
    new_content      = 4
    existing_content = 2
  }
  analysis {
    new_content      = 4
    existing_content = 2
  }
  policy_enforcer {
    new_content      = 4
    existing_content = 2
  }
  impact_analysis {
    new_content = 2
  }
  notification {
    new_content = 2
  }
  user_catalog {
    new_content      = 4
    existing_content = 2
  }
  sbom_impact_analysis {
    new_content      = 4
    existing_content = 2
  }
  migration_sbom {
    new_content      = 4
    existing_content = 2
  }
  sbom {
    new_content      = 4
    existing_content = 2
  } 
  panoramic {
    new_content      = 4
  }
}

resource "xray_repository_config" "xray-repo-config-pattern" {

  repo_name = "example-repo-local"
  jas_enabled = true

  config {
    vuln_contextual_analysis = true
    retention_in_days        = 90

    exposures {
      scanners_category {
        secrets = true
      }
	  }
  }

  paths_config {

    pattern {
      include             = "core/**"
      exclude             = "core/internal/**"
      index_new_artifacts = true
      retention_in_days   = 60
    }

    pattern {
      include             = "core/**"
      exclude             = "core/external/**"
      index_new_artifacts = true
      retention_in_days   = 45
    }

    all_other_artifacts {
      index_new_artifacts = true
      retention_in_days   = 60
    }
  }
}

resource "xray_repository_config" "xray-repo-config" {

  repo_name = "example-repo-local"

  jas_enabled = true
  config {
    vuln_contextual_analysis = true
    retention_in_days        = 90
    
    exposures {
      scanners_category {
        secrets = true
      }
	  }
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
  expiration_date = "2026-01-19"
  vulnerabilities = ["any"]
  cves = ["any"]

  component {
    name    = "name"
    version = "version"
  }
}