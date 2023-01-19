## 1.9.8 (January 19, 2023).

BUG FIXES:

* resource/xray_violations_report: fixed an issue, when the provider crashed if the `security_filters` attribute wasn't set.
  Issue [#95](https://github.com/jfrog/terraform-provider-xray/issues/95)
  PR [#100](https://github.com/jfrog/terraform-provider-xray/pull/100)

## 1.9.7 (January 18, 2023). Tested on Artifactory 7.49.5 and Xray 3.65.2

BUG FIXES:

* resource/xray_ignore_rule: fixed nil pointer exception, when "expiration_date" attribute wasn't set. Fixed documentation, added HCL examples.
  Issue [#94](https://github.com/jfrog/terraform-provider-xray/issues/94)
  PR [#99](https://github.com/jfrog/terraform-provider-xray/pull/99)

## 1.9.6 (January 12, 2023). Tested on Artifactory 7.49.5 and Xray 3.64.4

BUG FIXES:

* resource/xray_operational_risk_policy: documentation updated to match Xray behavior, all policy types are lowercase now.
 Issue: [#96](https://github.com/jfrog/terraform-provider-xray/issues/96)
 PR [#98](https://github.com/jfrog/terraform-provider-xray/pull/98)

## 1.9.5 (December 22, 2022). Tested on Artifactory 7.47.14 and Xray 3.62.4

BUG FIXES:

* resource/xray_ignore_rule, resource/xray_license_policy, resource/xray_licenses_report, resource/xray_operational_risk_policy, resource/xray_operational_risks_report, resource/xray_security_policy, resource/xray_violations_report, resource/xray_vulnerabilities_report, resource/xray_watch: Update `project_key` attribute validation to match Artifactory Project. PR: [#93](https://github.com/jfrog/terraform-provider-xray/pull/93)

## 1.9.4 (November 23, 2022). Tested on Artifactory 7.46.11 and Xray 3.61.5

BUG FIXES:

* resource/xray_watch: fix `watch_recipients` attribute not being set when reading from Xray. PR [#91](https://github.com/jfrog/terraform-provider-xray/pull/91)

## 1.9.3 (November 24, 2022). Tested on Artifactory 7.46.11 and Xray 3.61.5

BUG FIXES:

* resource/xray_security_policy: fix `min_severity` attribute state drift due to Xray API bug, which has been fixed. Issue [#84](https://github.com/jfrog/terraform-provider-xray/issues/84) PR [#90](https://github.com/jfrog/terraform-provider-xray/pull/90)

## 1.9.2 (November 22, 2022). Tested on Artifactory 7.46.11 and Xray 3.61.5

BUG FIXES:

* resource/xray_watch: fix `name` attribute not being set when reading from Xray. PR [#88](https://github.com/jfrog/terraform-provider-xray/pull/88)

## 1.9.1 (November 17, 2022). Tested on Artifactory 7.46.11 and Xray 3.60.2

BUG FIXES:

* resource/xray_watch: removed constraints from 'ant_filter' and 'path_ant_filter' attribute include and exclude fields.
  It's not required to set both 'include' and 'exclude' filters anymore. The fix allows users to set only one of include/exclude filters, if needed.

Issue [#86](https://github.com/jfrog/terraform-provider-xray/issues/86)
PR [#87](https://github.com/jfrog/terraform-provider-xray/pull/87)

## 1.9.0 (November 10, 2022). Tested on Artifactory 7.46.11 and Xray 3.59.7

FEATURES:

* resource/xray_licenses_report: add a new resource allowing to create Xray Licenses report.
* resource/xray_operational_risks_report: add a new resource allowing to create Xray Operational Risks report.
* resource/xray_violations_report: add a new resource allowing to create Xray Violations report.
* resource/xray_vulnerabilities_report: add a new resource allowing to create Xray Vulnerabilities report.

Issue [#60](https://github.com/jfrog/terraform-provider-xray/issues/60)
PR [#85](https://github.com/jfrog/terraform-provider-xray/pull/85)

## 1.8.0 (October 18, 2022). Tested on Artifactory 7.46.10 and Xray 3.59.4

IMPROVEMENTS:

* resource/xray_watch: add functionality to apply `path_ant_filter` for `repository` and `all-repos` `watch_resource.type`.
 PR [#82](https://github.com/jfrog/terraform-provider-xray/pull/82)

## 1.7.0 (October 6, 2022). Tested on Artifactory 7.41.13 and Xray 3.57.6

FEATURES:

* resource/xray_repository_config: add a new resource allowing to configure Xray report retention policies for the repositories. Issue [#77](https://github.com/jfrog/terraform-provider-xray/issues/77) PR [#81](https://github.com/jfrog/terraform-provider-xray/pull/81)
* Add ability to disable license check. PR [#80](https://github.com/jfrog/terraform-provider-xray/pull/80)

## 1.6.0 (August 31, 2022). Tested on Artifactory 7.41.7 and Xray 3.55.2

FEATURES:

* **New Resource:** `xray_ignore_rule` Issue: [#67](https://github.com/jfrog/terraform-provider-xray/issues/67) PR: [#76](https://github.com/jfrog/terraform-provider-xray/pull/76).

## 1.5.1 (August 9, 2022). Tested on Artifactory 7.41.7 and Xray 3.54.5

BUG FIXES:

* resource/xray_watch, resource/xray_security_policy, resource/xray_license_policy, and resource/xray_operational_risk_policy: Add support for hyphen character in `project_key` attribute. PR: [#73](https://github.com/jfrog/terraform-provider-xray/pull/73).

## 1.5.0 (August 3, 2022). Tested on Artifactory 7.41.7 and Xray 3.52.4

FEATURES:

* resource/xray_watch, resource/xray_security_policy, resource/xray_license_policy, and resource/xray_operational_risk_policy: Add support for `project_key` attribute. PR: [#72](https://github.com/jfrog/terraform-provider-xray/pull/72). Issue [#69](https://github.com/jfrog/terraform-provider-xray/issues/69)

## 1.4.0 (July 22, 2022). Tested on Artifactory 7.41.6 and Xray 3.52.4

FEATURES:

* resource/xray_operational_risk_policy: New resource to support 'operational_risk' policy. PR: [#71](https://github.com/jfrog/terraform-provider-xray/pull/71). Issue: [#50](https://github.com/jfrog/terraform-provider-xray/issues/50)

## 1.3.0 (July 13, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.3

FEATURES:

* resource/xray_workers_count: Add support to set Xray's workers count. PR: [#68](https://github.com/jfrog/terraform-provider-xray/pull/68). Issue: [#56](https://github.com/jfrog/terraform-provider-xray/issues/56)

## 1.2.1 (July 6, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.3

IMPROVEMENTS:

* resource/xray_watch: Update documentation for Ant pattern filter for `all-builds` and `all-projects` watch resource type. PR: [#66](https://github.com/jfrog/terraform-provider-xray/pull/66). Project provider issue: [#39](https://github.com/jfrog/terraform-provider-project/issues/39)

## 1.2.0 (July 1, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.3

IMPROVEMENTS:

* resource/xray_watch: Add support for Ant pattern filter for `all-builds` and `all-projects` watch resource type. PR: [#61](https://github.com/jfrog/terraform-provider-xray/pull/61). Issue: [#48](https://github.com/jfrog/terraform-provider-xray/issues/48)

## 1.1.8 (July 1, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.3

BUG FIXES:

* provider: Fix hardcoded HTTP user-agent string. PR: [#62](https://github.com/jfrog/terraform-provider-xray/pull/62)

## 1.1.7 (June 21, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.3

IMPROVEMENTS:

* Bump shared module version

## 1.1.6 (June 3, 2022). Tested on Artifactory 7.39.4 and Xray 3.51.0

BUG FIXES:

* resource/xray_watch: Fix error when creating watch with remote repository by adding new attribute `repo_type` to allow user to specify whether the repository is local or remote. [GH-55](https://github.com/jfrog/terraform-provider-xray/pull/55)

## 1.1.5 (May 27, 2022). Tested on Artifactory 7.38.10 and Xray 3.49.0

IMPROVEMENTS:

* Upgrade `gopkg.in/yaml.v3` to v3.0.0 for [CVE-2022-28948](https://nvd.nist.gov/vuln/detail/CVE-2022-28948) [GH-54](https://github.com/jfrog/terraform-provider-xray/pull/54)

## 1.1.4 (May 24, 2022). Tested on Artifactory 7.38.10 and Xray 3.49.0

BUG FIXES:

* add 'Commercial' licence to the list of allowed licenses.
 [GH-52](https://github.com/jfrog/terraform-provider-xray/pull/52)


## 1.1.3 (May 12, 2022). Tested on Artifactory 7.38.8 and Xray 3.48.2

* minor version bump to force release due to build failure


## 1.1.2 (May 11, 2022). Tested on Artifactory 7.38.8 and Xray 3.48.2

IMPROVEMENTS:

* fixed HCL example for Xray Watch.
  [GH-47](https://github.com/jfrog/terraform-provider-xray/pull/47).


## 1.1.1 (Apr 29, 2022). Tested on Artifactory 7.37.15 and Xray 3.47.3

IMPROVEMENTS:

* documentation reorganized, added subcategories and templates.
[GH-44](https://github.com/jfrog/terraform-provider-xray/pull/44).


## 1.1.0 (Apr 15, 2022). Tested on Artifactory 7.37.14 and Xray 3.47.3

IMPROVEMENTS:

* added `fix_version_dependant` field to `xray_security_policy` resource. The field introduced in Xray 3.44.1
[GH-39](https://github.com/jfrog/terraform-provider-xray/pull/39)

## 1.0.0 (Mar 16, 2022)

IMPROVEMENTS:

* added new resource `xray_settings` which will set Xray DB Sync Time.
[GH-35](https://github.com/jfrog/terraform-provider-xray/pull/35)


## 0.0.3 (Feb 22, 2022)

BUG FIXES:

* resource/xray_watch: Add all-builds to schema validation.
[GH-31](https://github.com/jfrog/terraform-provider-xray/pull/31)


## 0.0.1 (Jan 4, 2022)

Xray provider was separated from Artifactory provider. The most notable differences in the new Xray provider:
- Provider uses Xray API v2 for all the API calls.
- HCL was changed and now uses singular names instead of the plurals for the repeatable elements, like `rule`, `watch_resource`, `filter` and `assigned_policy`.
- Security policy and License policy now are separate Terraform provider resources.
- In Schemas, TypeList was replaced by TypeSet (where it makes sense) to avoid sorting problems, when Terraform detect the change in sorted elements.
- Added multiple validations for Schemas to verify the data on the Terraform level instead of getting errors in the API response.
