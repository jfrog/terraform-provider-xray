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

BUG FIX:

* resource/xray_watch: Fix error when creating watch with remote repository by adding new attribute `repo_type` to allow user to specify whether the repository is local or remote. [GH-55](https://github.com/jfrog/terraform-provider-xray/pull/55)

## 1.1.5 (May 27, 2022). Tested on Artifactory 7.38.10 and Xray 3.49.0

IMPROVEMENTS:

* Upgrade `gopkg.in/yaml.v3` to v3.0.0 for [CVE-2022-28948](https://nvd.nist.gov/vuln/detail/CVE-2022-28948) [GH-54](https://github.com/jfrog/terraform-provider-xray/pull/54)

## 1.1.4 (May 24, 2022). Tested on Artifactory 7.38.10 and Xray 3.49.0

BUG FIX:

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
