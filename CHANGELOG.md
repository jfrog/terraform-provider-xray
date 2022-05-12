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

