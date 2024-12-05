## 3.0.2 (December 5, 2024). Tested on Artifactory 7.98.9 and Xray 3.107.16 with Terraform 1.10.1 and OpenTofu 1.8.7

BUG FIXES:

* resource/xray_ignore_rule: Fix incorrect API request field name for `release_bundle` attribute. Issue: [#285](https://github.com/jfrog/terraform-provider-xray/issues/285) PR: [#286](https://github.com/jfrog/terraform-provider-xray/issues/286)

IMPROVEMENTS:

* resource/xray_binary_manager_repos: Update validation attribute `package_type` to match Xray API. PR: [#286](https://github.com/jfrog/terraform-provider-xray/issues/286)

## 3.0.1 (November 19, 2024)

BUG FIXES:

* GoReleaser: Fix incorrect `ldflags` value. PR: [#278](https://github.com/jfrog/terraform-provider-xray/issues/278)

## 3.0.0 (November 19, 2024). Tested on Artifactory 7.98.8 and Xray 3.104.18 with Terraform 1.9.8 and OpenTofu 1.8.5

BREAKING CHANGES:

* provider: Deprecated attribute `check_license` is removed.

BUG FIXES:

* resource/xray_license_policy: Switch `allowed_licenses` and `banned_licenses` attribute type from `TypeSet` to `TypeList` to resolve performance issue with large number of licenses. Add validation to ensure `allowed_licenses` and `banned_licenses` attributes cannot be set at the same time. Issue: [#262](https://github.com/jfrog/terraform-provider-xray/issues/262) and [#271](https://github.com/jfrog/terraform-provider-xray/issues/271) PR: [#274](https://github.com/jfrog/terraform-provider-xray/issues/274)
* resource/xray_security_policy: Fix validation not allowing `malicious_package` set to `false` when `min_severity` is set. Issue: [#272](https://github.com/jfrog/terraform-provider-xray/issues/272) PR: [#276](https://github.com/jfrog/terraform-provider-xray/issues/276)
* resource/xray_repository_config: Add missing package types (`nuget` and `oci`) support for `exposure`. Add `cocoapods` package type support for scanning. Issue: [#273](https://github.com/jfrog/terraform-provider-xray/issues/273) PR: [#277](https://github.com/jfrog/terraform-provider-xray/issues/277)

## 2.13.2 (November 11, 2024). Tested on Artifactory 7.98.8 and Xray 3.104.18 with Terraform 1.9.8 and OpenTofu 1.8.5

BUG FIXES:

* resource/xray_security_policy: Fix "Provider produced inconsistent result after apply" error after resource creation. Issue: [#265](https://github.com/jfrog/terraform-provider-xray/issues/265) PR: [#268](https://github.com/jfrog/terraform-provider-xray/issues/268)

## 2.13.1 (October 31, 2024). Tested on Artifactory 7.98.7 and Xray 3.104.18 with Terraform 1.9.8 and OpenTofu 1.8.4

BUG FIXES:

* resource/xray_ignore_rule: Fix another date parsing issue with timezone for `expiration_date` attribute. Issue: [#259](https://github.com/jfrog/terraform-provider-xray/issues/259) PR: [#260](https://github.com/jfrog/terraform-provider-xray/issues/260)

## 2.13.0 (October 17, 2024). Tested on Artifactory 7.90.14 and Xray 3.104.18 with Terraform 1.9.8 and OpenTofu 1.8.3

IMPROVEMENTS:

* provider: Add `tfc_credential_tag_name` configuration attribute to support use of different/[multiple Workload Identity Token in Terraform Cloud Platform](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials/manual-generation#generating-multiple-tokens). Issue: [#68](https://github.com/jfrog/terraform-provider-shared/issues/68) PR: [#257](https://github.com/jfrog/terraform-provider-xray/issues/257)

## 2.12.0 (October 4, 2024). Tested on Artifactory 7.90.13 and Xray 3.104.15 with Terraform 1.9.7 and OpenTofu 1.8.2

BUG FIXES:

* resource/xray_license_policy: Fix case insensitive attribute validations for `actions.custom_severity`.
* resource/xray_operational_risk_policy: Fix case insensitive attribute validations for `criteria.op_risk_min_risk`, `criteria.op_risk_custom.risk`.
* resource/xray_security_policy: Fix case insensitive attribute validations for `criteria.min_severity`, `criteria.exposures.min_severity`, and `criteria.package_type`.
* resource/xray_violations_report: Fix case insensitive attribute validations for `filter.type`.

PR: [#254](https://github.com/jfrog/terraform-provider-xray/pull/254) Issue: [#253](https://github.com/jfrog/terraform-provider-xray/issues/253)

## 2.11.2 (September 23, 2024). Tested on Artifactory 7.90.10 and Xray 3.104.11 with Terraform 1.9.6 and OpenTofu 1.8.2

BUG FIXES:

* resource/xray_\*\_policy: Fix "Provider produced inconsistent result after apply" error due to `build_failure_grace_period_in_days` attribute. PR: [#248](https://github.com/jfrog/terraform-provider-xray/pull/248) Issue: [#248](https://github.com/jfrog/terraform-provider-xray/issues/248)

## 2.11.1 (September 16, 2024). Tested on Artifactory 7.90.10 and Xray 3.104.11 with Terraform 1.9.5 and OpenTofu 1.8.2

IMPROVEMENTS:

* resource/xray_license_policy, resource/xray_operational_risk_policy, resource/xray_security_policy: Migrate from SDKv2 to Plugin Framework. PR: [#239](https://github.com/jfrog/terraform-provider-xray/pull/239)
* resource/xray_licenses_report, resource/xray_operational_risks_report, resource/xray_violations_report, resource/xray_vulnerabilities_report: Migrate from SDKv2 to Plugin Framework. PR: [#240](https://github.com/jfrog/terraform-provider-xray/pull/240)
* resource/xray_ignore_rule: Fix date parsing issue with timezone for `expiration_date` attribute. PR: [#238](https://github.com/jfrog/terraform-provider-xray/pull/238), [#244](https://github.com/jfrog/terraform-provider-xray/pull/244)

## 2.11.0 (August 27, 2024). Tested on Artifactory 7.90.8 and Xray 3.102.5 with Terraform 1.9.5 and OpenTofu 1.8.1

IMPROVEMENTS:

* resource/xray_repository_config: Migrate from SDKv2 to Plugin Framework. PR: [#234](https://github.com/jfrog/terraform-provider-xray/pull/234)
* resource/xray_repository_config: Updated schema and validation to work with Xray version 3.102.3. PR: [#235](https://github.com/jfrog/terraform-provider-xray/pull/235)
* resource/xray_workers_count: Updated schema to work with Xray version 3.102.3. PR: [#235](https://github.com/jfrog/terraform-provider-xray/pull/235)

BUG FIXES:

* resource/xray_\*\_policy: Fix incorrect value being set from API in `exposures` attributes. PR: [#234](https://github.com/jfrog/terraform-provider-xray/pull/234)

NOTES:

* provider: `check_license` attribute is deprecated and provider no longer checks Artifactory license during initialization. It will be removed in the next major version release.

## 2.10.0 (August 8, 2024). Tested on Artifactory 7.90.6 and Xray 3.101.5 with Terraform 1.9.4 and OpenTofu 1.8.1

IMPROVEMENTS:

* resource/xray_binary_manager_release_bundles_v2: Add `indexed_release_bundle_v2` attribute validation to prevent the use of Ant-style pattern. PR: [#227](https://github.com/jfrog/terraform-provider-xray/pull/227) Issue: [#226](https://github.com/jfrog/terraform-provider-xray/issues/226)
* resource/xray_binary_manager_build: Add `indexed_builds` attribute validation to prevent the use of Ant-style pattern. PR: [#227](https://github.com/jfrog/terraform-provider-xray/pull/227) Issue: [#226](https://github.com/jfrog/terraform-provider-xray/issues/226)
* resource/xray_\*\_policy: Add `block_release_bundle_promotion` attribut to support Release Bundle promotion blocking for policy. PR: [#231](https://github.com/jfrog/terraform-provider-xray/pull/231)

## 2.9.0 (July 30, 2024). Tested on Artifactory 7.90.5 and Xray 3.101.5 with Terraform 1.9.3 and OpenTofu 1.8.0

FEATURES:

* **New Resource:** resource/xray_binary_manager_release_bundles_v2 - New resources to support Release Bundles V2 for binary manager indexing configuration. PR: [#222](https://github.com/jfrog/terraform-provider-xray/pull/222) Issue: [#220](https://github.com/jfrog/terraform-provider-xray/issues/220)

IMPROVEMENTS:

* resource/xray_security_policy: Add `applicable_cves_only` attribute to support JFrog Advanced Security feature. PR: [#223](https://github.com/jfrog/terraform-provider-xray/pull/223) Issue: [#221](https://github.com/jfrog/terraform-provider-xray/issues/221)

BUG FIXES:

* resource/xray_ignore_rule: Fix error when creating project specific ignore rule with build filter. PR: [#224](https://github.com/jfrog/terraform-provider-xray/pull/224) Issue: [#213](https://github.com/jfrog/terraform-provider-xray/issues/213)

## 2.8.2 (June 21, 2024). Tested on Artifactory 7.84.15 and Xray 3.96.1 with Terraform 1.8.5 and OpenTofu 1.7.2

IMPROVEMENTS:

* resource/xray_custom_issue: Migrate from SDKv2 to Plugin Framework. PR: [#207](https://github.com/jfrog/terraform-provider-xray/pull/207)
* resource/xray_ignore_rule: Migrate from SDKv2 to Plugin Framework. PR: [#209](https://github.com/jfrog/terraform-provider-xray/pull/209)
* resource/xray_watch: Migrate from SDKv2 to Plugin Framework. PR: [#210](https://github.com/jfrog/terraform-provider-xray/pull/210)

## 2.8.1 (June 14, 2024). Tested on Artifactory 7.84.14 and Xray 3.96.1 with Terraform 1.8.5 and OpenTofu 1.7.2

BUG FIXES:

* resource/xray_\*\_policy: Fix incorrect error handling when deleting a policy that is still attached to a watch. This leads to the resource being deleted even though the policy can't be deleted. PR: [#205](https://github.com/jfrog/terraform-provider-xray/pull/205)

## 2.8.0 (May 30, 2024)

IMPROVEMENTS:

* resource/xray_security_policy: Add `package_name`, `package_type`, and `package_versions` attributes to support package security policy. PR: [#189](https://github.com/jfrog/terraform-provider-xray/pull/189)

## 2.7.1 (May 29, 2024). Tested on Artifactory 7.84.12 and Xray 3.96.1

IMPROVEMENTS:

* resource/xray_binary_manager_repos and resource/xray_binary_manager_builds: Add missing usage and import examples to documentation. PR: [#196](https://github.com/jfrog/terraform-provider-xray/pull/196) Issue: [#129](https://github.com/jfrog/terraform-provider-xray/issues/129)

## 2.7.0 (May 29, 2024). Tested on Artifactory 7.84.12 and Xray 3.96.1

FEATURES:

* resource/xray_binary_manager_repos and resource/xray_binary_manager_builds: Add new resources to support adding repositories or builds to binary manager indexing configuration. PR: [#194](https://github.com/jfrog/terraform-provider-xray/pull/194) Issue: [#129](https://github.com/jfrog/terraform-provider-xray/issues/129)

## 2.6.0 (May 6, 2024). Tested on Artifactory 7.84.11 and Xray 3.95.7

FEATURES:

* provider: Add support for Terraform Cloud Workload Identity Token. PR: [#183](https://github.com/jfrog/terraform-provider-xray/pull/183)

## 2.5.1 (April 30, 2024). Tested on Artifactory 7.77.10 and Xray 3.94.5

* resource/xray_settings: Migrate from SDKv2 to Plugin Framework. PR: [#174](https://github.com/jfrog/terraform-provider-xray/pull/174)
* resource/xray_workers_count: Migrate from SDKv2 to Plugin Framework. PR: [#175](https://github.com/jfrog/terraform-provider-xray/pull/175)
* resource/xray_webhook: Migrate from SDKv2 to Plugin Framework. PR: [#176](https://github.com/jfrog/terraform-provider-xray/pull/176)

## 2.5.0 (March 29, 2024). Tested on Artifactory 7.77.8 and Xray 3.91.3

FEATURES:

* data/xray_artifacts_scan: Add a new data source to retrieve a list of artifacts scanned by Xray.

PR: [#170](https://github.com/jfrog/terraform-provider-xray/pull/170)
Issue: [#168](https://github.com/jfrog/terraform-provider-xray/issues/168)

## 2.4.0 (March 22, 2024). Tested on Artifactory 7.77.8 and Xray 3.91.3

IMPROVEMENTS:

* resource/xray_settings: Add attributes to support [Xray Basic settings](https://jfrog.com/help/r/jfrog-security-documentation/advanced-xray-settings). PR: [#169](https://github.com/jfrog/terraform-provider-xray/pull/169) Issue: [#78](https://github.com/jfrog/terraform-provider-xray/issues/78)

## 2.3.0 (Feburary 15, 2024). Tested on Artifactory 7.77.7 and Xray 3.91.3

IMPROVEMENTS:

* resource/xray_violations_report: add `published` attribute for `security_filters` to support `start` and `end` dates. PR: [#164](https://github.com/jfrog/terraform-provider-xray/pull/164) Issue: [#161](https://github.com/jfrog/terraform-provider-xray/issues/161)

## 2.2.0 (Feburary 2, 2024). Tested on Artifactory 7.77.3 and Xray 3.88.10

IMPROVEMENTS:

* resource/xray_ignore_rule: ensure when all nested attributes (e.g. `name`, `version`, etc.) change, they will trigger a re-creation of the resource. PR: [#162](https://github.com/jfrog/terraform-provider-xray/pull/162) Issue: [#156](https://github.com/jfrog/terraform-provider-xray/issues/156)
* resource/xray_repository_config: add new attribute `jas_enabled` to allow users to specify if their JFrog Platform has Advanced Security enabled or not. This affects how the provider interacts with Xray API. PR: [#163](https://github.com/jfrog/terraform-provider-xray/pull/163) Issue: [#159](https://github.com/jfrog/terraform-provider-xray/issues/159)

## 2.1.1 (January 22, 2024). Tested on Artifactory 7.71.11 and Xray 3.87.9

IMPROVEMENTS:

* resource/xray_*_report: remove "Import" section from report documentation as these resources do not support importing. PR: [#160](https://github.com/jfrog/terraform-provider-xray/pull/160) Issue: [#157](https://github.com/jfrog/terraform-provider-xray/issues/157)

## 2.1.0 (December 7, 2023). Tested on Artifactory 7.71.11 and Xray 3.87.5

IMPROVEMENTS:

* resource/xray_watch: add support for watch type `releaseBundle`, `all-releaseBundles`, `releaseBundleV2`, and `all-releaseBundlesV2`. PR: [#153](https://github.com/jfrog/terraform-provider-xray/pull/153) Issue: [#150](https://github.com/jfrog/terraform-provider-xray/issues/150)

## 2.0.5 (November 30, 2023). Tested on Artifactory 7.71.5 and Xray 3.86.3

BUG FIXES:

* resource/xray_security_policy: Fix ordering of multiple `rule` attributes causes state drift. PR: [#152](https://github.com/jfrog/terraform-provider-xray/pull/152) Issue: [#149](https://github.com/jfrog/terraform-provider-xray/issues/149)

## 2.0.4 (November 29, 2023). Tested on Artifactory 7.71.5 and Xray 3.86.3

BUG FIXES:

* resource/xray_ignore_rule: Remove validation against setting attributes `vulnerabilities` and `cves` at the same time. Removed `Computed` attribute for `cves` to avoid state drift and forced replacement. PR: [#151](https://github.com/jfrog/terraform-provider-xray/pull/151) Issue: [#148](https://github.com/jfrog/terraform-provider-xray/issues/148)

## 2.0.3 (November 17, 2023). Tested on Artifactory 7.71.4 and Xray 3.85.5

BUG FIXES:

* resource/xray_ignore_rule: remove validation against setting attributes `build` and `component` at the same time. PR: [#147](https://github.com/jfrog/terraform-provider-xray/pull/147) Issue: [#146](https://github.com/jfrog/terraform-provider-xray/issues/146)

## 2.0.2 (November 1, 2023). Tested on Artifactory 7.71.3 and Xray 3.83.10

BUG FIXES:

* resource/xray_repository_config: fix provider crash after upgrading from 1.12.0 to >=1.15.0.

PR: [#145](https://github.com/jfrog/terraform-provider-xray/pull/145)
Issue: [#141](https://github.com/jfrog/terraform-provider-xray/issues/141) and [#144](https://github.com/jfrog/terraform-provider-xray/issues/144)

## 2.0.1 (October 12, 2023). Tested on Artifactory 7.71.3 and Xray 3.83.10

SECURITY:

* provider: Bump golang.org/x/net from 0.11.0 to 0.17.0 PR: [#142](https://github.com/jfrog/terraform-provider-xray/pull/142)

## 2.0.0 (September 27, 2023). Tested on Artifactory 7.68.11 and Xray 3.82.11

BREAKING CHANGES:

* resource/xray_operational_risk_policy: remove default values for attributes `op_risk_custom.release_date_greater_than_months`, `op_risk_custom.newer_versions_greater_than`, `op_risk_custom.release_cadence_per_year_less_than`, `op_risk_custom.commits_less_than`, and `op_risk_custom.committers_less_than`. They are now require to be defined explicitly if you wish to set any values. There may be state drifts for this policy resource as the provide code can't distinguish between default values vs configuration values so it can't automatically upgrade the TF state.

PR: [#140](https://github.com/jfrog/terraform-provider-xray/pull/140)
Issue: [#138](https://github.com/jfrog/terraform-provider-xray/issues/138)

## 1.18.0 (September 26, 2023). Tested on Artifactory 7.68.11 and Xray 3.82.11

FEATURES:

* resource/xray_webhook: add a new resource allowing webhook to be managed.

PR: [#139](https://github.com/jfrog/terraform-provider-xray/pull/139)
Issue: [#7](https://github.com/jfrog/terraform-provider-xray/issues/7)

## 1.17.1 (September 15, 2023). Tested on Artifactory 7.68.7 and Xray 3.82.6

IMPROVEMENTS:

* resource/xray_watch: replace potentially unsafe string intepolation with struct marshalling.

PR: [#137](https://github.com/jfrog/terraform-provider-xray/pull/137)

## 1.17.0 (September 13, 2023). Tested on Artifactory 7.68.7 and Xray 3.82.6

FEATURES:

* resource/xray_custom_issue: add a new resource allowing custom issue event to be managed.

PR: [#136](https://github.com/jfrog/terraform-provider-xray/pull/136)
Issue: [#123](https://github.com/jfrog/terraform-provider-xray/issues/123)

## 1.16.0 (September 7, 2023). Tested on Artifactory 7.63.14 and Xray 3.81.8

IMPROVEMENTS:

* resource/xray_repository_config: added validation to ensure either `config` or `path_config` attribute is defined. 

PR: [#135](https://github.com/jfrog/terraform-provider-xray/pull/135)
Issue: [#134](https://github.com/jfrog/terraform-provider-xray/issues/134)

## 1.15.0 (August 29, 2023). Tested on Artifactory 7.63.14 and Xray 3.80.9

BUG FIXES:

* resource/xray_repository_config: added `exposures` to `config` to support JFrog Advanced Security scanning. 

PR: [#133](https://github.com/jfrog/terraform-provider-xray/pull/133)

## 1.14.2 (July 24, 2023). Tested on Artifactory 7.63.5 and Xray 3.78.10

BUG FIXES:

* resource/xray_watch: added `path-regex` filter type for Xray watch. 

PR: [#132](https://github.com/jfrog/terraform-provider-xray/pull/132)
Issue: [#127](https://github.com/jfrog/terraform-provider-xray/issues/127)

## 1.14.1 (July 18, 2023). Tested on Artifactory 7.63.5 and Xray 3.78.10

BUG FIXES:

* resource/xray_ignore_rule: removed restriction, so the ignore rule can be created for both a policy and a watch.

PR: [#131](https://github.com/jfrog/terraform-provider-xray/pull/131)
Issue: [#130](https://github.com/jfrog/terraform-provider-xray/issues/130)

## 1.14.0 (June 1, 2023). Tested on Artifactory 7.59.9 and Xray 3.74.8

IMPROVEMENTS:

* resource/xray_*_policy: `actions` is a required block now. Also, changed default behavior for `actions` nested boolean attributes to match the Xray UI behavior. 
* resource/xray_license_policy: removed license name verification from `banned_licenses` and `allowed_licenses` lists to allow users enter custom licenses, created in their Xray instance. Please note, Xray API doesn't verify if the license (custom or not) exists, so if the user enters a non-existing license name, this policy will be created but won't trigger a violation. 

PR: [#122](https://github.com/jfrog/terraform-provider-xray/pull/122)
Issues: [#120](https://github.com/jfrog/terraform-provider-xray/issues/120), [#121](https://github.com/jfrog/terraform-provider-xray/issues/121)

## 1.13.0 (April 19, 2023). Tested on Artifactory 7.55.10 and Xray 3.71.6

IMPROVEMENTS:

* resource/xray_security_policy: added new security policy rule criteria `exposures`, which allows to create a policy with criteria type Exposures and include specific exposures. Works only with [JFrog Advanced Security](https://jfrog.com/advanced-security/) license, otherwise the block will be ignored by API.
 PR: [#118](https://github.com/jfrog/terraform-provider-xray/pull/118)

## 1.12.0 (April 11, 2023). Tested on Artifactory 7.55.10 and Xray 3.69.3

IMPROVEMENTS:

* resource/xray_security_policy: added new security policy rule criteria `vulnerability_ids`, which allows to create a policy with criteria type Vulnerabilities and include a list of a specific CVEs.
 Issue: [#112](https://github.com/jfrog/terraform-provider-xray/issues/112)
 PR: [#116](https://github.com/jfrog/terraform-provider-xray/pull/116)

## 1.11.1 (March 28, 2023). Tested on Artifactory 7.55.9 and Xray 3.69.3

IMPROVEMENTS:
* `project_key` attribute validation for all the resources has been changed to match Artifactory requirements since 7.56.2 - the length should be between 2-32 characters.
  PR: [#113](https://github.com/jfrog/terraform-provider-xray/pull/113)

## 1.11.0 (March 22, 2023). Tested on Artifactory 7.55.8 and Xray 3.69.3

IMPROVEMENTS:
* resource/xray_security_policy: added new attribute `malicious_package`. It allows to create a violation on any malicious package detected.
 Issue: [#109](https://github.com/jfrog/terraform-provider-xray/issues/109)
 PR: [#111](https://github.com/jfrog/terraform-provider-xray/pull/111)

## 1.10.0 (March 16, 2023). Tested on Artifactory 7.55.7 and Xray 3.67.9

IMPROVEMENTS:
* resource/xray_watch: Added support for `mime-type` to text filter. Added new filter type `kv_filter` to support "property" filter with key/value.
  Issue: [#107](https://github.com/jfrog/terraform-provider-xray/issues/107)
  PR: [#108](https://github.com/jfrog/terraform-provider-xray/pull/108)

## 1.9.11 (February 27, 2023). Tested on Artifactory 7.55.2 and Xray 3.67.9

IMPROVEMENTS:
* resource/xray_ignore_rule, resource/xray_*_policy, resource/xray_watch, resource/xray_repository_config, resource/xray_settings: updated documentation to include importing resource which has been supported previously.
* resource/xray_*_policy, resource/xray_watch: added `project_key` parsing for importing
* provider: Update golang.org/x/net module to latest version. Dependabot alerts: [3](https://github.com/jfrog/terraform-provider-xray/security/dependabot/3), [4](https://github.com/jfrog/terraform-provider-xray/security/dependabot/4)

PR: [#105](https://github.com/jfrog/terraform-provider-xray/pull/105)

## 1.9.10 (February 10, 2023). Tested on Artifactory 7.49.6 and Xray 3.66.6

BUG FIXES:

* resource/xray_watch: added missing support for `operational_risk` policy types.
  Issue [#103](https://github.com/jfrog/terraform-provider-xray/issues/103)
  PR [#104](https://github.com/jfrog/terraform-provider-xray/pull/104)

## 1.9.9 (January 31, 2023). Tested on Artifactory 7.49.6 and Xray 3.65.3

IMPROVEMENTS:

* added import instructions to all the provider resources.
 Issue [#101](https://github.com/jfrog/terraform-provider-xray/issues/101)
 PR [#102](https://github.com/jfrog/terraform-provider-xray/pull/102) 

## 1.9.8 (January 19, 2023). Tested on Artifactory 7.49.5 and Xray 3.65.2

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
