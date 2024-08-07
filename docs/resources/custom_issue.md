---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "xray_custom_issue Resource - terraform-provider-xray"
subcategory: ""
description: |-
  Provides an Xray custom issue event resource. See Xray Custom Issue https://jfrog.com/help/r/xray-how-to-formally-raise-an-issue-regarding-an-indexed-artifact and REST API https://jfrog.com/help/r/jfrog-rest-apis/issues for more details.
  ~>Due to JFrog Xray REST API behavior, when component.vulnerable_versions or component.fixed_versions are set, their values are mirrored in the component.vulnerable_ranges attribute, and vice versa. We recommend setting all the component attribute values to match to avoid state drift.
---

# xray_custom_issue (Resource)

Provides an Xray custom issue event resource. See [Xray Custom Issue](https://jfrog.com/help/r/xray-how-to-formally-raise-an-issue-regarding-an-indexed-artifact) and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/issues) for more details.

~>Due to JFrog Xray REST API behavior, when `component.vulnerable_versions` or `component.fixed_versions` are set, their values are mirrored in the `component.vulnerable_ranges` attribute, and vice versa. We recommend setting all the `component` attribute values to match to avoid state drift.

## Example Usage

```terraform
resource "xray_custom_issue" "my-issue-1" {
    name          = "my-issue-1"
    description   = "My custom issue"
    summary       = "My issue"
    type          = "security"
    provider_name = "custom"
    package_type  = "generic"
    severity      = "High"

    component {
        id                  = "aero:aero"
        vulnerable_versions = ["[0.2.3]"]
        vulnerable_ranges {
            vulnerable_versions = ["[0.2.3]"]
        }
    }

    cve {
        cve     = "CVE-2017-1000386"
        cvss_v2 = "2.4"
    }

    source {
        id = "CVE-2017-1000386"
    }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `description` (String) Description of custom issue
- `name` (String) Name of the custom issue. It must not begin with 'xray' (case insensitive)
- `package_type` (String) Package Type of custom issue. Valid values are: alpine, bower, cargo, composer, conan, conda, cran, debian, docker, generic, go, gradle, huggingface, ivy, maven, npm, nuget, oci, pypi, rpm, rubygems, sbt, terraformbe
- `provider_name` (String) Provider of custom issue. It must not be 'jfrog' (case insensitive)
- `severity` (String) Severity of custom issue. Valid values: Critical, High, Medium, Low, Information
- `summary` (String) Summary of custom issue
- `type` (String) Type of custom issue. Valid values: other, performance, security, versions

### Optional

- `component` (Block Set) Component of custom issue (see [below for nested schema](#nestedblock--component))
- `cve` (Block Set) CVE of the custom issue (see [below for nested schema](#nestedblock--cve))
- `source` (Block Set) List of sources (see [below for nested schema](#nestedblock--source))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--component"></a>
### Nested Schema for `component`

Required:

- `id` (String) ID of the component

Optional:

- `fixed_versions` (Set of String) List of fixed versions
- `vulnerable_ranges` (Block Set) List of the vulnerable ranges (see [below for nested schema](#nestedblock--component--vulnerable_ranges))
- `vulnerable_versions` (Set of String) List of vulnerable versions

<a id="nestedblock--component--vulnerable_ranges"></a>
### Nested Schema for `component.vulnerable_ranges`

Optional:

- `fixed_versions` (Set of String) List of fixed versions
- `vulnerable_versions` (Set of String) List of vulnerable versions



<a id="nestedblock--cve"></a>
### Nested Schema for `cve`

Optional:

- `cve` (String) CVE ID
- `cvss_v2` (String) CVSS v2 score
- `cvss_v3` (String) CVSS v3 score


<a id="nestedblock--source"></a>
### Nested Schema for `source`

Required:

- `id` (String) ID of the source, e.g. CVE

Optional:

- `name` (String) Name of the source
- `url` (String) URL of the source

## Import

Import is supported using the following syntax:

```shell
terraform import xray_custom_issue.my-issue-1 my-issue-1
```
