---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "xray_watch Resource - terraform-provider-xray"
subcategory: ""
description: |-
  Provides an Xray watch resource.
---

# xray_watch (Resource)

Provides an Xray watch resource.

## Example Usage

```terraform
resource "xray_watch" "all-repos" {
  name        = "all-repos-watch"
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
  name        = "repository-watch"
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
  name        = "build-watch"
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

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **assigned_policy** (Block List, Min: 1) Nested argument describing policies that will be applied. Defined below. (see [below for nested schema](#nestedblock--assigned_policy))
- **name** (String) Name of the watch (must be unique)
- **watch_resource** (Block List, Min: 1) Nested argument describing the resources to be watched. Defined below. (see [below for nested schema](#nestedblock--watch_resource))

### Optional

- **active** (Boolean) Whether or not the watch will be active
- **description** (String) Description of the watch
- **id** (String) The ID of this resource.
- **watch_recipients** (List of String) A list of email addressed that will get emailed when a violation is triggered.

<a id="nestedblock--assigned_policy"></a>
### Nested Schema for `assigned_policy`

Required:

- **name** (String) The name of the policy that will be applied
- **type** (String) The type of the policy


<a id="nestedblock--watch_resource"></a>
### Nested Schema for `watch_resource`

Required:

- **type** (String) Type of resource to be watched. Options: `all-repos`, `repository`, `build`, `project`, `all-projects`.

Optional:

- **bin_mgr_id** (String) The ID number of a binary manager resource. Should be set to `default` if not set on the Artifactory side.
- **filter** (Block List) Nested argument describing filters to be applied. Defined below. (see [below for nested schema](#nestedblock--watch_resource--filter))
- **name** (String) The name of the build or repository. Enable Xray indexing must be enabled on the repo or build

<a id="nestedblock--watch_resource--filter"></a>
### Nested Schema for `watch_resource.filter`

Required:

- **type** (String) The type of filter, such as `regex`, `package-type` or `ant-patterns`
- **value** (String) The value of the filter, such as the text of the regex or name of the package type.

