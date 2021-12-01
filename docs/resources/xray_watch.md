# Xray Watch Resource

Provides a Xray watch resource.

## Example Usage

```hcl
# Create a new Xray watch for all repositories, assign policies
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
```
```hcl
# Create a new Xray watch for a set of repositories, assign policies
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
```

```hcl
# Create a new Xray watch for a set of builds, assign policies
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

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the watch (must be unique)
* `description` - (Optional) Description of the watch
* `active` - (Optional) Whether or not the watch will be active
* `watch_resource` - (Required) Nested argument describing the resources to be watched. Defined below.
* `assigned_policy` - (Required) Nested argument describing policies that will be applied. Defined below.

### watch_resource

The top-level `watch_resource` block contains a resource object that supports the following:

* `type` - (Required) Type of resource to be watched. Options: `all-repos`, `repository`, `build`, `project`, `all-projects`.
* `bin_mgr_id` - (Optional) The ID number of a binary manager resource. `default` if not set on the Artifactory side.
* `name` - (Required) A name describing the resource.
* `filter` - (Optional) Nested argument describing filters to be applied. Defined below.

Multiple blocks supported.

#### filter

The nested `filters` block contains a filter to be applied, supports the following:

* `type` - (Required) The type of filter, such as `regex` or `package-type`
* `value` - (Required) The value of the filter, such as the text of the regex or name of the package type.

Multiple blocks supported.

### assigned_policy

The top-level `assigned_policy` block contains a policy objects that support the following:

* `name` - (Required) The name of the policy that will be applied
* `type` - (Required) The type of the policy

Multiple blocks supported.

## Import

Watches can be imported using their name, e.g.

```
$ terraform import xray_watch.example watch-name
```
