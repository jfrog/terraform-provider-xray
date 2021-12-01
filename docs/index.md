# JFrog Xray Provider

The [Xray](https://jfrog.com/xray/) provider is used to interact with the
resources supported by JFrog Xray. Xray is a part of JFrog Artifactory and can't be used separately.
The provider needs to be configured with the proper credentials before it can be used.

Xray API documentation can be found [here](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API)

This provider requires access to Artifactory and Xray APIs, which are only available in the _licensed_ pro and enterprise editions.
You can determine which license you have by accessing the following URL
`${host}/artifactory/api/system/licenses/`

You can either access it via api, or web browser - it does require admin level credentials, but it's one of the few
APIs that will work without a license (side node: you can also install your license here with a `POST`)

```bash
curl -sL ${host}/artifactory/api/system/licenses/ | jq .
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

## Authentication
The Xray provider supports only Bearer Token authentication. 

### Bearer Token
Artifactory access tokens may be used via the Authorization header by providing the `access_token` field to the provider
block. Getting this value from the environment is supported with the `ARTIFACTORY_ACCESS_TOKEN`, `XRAY_ACCESS_TOKEN`,
or `JFROG_ACCESS_TOKEN` variables.
Set `url` field to provide JFrog Xray URL. Alternatively you can set `ARTIFACTORY_URL`, `JFROG_URL` or `PROJECTS_URL` variables.

Usage:
```hcl
# Configure the Xray provider
provider "xray" {
  url = "artifactory.site.com/artifactory"
  access_token = "abc...xy"
}
```

## Argument Reference

The following arguments are supported:

* `url` - (Required) URL of Artifactory. This can also be sourced from the `ARTIFACTORY_URL`, `JFROG_URL` or `PROJECTS_URL` environment variables.
* `access_token` - (Optional) This is a bearer token that can be given to you by your admin under `Identity and Access`.
For Xray functionality, this is the only auth method accepted. This can also be sourced from the `ARTIFACTORY_ACCESS_TOKEN`, `XRAY_ACCESS_TOKEN`,
  or `JFROG_ACCESS_TOKEN` environment variables.
