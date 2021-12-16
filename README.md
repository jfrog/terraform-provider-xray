# Terraform Provider Xray

[![Actions Status](https://github.com/jfrog/terraform-provider-xray/workflows/release/badge.svg)](https://github.com/jfrog/terraform-provider-xray/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/jfrog/terraform-provider-xray)](https://goreportcard.com/report/github.com/jfrog/terraform-provider-xray)

To use this provider in your Terraform module, follow the documentation [here](https://registry.terraform.io/providers/jfrog/xray/latest/docs).
[Xray general information](https://jfrog.com/xray/)
[Xray API Documentation](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API)

## Release notes for v0.0.1
Xray provider was separated from Artifactory provider. The most notable differences in the new Xray provider: 
- Provider uses Xray API v2 for all the API calls.
- HCL was changed and now uses singular names instead of the plurals for the repeatable elements, like `rule`, `watch_resource`, `filter` and `assigned_policy`.
- Security policy and License policy now are separate Terraform provider resources.
- In Schemas, TypeList was replaced by TypeSet (where it makes sense) to avoid sorting problems, when Terraform detect the change in sorted elements.
- Added multiple validations for Schemas to verify the data on the Terraform level instead of getting errors in the API response.


## License requirements:
This provider requires Xray to be added to your Artifactory installation. 
Xray requires minimum Pro Team license (Public Marketplace version or SaaS) or Pro X license (Self-hosted).
See the details [here](https://jfrog.com/pricing/#sass)
You can determine which license you have by accessing the following Artifactory URL `${host}/artifactory/api/system/licenses/`

## Limitations of functionality
Currently, Xray provider is not supporting JSON objects in the Watch filter value. We are working on adding this functionality. 


## Build the Provider
Simply run `make install` - this will compile the provider and install it to `~/.terraform.d`. When running this, it will
take the current tag and bump it 1 minor version. It does not actually create a new tag (that is `make release`).
If you wish to use the locally installed provider, make sure your TF script refers to the new version number.

Requirements:
- [Terraform](https://www.terraform.io/downloads.html) 0.13
- [Go](https://golang.org/doc/install) 1.15+ (to build the provider plugin)

## Testing
Since JFrog Xray is an addon for Artifactory, you will need a running instance of the JFrog platform (Artifactory and Xray).
However, there is no currently supported dockerized, local version. The fastest way to install Artifactory and Xray as a self-hosted installation is to use Platform
Helm chart. Free 30 days trial version is available [here](https://jfrog.com/start-free/#hosted) 
If you want to test on SaaS instance - [30 day trial can be freely obtained](https://jfrog.com/start-free/#saas) 
and will allow local development. 

Then, you have to set some environment variables as this is how the acceptance tests pick up their config:
```bash
JFROG_URL=http://localhost:8081
XRAY_ACCESS_TOKEN=your-admin-key
TF_ACC=true
```
a crucial, and very much hidden, env var to set is
`TF_ACC=true` - you can literally set `TF_ACC` to anything you want, so long as it's set. The acceptance tests use
terraform testing libraries that, if this flag isn't set, will skip all tests.

`XRAY_ACCESS_TOKEN` can be generated in the UI. Go to **Settings -> Identity and Access -> Access Tokens -> Generate Admin Token**


You can then run the tests as `make acceptance`. You can check what it's doing on the background in the [GNUmakefile](GNUmakefile) in the project. 

We've found that it's very convenient to use [Charles proxy](https://www.charlesproxy.com/) to see the payload, generated by Terraform Provider during the testing process.
You can also use any other network packet reader, like Wireshark and so on. 


## Documentation generation
All the documentation in the project is generated by [tfplugindocs](https://github.com/hashicorp/terraform-plugin-docs).
If you make any changes to the resource schemas, you will need to re-generate documentation. For this purpose you can run `go generate` or install 
**tfplugindocs**, as described in the [project documentation](https://github.com/hashicorp/terraform-plugin-docs#installation).

## Versioning
In general, this project follows [semver](https://semver.org/) as closely as we
can for tagging releases of the package. We've adopted the following versioning policy:

* We increment the **major version** with any incompatible change to
  functionality, including changes to the exported Go API surface
  or behavior of the API.
* We increment the **minor version** with any backwards-compatible changes to
  functionality.
* We increment the **patch version** with any backwards-compatible bug fixes.

## Contributors
Pull requests, issues and comments are welcomed. For pull requests:

* Add tests for new features and bug fixes
* Follow the existing style
* Separate unrelated changes into multiple pull requests

See the existing issues for things to start contributing.

For bigger changes, make sure you start a discussion first by creating
an issue and explaining the intended change.

JFrog requires contributors to sign a Contributor License Agreement,
known as a CLA. This serves as a record stating that the contributor is
entitled to contribute the code/documentation/translation to the project
and is willing to have it used in distributions and derivative works
(or is willing to transfer ownership).

[Sign the CLA](https://cla-assistant.io/jfrog/terraform-provider-xray)

## License
Copyright (c) 2021 JFrog.

Apache 2.0 licensed, see [LICENSE](LICENSE) file.