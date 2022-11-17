package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func resourceXrayWatch() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceXrayWatchCreate,
		ReadContext:   resourceXrayWatchRead,
		UpdateContext: resourceXrayWatchUpdate,
		DeleteContext: resourceXrayWatchDelete,
		Description:   "Provides an Xray watch resource.",

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		CustomizeDiff: watchResourceDiff,

		Schema: util.MergeMaps(
			getProjectKeySchema(false, "Support repository and build watch resource types. When specifying individual repository or build they must be already assigned to the project. Build must be added as indexed resources."),
			map[string]*schema.Schema{
				"name": {
					Type:             schema.TypeString,
					Required:         true,
					ForceNew:         true,
					Description:      "Name of the watch (must be unique)",
					ValidateDiagFunc: validator.StringIsNotEmpty,
				},
				"description": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Description of the watch",
				},
				"active": {
					Type:        schema.TypeBool,
					Optional:    true,
					Description: "Whether or not the watch is active",
				},
				"watch_resource": {
					Type:        schema.TypeSet,
					Required:    true,
					Description: "Nested argument describing the resources to be watched. Defined below.",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"type": {
								Type:             schema.TypeString,
								Required:         true,
								Description:      "Type of resource to be watched. Options: `all-repos`, `repository`, `all-builds`, `build`, `project`, `all-projects`.",
								ValidateDiagFunc: validator.StringInSlice(true, "all-repos", "repository", "all-builds", "build", "project", "all-projects"),
							},
							"bin_mgr_id": {
								Type:        schema.TypeString,
								Optional:    true,
								Default:     "default",
								Description: "The ID number of a binary manager resource. Default value is `default`. To check the list of available binary managers, use the API call `${JFROG_URL}/xray/api/v1/binMgr` as an admin user, use `binMgrId` value. More info [here](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-GetBinaryManager)",
							},
							"name": {
								Type:        schema.TypeString,
								Optional:    true,
								Description: "The name of the build, repository or project. Xray indexing must be enabled on the repository or build",
							},
							"repo_type": {
								Type:             schema.TypeString,
								Optional:         true,
								ValidateDiagFunc: validator.StringInSlice(true, "local", "remote"),
								Description:      "Type of repository. Only applicable when `type` is `repository`. Options: `local` or `remote`.",
							},
							"filter": {
								Type:        schema.TypeSet,
								Optional:    true,
								MinItems:    1,
								Description: "Filter for `regex` and `package-type` type. Works only with `all-repos` watch_resource.type.",
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"type": {
											Type:             schema.TypeString,
											Required:         true,
											Description:      "The type of filter, such as `regex` or `package-type`",
											ValidateDiagFunc: validator.StringInSlice(true, "regex", "package-type"),
										},
										"value": {
											Type:             schema.TypeString,
											Required:         true,
											Description:      "The value of the filter, such as the text of the regex or name of the package type.",
											ValidateDiagFunc: validator.StringIsNotEmpty,
										},
									},
								},
							},
							"ant_filter": {
								Type:        schema.TypeSet,
								Optional:    true,
								MinItems:    1,
								Description: "`ant-patterns` filter for `all-builds` and `all-projects` watch_resource.type",
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"include_patterns": {
											Type: schema.TypeList,
											Elem: &schema.Schema{
												Type: schema.TypeString,
											},
											Optional:    true,
											Description: "Use Ant-style wildcard patterns to specify build names (i.e. artifact paths) in the build info repository (without a leading slash) that will be included in this watch. Projects are supported too. Ant-style path expressions are supported (*, **, ?). For example, an 'apache/**' pattern will include the 'apache' build info in the watch.",
										},
										"exclude_patterns": {
											Type: schema.TypeList,
											Elem: &schema.Schema{
												Type: schema.TypeString,
											},
											Optional:    true,
											Description: "Use Ant-style wildcard patterns to specify build names (i.e. artifact paths) in the build info repository (without a leading slash) that will be excluded in this watch. Projects are supported too. Ant-style path expressions are supported (*, **, ?). For example, an 'apache/**' pattern will exclude the 'apache' build info in the watch.",
										},
									},
								},
							},
							"path_ant_filter": {
								Type:        schema.TypeSet,
								Optional:    true,
								MinItems:    1,
								Description: "`path-ant-patterns` filter for `repository` and `all-repos` watch_resource.type",
								Elem: &schema.Resource{
									Schema: map[string]*schema.Schema{
										"include_patterns": {
											Type: schema.TypeList,
											Elem: &schema.Schema{
												Type: schema.TypeString,
											},
											Optional:    true,
											Description: "The pattern will apply to the selected repositories. Simple comma separated wildcard patterns for repository artifact paths (with no leading slash). Ant-style path expressions are supported (*, **, ?). For example: 'org/apache/**'",
										},
										"exclude_patterns": {
											Type: schema.TypeList,
											Elem: &schema.Schema{
												Type: schema.TypeString,
											},
											Optional:    true,
											Description: "The pattern will apply to the selected repositories. Simple comma separated wildcard patterns for repository artifact paths (with no leading slash). Ant-style path expressions are supported (*, **, ?). For example: 'org/apache/**'",
										},
									},
								},
							},
						},
					},
				},
				// Key is "assigned_policies" in the API call body. Plural is used for better reflection of the
				// actual functionality (see HCL examples)
				"assigned_policy": {
					Type:        schema.TypeSet,
					Required:    true,
					Description: "Nested argument describing policies that will be applied. Defined below.",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name": {
								Type:        schema.TypeString,
								Required:    true,
								Description: "The name of the policy that will be applied",
							},
							"type": {
								Type:             schema.TypeString,
								Required:         true,
								Description:      "The type of the policy - security or license",
								ValidateDiagFunc: validator.StringInSlice(true, "security", "license"),
							},
						},
					},
				},
				"watch_recipients": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "A list of email addressed that will get emailed when a violation is triggered.",
					Elem: &schema.Schema{
						Type:             schema.TypeString,
						ValidateDiagFunc: validator.IsEmail,
					},
				},
			},
		),
	}
}
