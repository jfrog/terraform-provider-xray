package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the watch (must be unique)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the watch",
			},
			"active": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether or not the watch will be active",
			},
			"watch_resource": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Nested argument describing the resources to be watched. Defined below.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "Type of resource to be watched. Options: `all-repos`, `repository`, `build`, `project`, `all-projects`.",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"all-repos", "repository", "build", "project", "all-projects"}, true)),
						},
						"bin_mgr_id": {
							Type:        schema.TypeString,
							Optional:    true,
							Default:     "default",
							Description: "The ID number of a binary manager resource. Should be set to `default` if not set on the Artifactory side.",
						},
						"name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The name of the build or repository. Enable Xray indexing must be enabled on the repo or build",
						},
						"filter": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Nested argument describing filters to be applied. Defined below.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:             schema.TypeString,
										Required:         true,
										Description:      "The type of filter, such as `regex`, `package-type` or `ant-patterns`",
										ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"regex", "package-type", "ant-patterns"}, true)),
									},
									// TODO support Exclude and Include patterns
									// eg "value":{"ExcludePatterns":[],"IncludePatterns":["*"]}
									"value": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "The value of the filter, such as the text of the regex or name of the package type.",
									},
								},
							},
						},
					},
				},
			},
			// "assigned_policies" in the API call body. Plural is replaced for better reflection of the
			// actual functionality (see HCL examples)
			"assigned_policy": {
				Type:        schema.TypeList,
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
							Description:      "The type of the policy",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"security", "license"}, true)),
						},
					},
				},
			},
			"watch_recipients": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "A list of email addressed that will get emailed when a violation is triggered.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validateIsEmail,
				},
			},
		},
	}
}
