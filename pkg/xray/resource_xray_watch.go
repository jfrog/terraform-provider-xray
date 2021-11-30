package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceXrayWatch() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceXrayWatchCreate,
		ReadContext:   resourceXrayWatchRead,
		UpdateContext: resourceXrayWatchUpdate,
		DeleteContext: resourceXrayWatchDelete,
		Description:   "Create a watch for all the repos using the filter",

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"active": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"resource": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"bin_mgr_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"name": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The name of the repository. Enable Xray indexing must be enabled on the repo",
						},
						"filter": { // Plural replaced for the HCL sake
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Required: true,
									},
									// TODO this can be either a string or possibly a json blob
									// eg "value":{"ExcludePatterns":[],"IncludePatterns":["*"]}
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			// "assigned_policies" in the API call body. Plural is replaced in lue of better reflection of the
			// actual functionality (see HCL examples)
			"assigned_policy": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},

			"watch_recipients": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}
