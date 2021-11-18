package xray

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWatchAllRepos() *schema.Resource {
	var watchAllReposSchema = mergeSchema(baseWatchSchema, map[string]*schema.Schema{
		"resources": {
			Type:     schema.TypeList,
			Required: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"type": {
						Type:     schema.TypeString,
						Required: true,
					},
					"filters": {
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
	})

	type WatchFilter struct {
		Type  string `json:"type,omitempty"`
		Value string `json:"value,omitempty"`
	}

	type WatchProjectResourcesResource struct {
		Type    string         `hcl:"type" json:"type,omitempty"`
		Filters *[]WatchFilter `hcl:"filters" json:"filters,omitempty"`
	}

	type WatchProjectResource struct {
		Resources []WatchProjectResourcesResource
	}

	type WatchAllRepoResource struct {
		Watch
		ProjectResouces *WatchProjectResource
	}

	var unPackXrayWatchAllRepos = func(data *schema.ResourceData) (interface{}, string, error) {
		d := &ResourceData{data}

		watch := WatchGeneralData{
			Name:        d.getString("type", false),
			Description: d.getString("description", false),
			Active:      d.getBoolRef("active", false),
		}

		return watch, watch.Id(), nil
	}

	return mkResourceSchema(watchAllReposSchema, universalPack(schemaHasKey(watchAllReposSchema)),
		unPackXrayWatchAllRepos, func() interface{} {
			return &WatchProjectResource{}
		})

}
