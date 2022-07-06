package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
	"golang.org/x/exp/slices"
)

type WatchGeneralData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

type WatchFilter struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type WatchFilterAntValue struct {
	ExcludePatterns []string `json:"ExcludePatterns"`
	IncludePatterns []string `json:"IncludePatterns"`
}

type WatchProjectResource struct {
	Type            string        `json:"type"`
	BinaryManagerId string        `json:"bin_mgr_id"`
	Filters         []WatchFilter `json:"filters"`
	Name            string        `json:"name"`
	RepoType        string        `json:"repo_type,omitempty"`
}

type WatchProjectResources struct {
	Resources []WatchProjectResource `json:"resources"`
}

type WatchAssignedPolicy struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Watch struct {
	GeneralData      WatchGeneralData      `json:"general_data"`
	ProjectResources WatchProjectResources `json:"project_resources"`
	AssignedPolicies []WatchAssignedPolicy `json:"assigned_policies"`
	WatchRecipients  []string              `json:"watch_recipients"`
}

func unpackWatch(d *schema.ResourceData) Watch {
	watch := Watch{}

	gd := WatchGeneralData{
		Name: d.Get("name").(string),
	}
	if v, ok := d.GetOk("description"); ok {
		gd.Description = v.(string)
	}
	if v, ok := d.GetOk("active"); ok {
		gd.Active = v.(bool)
	}
	watch.GeneralData = gd

	pr := WatchProjectResources{}
	if v, ok := d.GetOk("watch_resource"); ok {
		var r []WatchProjectResource
		for _, res := range v.(*schema.Set).List() {
			r = append(r, unpackProjectResource(res))
		}
		pr.Resources = r
	}
	watch.ProjectResources = pr

	var ap []WatchAssignedPolicy
	if v, ok := d.GetOk("assigned_policy"); ok {
		policies := v.(*schema.Set).List()
		for _, pol := range policies {
			ap = append(ap, unpackAssignedPolicy(pol))
		}
	}
	watch.AssignedPolicies = ap

	var watchRecipients []string

	if v, ok := d.GetOk("watch_recipients"); ok {
		recipients := v.(*schema.Set).List()
		for _, watchRec := range recipients {
			watchRecipients = append(watchRecipients, watchRec.(string))
		}
	}
	watch.WatchRecipients = watchRecipients

	return watch
}

func unpackProjectResource(rawCfg interface{}) WatchProjectResource {
	resource := WatchProjectResource{}

	cfg := rawCfg.(map[string]interface{})
	resource.Type = cfg["type"].(string)

	if v, ok := cfg["bin_mgr_id"]; ok {
		resource.BinaryManagerId = v.(string)
	}

	if v, ok := cfg["name"]; ok {
		resource.Name = v.(string)
	}

	if v, ok := cfg["repo_type"]; ok {
		resource.RepoType = v.(string)
	}

	if v, ok := cfg["filter"]; ok {
		filters := unpackFilters(v.(*schema.Set))
		resource.Filters = append(resource.Filters, filters...)
	}

	if v, ok := cfg["ant_filter"]; ok {
		antFilters := unpackAntFilters(v.(*schema.Set))
		resource.Filters = append(resource.Filters, antFilters...)
	}

	return resource
}

func unpackFilters(d *schema.Set) []WatchFilter {
	tfFilters := d.List()

	var filters []WatchFilter

	for _, raw := range tfFilters {
		f := raw.(map[string]interface{})
		filter := WatchFilter{
			Type:  f["type"].(string),
			Value: json.RawMessage(strconv.Quote(f["value"].(string))),
		}
		filters = append(filters, filter)
	}

	return filters
}

func unpackAntFilters(d *schema.Set) []WatchFilter {
	tfFilters := d.List()

	var filters []WatchFilter

	for _, raw := range tfFilters {
		antValue := raw.(map[string]interface{})

		// create JSON string from slice:
		// from []string{"a", "b"} to `["ExcludePatterns": ["a", "b"]]`
		excludePatterns, _ := json.Marshal(util.CastToStringArr(antValue["exclude_patterns"].([]interface{})))
		includePatterns, _ := json.Marshal(util.CastToStringArr(antValue["include_patterns"].([]interface{})))
		filterJsonString := fmt.Sprintf(
			`{"ExcludePatterns": %s, "IncludePatterns": %s}`,
			excludePatterns,
			includePatterns,
		)

		filter := WatchFilter{
			Type:  "ant-patterns",
			Value: json.RawMessage(filterJsonString),
		}
		filters = append(filters, filter)
	}

	return filters
}

func unpackAssignedPolicy(rawCfg interface{}) WatchAssignedPolicy {
	policy := WatchAssignedPolicy{}

	cfg := rawCfg.(map[string]interface{})
	policy.Name = cfg["name"].(string)
	policy.Type = cfg["type"].(string)

	return policy
}

func packProjectResources(ctx context.Context, resources WatchProjectResources) []interface{} {
	var list []interface{}
	for _, res := range resources.Resources {
		resourceMap := map[string]interface{}{}
		resourceMap["type"] = res.Type
		if len(res.Name) > 0 {
			resourceMap["name"] = res.Name
		}
		if len(res.BinaryManagerId) > 0 {
			resourceMap["bin_mgr_id"] = res.BinaryManagerId
		}
		if len(res.RepoType) > 0 {
			resourceMap["repo_type"] = res.RepoType
		}

		resourceMap, errors := packFilters(res.Filters, resourceMap)
		if len(errors) > 0 {
			tflog.Error(ctx, fmt.Sprintf(`failed to pack filters: %v`, errors))
		}

		list = append(list, resourceMap)
	}

	return list
}

type PackFilterFunc func(filter WatchFilter) (map[string]interface{}, error)

func packStringFilter(filter WatchFilter) (map[string]interface{}, error) {
	var value string
	err := json.Unmarshal(filter.Value, &value)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"type":  filter.Type,
		"value": value,
	}, nil
}

func packAntFilter(filter WatchFilter) (map[string]interface{}, error) {
	var value WatchFilterAntValue
	err := json.Unmarshal(filter.Value, &value)
	m := map[string]interface{}{
		"exclude_patterns": value.ExcludePatterns,
		"include_patterns": value.IncludePatterns,
	}
	return m, err
}

var packFilterMap = map[string]map[string]interface{}{
	"regex": map[string]interface{}{
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"package-type": map[string]interface{}{
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"ant-patterns": map[string]interface{}{
		"func":          packAntFilter,
		"attributeName": "ant_filter",
	},
}

func packFilters(filters []WatchFilter, resources map[string]interface{}) (map[string]interface{}, []error) {
	resources["filter"] = []map[string]interface{}{}
	resources["ant_filter"] = []map[string]interface{}{}
	var errors []error

	for _, filter := range filters {
		packFilterAttribute, ok := packFilterMap[filter.Type]
		if !ok {
			return nil, []error{fmt.Errorf("invalid filter.Type: %s", filter.Type)}
		}

		packedFilter, err := packFilterAttribute["func"].(func(WatchFilter) (map[string]interface{}, error))(filter)
		if err != nil {
			errors = append(errors, err)
		} else {
			attributeName := packFilterAttribute["attributeName"].(string)
			resources[attributeName] = append(resources[attributeName].([]map[string]interface{}), packedFilter)
		}
	}

	return resources, errors
}

func packAssignedPolicies(policies []WatchAssignedPolicy) []interface{} {
	var l []interface{}
	for _, p := range policies {
		m := map[string]interface{}{
			"name": p.Name,
			"type": p.Type,
		}
		l = append(l, m)
	}

	return l
}

func packWatch(ctx context.Context, watch Watch, d *schema.ResourceData) diag.Diagnostics {
	if err := d.Set("description", watch.GeneralData.Description); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("active", watch.GeneralData.Active); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("watch_resource", packProjectResources(ctx, watch.ProjectResources)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("assigned_policy", packAssignedPolicies(watch.AssignedPolicies)); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func getWatch(id string, client *resty.Client) (Watch, *resty.Response, error) {
	watch := Watch{}
	resp, err := client.R().SetResult(&watch).Get("xray/api/v2/watches/" + id)
	return watch, resp, err
}

func resourceXrayWatchCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := unpackWatch(d)
	_, err := m.(*resty.Client).R().SetBody(watch).Post("xray/api/v2/watches")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(watch.GeneralData.Name)
	return resourceXrayWatchRead(ctx, d, m)
}

func resourceXrayWatchRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch, resp, err := getWatch(d.Id(), m.(*resty.Client))
	if err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, fmt.Sprintf("Xray watch (%s) not found, removing from state", d.Id()))
			d.SetId("")
		}
		return diag.FromErr(err)
	}
	packWatch(ctx, watch, d)
	return nil
}

func resourceXrayWatchUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := unpackWatch(d)
	resp, err := m.(*resty.Client).R().SetBody(watch).Put("xray/api/v2/watches/" + d.Id())
	if err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, fmt.Sprintf("Xray watch (%s) not found, removing from state", d.Id()))
			d.SetId("")
		}
		return diag.FromErr(err)
	}

	d.SetId(watch.GeneralData.Name)
	return resourceXrayWatchRead(ctx, d, m)
}

func resourceXrayWatchDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	resp, err := m.(*resty.Client).R().Delete("xray/api/v2/watches/" + d.Id())
	if err != nil && resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return diag.FromErr(err)
	}
	return nil
}

func watchResourceDiff(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
	watchResources := diff.Get("watch_resource").(*schema.Set).List()
	if len(watchResources) == 0 {
		return nil
	}
	for _, watchResource := range watchResources {
		r := watchResource.(map[string]interface{})
		resourceType := r["type"].(string)

		// validate repo_type
		repoType := r["repo_type"].(string)
		if resourceType == "repository" && len(repoType) == 0 {
			return fmt.Errorf("attribute 'repo_type' not set when 'watch_resource.type' is set to 'repository'")
		}

		// validate type with filter and ant_filter
		antFilters := r["ant_filter"].(*schema.Set).List()
		antPatternsResourceTypes := []string{"all-builds", "all-projects"}
		if !slices.Contains(antPatternsResourceTypes, resourceType) && len(antFilters) > 0 {
			return fmt.Errorf("attribute 'ant_filter' is set when 'watch_resource.type' is not set to 'all-builds' or 'all-projects'")
		}
	}
	return nil
}
