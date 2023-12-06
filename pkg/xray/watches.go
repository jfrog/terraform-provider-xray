package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
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

type WatchFilterKvValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type WatchProjectResource struct {
	Type            string        `json:"type"`
	BinaryManagerId string        `json:"bin_mgr_id"`
	Filters         []WatchFilter `json:"filters,omitempty"`
	Name            string        `json:"name,omitempty"`
	BuildRepo       string        `json:"build_repo,omitempty"`
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
	ProjectKey       string                `json:"-"`
	GeneralData      WatchGeneralData      `json:"general_data"`
	ProjectResources WatchProjectResources `json:"project_resources"`
	AssignedPolicies []WatchAssignedPolicy `json:"assigned_policies"`
	WatchRecipients  []string              `json:"watch_recipients"`
}

func unpackWatch(d *schema.ResourceData) Watch {
	watch := Watch{}

	if v, ok := d.GetOk("project_key"); ok {
		watch.ProjectKey = v.(string)
	}

	generalData := WatchGeneralData{
		Name: d.Get("name").(string),
	}
	if v, ok := d.GetOk("description"); ok {
		generalData.Description = v.(string)
	}
	if v, ok := d.GetOk("active"); ok {
		generalData.Active = v.(bool)
	}
	watch.GeneralData = generalData

	projectResources := WatchProjectResources{}
	if v, ok := d.GetOk("watch_resource"); ok {
		var r []WatchProjectResource
		for _, res := range v.(*schema.Set).List() {
			r = append(r, unpackProjectResource(res))
		}
		projectResources.Resources = r
	}
	watch.ProjectResources = projectResources

	var assignedPolicies []WatchAssignedPolicy
	if v, ok := d.GetOk("assigned_policy"); ok {
		policies := v.(*schema.Set).List()
		for _, pol := range policies {
			assignedPolicies = append(assignedPolicies, unpackAssignedPolicy(pol))
		}
	}
	watch.AssignedPolicies = assignedPolicies

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
		antFilters := unpackAntFilters(v.(*schema.Set), "ant-patterns")
		resource.Filters = append(resource.Filters, antFilters...)
	}

	if v, ok := cfg["path_ant_filter"]; ok {
		antFilters := unpackAntFilters(v.(*schema.Set), "path-ant-patterns")
		resource.Filters = append(resource.Filters, antFilters...)
	}

	if v, ok := cfg["kv_filter"]; ok {
		kvFilters := unpackKvFilters(v.(*schema.Set))
		resource.Filters = append(resource.Filters, kvFilters...)
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

func unpackAntFilters(d *schema.Set, filterType string) []WatchFilter {
	tfFilters := d.List()

	var filters []WatchFilter

	type antFilterValue struct {
		ExcludePatterns []string `json:"ExcludePatterns"`
		IncludePatterns []string `json:"IncludePatterns"`
	}

	for _, raw := range tfFilters {
		antValue := raw.(map[string]interface{})

		// create JSON string from slice:
		// from []string{"a", "b"} to `["ExcludePatterns": ["a", "b"]]`
		filterValue, _ := json.Marshal(
			&antFilterValue{
				ExcludePatterns: sdk.CastToStringArr(antValue["exclude_patterns"].([]interface{})),
				IncludePatterns: sdk.CastToStringArr(antValue["include_patterns"].([]interface{})),
			},
		)

		filter := WatchFilter{
			Type:  filterType,
			Value: json.RawMessage(filterValue),
		}
		filters = append(filters, filter)
	}

	return filters
}

func unpackKvFilters(d *schema.Set) []WatchFilter {
	tfFilters := d.List()

	var filters []WatchFilter

	for _, raw := range tfFilters {
		kv := raw.(map[string]interface{})

		filterJsonString := fmt.Sprintf(
			`{"key": "%s", "value": "%s"}`,
			kv["key"].(string),
			kv["value"].(string),
		)

		filter := WatchFilter{
			Type:  kv["type"].(string),
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

var allTypes = []string{"all-repos", "all-builds", "all-projects"}

func packProjectResources(ctx context.Context, resources WatchProjectResources) []interface{} {
	var resourceMaps []interface{}

	for _, res := range resources.Resources {
		resourceMap := map[string]interface{}{}
		resourceMap["type"] = res.Type
		// only pack watch resource name if type isn't for all-*
		// Xray API returns a generated name for all-* type which will
		// cause TF to want to update the resource since it doesn't match
		// the configuration.
		if len(res.Name) > 0 && !slices.Contains(allTypes, res.Type) {
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

		resourceMaps = append(resourceMaps, resourceMap)
	}

	return resourceMaps
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

func packKvFilter(filter WatchFilter) (map[string]interface{}, error) {
	var kvValue WatchFilterKvValue
	err := json.Unmarshal(filter.Value, &kvValue)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"type":  filter.Type,
		"key":   kvValue.Key,
		"value": kvValue.Value,
	}, nil
}

var packFilterMap = map[string]map[string]interface{}{
	"regex": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"path-regex": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"package-type": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"mime-type": {
		"func":          packStringFilter,
		"attributeName": "filter",
	},
	"ant-patterns": {
		"func":          packAntFilter,
		"attributeName": "ant_filter",
	},
	"path-ant-patterns": {
		"func":          packAntFilter,
		"attributeName": "path_ant_filter",
	},
	"property": {
		"func":          packKvFilter,
		"attributeName": "kv_filter",
	},
}

func packFilters(filters []WatchFilter, resources map[string]interface{}) (map[string]interface{}, []error) {
	resources["filter"] = []map[string]interface{}{}
	resources["ant_filter"] = []map[string]interface{}{}
	resources["path_ant_filter"] = []map[string]interface{}{}
	resources["kv_filter"] = []map[string]interface{}{}
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
	var assignedPolicies []interface{}
	for _, p := range policies {
		assignedPolicy := map[string]interface{}{
			"name": p.Name,
			"type": p.Type,
		}
		assignedPolicies = append(assignedPolicies, assignedPolicy)
	}

	return assignedPolicies
}

func packWatch(ctx context.Context, watch Watch, d *schema.ResourceData) diag.Diagnostics {
	if err := d.Set("name", watch.GeneralData.Name); err != nil {
		return diag.FromErr(err)
	}
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
	if err := d.Set("watch_recipients", watch.WatchRecipients); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceXrayWatchCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := unpackWatch(d)

	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, watch.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	// add 'build_repo' to resource if project_key is specified.
	// undocumented Xray API structure that is required!
	if len(watch.ProjectKey) > 0 {
		for idx, resource := range watch.ProjectResources.Resources {
			if resource.Type == "build" {
				watch.ProjectResources.Resources[idx].BuildRepo = fmt.Sprintf("%s-build-info", watch.ProjectKey)
			}
		}
	}

	_, err = req.
		SetBody(watch).
		Post("xray/api/v2/watches")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(watch.GeneralData.Name)
	return resourceXrayWatchRead(ctx, d, m)
}

func resourceXrayWatchRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := Watch{}

	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, projectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := req.
		SetResult(&watch).
		SetPathParams(map[string]string{
			"name": d.Id(),
		}).
		Get("xray/api/v2/watches/{name}")
	if err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, fmt.Sprintf("Xray watch (%s) not found, removing from state", d.Id()))
			d.SetId("")
		}
		return diag.FromErr(err)
	}

	return packWatch(ctx, watch, d)
}

func resourceXrayWatchUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := unpackWatch(d)

	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, watch.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := req.
		SetBody(watch).
		SetPathParams(map[string]string{
			"name": d.Id(),
		}).
		Put("xray/api/v2/watches/{name}")
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

func resourceXrayWatchDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	watch := unpackWatch(d)

	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, watch.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := req.
		SetPathParams(map[string]string{
			"name": d.Id(),
		}).
		Delete("xray/api/v2/watches/{name}")
	if err != nil && resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return diag.FromErr(err)
	}
	return nil
}

func watchResourceDiff(_ context.Context, diff *schema.ResourceDiff, v interface{}) error {
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

		repositoryResourceTypes := []string{"repository", "all-repos"}

		pathAntFilters := r["path_ant_filter"].(*schema.Set).List()
		if !slices.Contains(repositoryResourceTypes, resourceType) && len(pathAntFilters) > 0 {
			return fmt.Errorf("attribute 'path_ant_filter' is set when 'watch_resource.type' is not set to 'repository' or 'all-repos'")
		}

		kvFilters := r["kv_filter"].(*schema.Set).List()
		if !slices.Contains(repositoryResourceTypes, resourceType) && len(kvFilters) > 0 {
			return fmt.Errorf("attribute 'kv_filter' is set when 'watch_resource.type' is not set to 'repository' or 'all-repos'")
		}
	}
	return nil
}
