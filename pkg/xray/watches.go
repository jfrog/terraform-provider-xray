package xray

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"
	"net/http"

	"github.com/go-resty/resty/v2"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type WatchGeneralData struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Active      bool   `json:"active,omitempty"`
}

type WatchFilterValue struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

type WatchFilter struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type WatchProjectResource struct {
	Type            *string       `json:"type,omitempty"`
	BinaryManagerId *string       `json:"bin_mgr_id,omitempty"`
	Filters         []WatchFilter `json:"filters,omitempty"`
	// Watch a repo
	Name string `json:"name,omitempty"`
}

type WatchProjectResources struct {
	Resources *[]WatchProjectResource `json:"resources,omitempty"`
}

type WatchAssignedPolicy struct {
	Name *string `json:"name,omitempty"`
	Type *string `json:"type,omitempty"`
}

type Watch struct {
	GeneralData      *WatchGeneralData      `json:"general_data,omitempty"`
	ProjectResources *WatchProjectResources `json:"project_resources,omitempty"`
	AssignedPolicies *[]WatchAssignedPolicy `json:"assigned_policies,omitempty"`
}

func unpackWatch(d *schema.ResourceData) *Watch {
	watch := new(Watch)

	gd := &WatchGeneralData{
		Name: d.Get("name").(string),
	}
	if v, ok := d.GetOk("description"); ok {
		gd.Description = v.(string)
	}
	if v, ok := d.GetOk("active"); ok {
		gd.Active = v.(bool)
	}
	watch.GeneralData = gd

	pr := &WatchProjectResources{}
	if v, ok := d.GetOk("watch_resource"); ok {
		r := &[]WatchProjectResource{}
		for _, res := range v.([]interface{}) {
			*r = append(*r, *unpackProjectResource(res))
		}
		pr.Resources = r
	}
	watch.ProjectResources = pr

	ap := &[]WatchAssignedPolicy{}
	if v, ok := d.GetOk("assigned_policy"); ok {
		for _, pol := range v.([]interface{}) {
			*ap = append(*ap, *unpackAssignedPolicy(pol))
		}
	}
	watch.AssignedPolicies = ap

	return watch
}

func unpackProjectResource(rawCfg interface{}) *WatchProjectResource {
	resource := new(WatchProjectResource)

	cfg := rawCfg.(map[string]interface{})
	resource.Type = StringPtr(cfg["type"].(string))

	if v, ok := cfg["bin_mgr_id"]; ok {
		resource.BinaryManagerId = StringPtr(v.(string))
	}
	if v, ok := cfg["name"]; ok {
		resource.Name = v.(string)
	}

	if v, ok := cfg["filter"]; ok {
		resourceFilters := unpackFilters(v.([]interface{}))
		resource.Filters = resourceFilters
	}

	return resource
}

func unpackFilters(list []interface{}) []WatchFilter {
	filters := make([]WatchFilter, 0, len(list))

	for _, raw := range list {
		filter := new(WatchFilter)
		f := raw.(map[string]interface{})
		filter.Type = f["type"].(string) // TODO: recognize the type of the filter
		filter.Value = f["value"].(string)
		filters = append(filters, *filter)
	}

	return filters
}

func unpackAssignedPolicy(rawCfg interface{}) *WatchAssignedPolicy {
	policy := new(WatchAssignedPolicy)

	cfg := rawCfg.(map[string]interface{})
	policy.Name = StringPtr(cfg["name"].(string))
	policy.Type = StringPtr(cfg["type"].(string))

	return policy
}

func packProjectResources(resources *WatchProjectResources) []interface{} {
	if resources == nil || resources.Resources == nil {
		return []interface{}{}
	}

	var list []interface{}
	for _, res := range *resources.Resources {
		resourceMap := make(map[string]interface{})
		resourceMap["type"] = res.Type
		if len(res.Name) > 0 {
			resourceMap["name"] = res.Name
		}
		if res.BinaryManagerId != nil {
			resourceMap["bin_mgr_id"] = res.BinaryManagerId
		}
		resourceMap["filter"] = packFilters(res.Filters)
		list = append(list, resourceMap)
	}

	return list
}

func packFilters(filters []WatchFilter) []interface{} {
	if filters == nil {
		return []interface{}{}
	}

	var l []interface{}
	for _, f := range filters {
		m := map[string]interface{}{
			"type":  f.Type,
			"value": f.Value,
		}
		l = append(l, m)
	}

	return l
}

func packAssignedPolicies(policies *[]WatchAssignedPolicy) []interface{} {
	if policies == nil {
		return []interface{}{}
	}

	var l []interface{}
	for _, p := range *policies {
		m := make(map[string]interface{})
		m["name"] = p.Name
		m["type"] = p.Type
		l = append(l, m)
	}

	return l
}

func resourceXrayWatchCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	watch := unpackWatch(d)
	_, err := m.(*resty.Client).R().SetBody(watch).Post("xray/api/v2/watches")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(watch.GeneralData.Name) // ID may be returned according to the API docs, but not in go-xray
	resourceXrayWatchRead(ctx, d, m)
	return diags
}

func resourceXrayWatchRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	watch := Watch{}
	resp, err := m.(*resty.Client).R().SetResult(&watch).Get("xray/api/v2/watches/" + d.Id())
	if err != nil {

		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			log.Printf("[WARN] Xray watch (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}
		return diags
	}
	// add packWatch functions, call it from here
	if err := d.Set("description", watch.GeneralData.Description); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("active", watch.GeneralData.Active); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("watch_resource", packProjectResources(watch.ProjectResources)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("assigned_policy", packAssignedPolicies(watch.AssignedPolicies)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceXrayWatchUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	watch := unpackWatch(d)
	_, err := m.(*resty.Client).R().SetBody(watch).Put("xray/api/v2/watches/" + d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(watch.GeneralData.Name)
	resourceXrayWatchRead(ctx, d, m)
	return diags
}

func resourceXrayWatchDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	resp, err := m.(*resty.Client).R().Delete("xray/api/v2/watches/" + d.Id())
	if err != nil && resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return diag.FromErr(err)
	}
	return diags
}

func checkWatch(id string, request *resty.Request) (*resty.Response, error) {
	return request.Get("xray/api/v2/watches/" + id)
}

func testCheckWatch(id string, request *resty.Request) (*resty.Response, error) {
	return checkWatch(id, request.AddRetryCondition(neverRetry))
}
