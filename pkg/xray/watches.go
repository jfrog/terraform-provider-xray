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
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

type WatchFilterValue struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

type WatchFilter struct {
	Type  *string `json:"type,omitempty"`
	Value *string `json:"value,omitempty"`
}

type WatchProjectResource struct {
	Type            *string        `json:"type,omitempty"`
	BinaryManagerId *string        `json:"bin_mgr_id,omitempty"`
	Filters         *[]WatchFilter `json:"filters,omitempty"`
	// Watch a repo
	Name *string `json:"name,omitempty"`
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

func expandWatch(d *schema.ResourceData) *Watch {
	watch := new(Watch)

	gd := &WatchGeneralData{
		Name: StringPtr(d.Get("name").(string)),
	}
	if v, ok := d.GetOk("description"); ok {
		gd.Description = StringPtr(v.(string))
	}
	if v, ok := d.GetOk("active"); ok {
		gd.Active = BoolPtr(v.(bool))
	}
	watch.GeneralData = gd

	pr := &WatchProjectResources{}
	if v, ok := d.GetOk("watch_resource"); ok {
		r := &[]WatchProjectResource{}
		for _, res := range v.([]interface{}) {
			*r = append(*r, *expandProjectResource(res))
		}
		pr.Resources = r
	}
	watch.ProjectResources = pr

	ap := &[]WatchAssignedPolicy{}
	if v, ok := d.GetOk("assigned_policy"); ok {
		for _, pol := range v.([]interface{}) {
			*ap = append(*ap, *expandAssignedPolicy(pol))
		}
	}
	watch.AssignedPolicies = ap

	return watch
}

func expandProjectResource(rawCfg interface{}) *WatchProjectResource {
	resource := new(WatchProjectResource)

	cfg := rawCfg.(map[string]interface{})
	resource.Type = StringPtr(cfg["type"].(string))

	if v, ok := cfg["bin_mgr_id"]; ok {
		resource.BinaryManagerId = StringPtr(v.(string))
	}
	if v, ok := cfg["name"]; ok {
		resource.Name = StringPtr(v.(string))
	}

	if v, ok := cfg["filter"]; ok {
		resourceFilters := expandFilters(v.([]interface{}))
		resource.Filters = &resourceFilters
	}

	return resource
}

func expandFilters(l []interface{}) []WatchFilter {
	filters := make([]WatchFilter, 0, len(l))

	for _, raw := range l {
		filter := new(WatchFilter)
		f := raw.(map[string]interface{})
		filter.Type = StringPtr(f["type"].(string)) // TODO: recognize the type of the filter
		filter.Value = StringPtr(f["value"].(string))
		filters = append(filters, *filter)
	}

	return filters
}

func expandAssignedPolicy(rawCfg interface{}) *WatchAssignedPolicy {
	policy := new(WatchAssignedPolicy)

	cfg := rawCfg.(map[string]interface{})
	policy.Name = StringPtr(cfg["name"].(string))
	policy.Type = StringPtr(cfg["type"].(string))

	return policy
}

func flattenProjectResources(resources *WatchProjectResources) []interface{} {
	if resources == nil || resources.Resources == nil {
		return []interface{}{}
	}

	var l []interface{}
	for _, res := range *resources.Resources {
		m := make(map[string]interface{})
		m["type"] = res.Type
		if res.Name != nil {
			m["name"] = res.Name
		}
		if res.BinaryManagerId != nil {
			m["bin_mgr_id"] = res.BinaryManagerId
		}
		m["filter"] = flattenFilters(res.Filters)
		l = append(l, m)
	}

	return l
}

func flattenFilters(filters *[]WatchFilter) []interface{} {
	if filters == nil {
		return []interface{}{}
	}

	var l []interface{}
	for _, f := range *filters {
		m := make(map[string]interface{})
		m["type"] = f.Type
		m["value"] = f.Value
		l = append(l, m)
	}

	return l
}

func flattenAssignedPolicies(policies *[]WatchAssignedPolicy) []interface{} {
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
	watch := expandWatch(d)
	_, err := m.(*resty.Client).R().SetBody(watch).Post("xray/api/v2/watches")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(*watch.GeneralData.Name) // ID may be returned according to the API docs, but not in go-xray
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

	if err := d.Set("description", watch.GeneralData.Description); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("active", watch.GeneralData.Active); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("watch_resource", flattenProjectResources(watch.ProjectResources)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("assigned_policy", flattenAssignedPolicies(watch.AssignedPolicies)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceXrayWatchUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	watch := expandWatch(d)
	_, err := m.(*resty.Client).R().SetBody(watch).Put("xray/api/v2/watches/" + d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(*watch.GeneralData.Name)
	resourceXrayWatchRead(ctx, d, m)
	return diags
}

func resourceXrayWatchDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	_, err := m.(*resty.Client).R().Delete("xray/api/v2/watches/" + d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	return diags
}
