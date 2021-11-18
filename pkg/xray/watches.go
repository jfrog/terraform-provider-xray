package xray

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/http"
	"reflect"
	"regexp"
	"strings"
)

const watchesEndpoint = "xray/api/v2/watches"

type Identifiable interface {
	Id() string
}

type Watch struct {
	GeneralData      *WatchGeneralData     `hcl:"general_data" json:"general_data,omitempty"`
	AssignedPolicies []WatchAssignedPolicy `hcl:"assigned_policies" json:"assigned_policies,omitempty"`
	WatchRecepients  []string              `hcl:"watch_recipients" json:"watch_recipients,omitempty"`
}

type WatchGeneralData struct {
	Name        string `hcl:"name" json:"name,omitempty"`
	Description string `hcl:"description" json:"description,omitempty"`
	Active      *bool  `hcl:"active" json:"active,omitempty"`
}

type WatchAssignedPolicy struct {
	Name *string `json:"name,omitempty"`
	Type *string `json:"type,omitempty"`
}

func (bp WatchGeneralData) Id() string {
	fmt.Println(bp.Id())
	return bp.Id()
}

func mkWatchCreate(unpack UnpackFunc, read schema.ReadContextFunc) schema.CreateContextFunc {

	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		watch, key, err := unpack(d)
		fmt.Println(key) // test
		if err != nil {
			return diag.FromErr(err)
		}
		// watch must be a pointer   *** DM in RT provider it's not a pointer, and it works. Why?
		// it's nil in both cases now
		_, err = m.(*resty.Client).R().AddRetryCondition(retryOnMergeError).SetBody(watch).Post(watchesEndpoint)

		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId(key)
		return read(ctx, d, m)
	}
}

func mkWatchRead(pack PackFunc, construct Constructor) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		repo := construct()
		// watch must be a pointer
		resp, err := m.(*resty.Client).R().SetResult(repo).Get(watchesEndpoint + d.Id())

		if err != nil {
			if resp != nil && (resp.StatusCode() == http.StatusNotFound) {
				d.SetId("")
				return nil
			}
			return diag.FromErr(err)
		}
		return diag.FromErr(pack(repo, d))
	}
}

func mkWatchUpdate(unpack UnpackFunc, read schema.ReadContextFunc) schema.UpdateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		repo, key, err := unpack(d)
		if err != nil {
			return diag.FromErr(err)
		}
		// repo must be a pointer
		_, err = m.(*resty.Client).R().AddRetryCondition(retryOnMergeError).SetBody(repo).Put(watchesEndpoint + d.Id())
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId(key)
		return read(ctx, d, m)
	}
}

func deleteWatch(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	resp, err := m.(*resty.Client).R().Delete(watchesEndpoint + d.Id())

	if err != nil && (resp != nil && resp.StatusCode() == http.StatusNotFound) {
		d.SetId("")
		return nil
	}
	return diag.FromErr(err)
}

type ReadFunc func(d *schema.ResourceData, m interface{}) error

// Constructor Must return a pointer to a struct. When just returning a struct, resty gets confused and thinks it's a map
type Constructor func() interface{}

// UnpackFunc must return a pointer to a struct and the resource id
type UnpackFunc func(s *schema.ResourceData) (interface{}, string, error)

type PackFunc func(repo interface{}, d *schema.ResourceData) error

var retryOnMergeError = func() func(response *resty.Response, _r error) bool {
	var mergeAndSaveRegex = regexp.MustCompile(".*Could not merge and save new descriptor.*")
	return func(response *resty.Response, _r error) bool {
		return mergeAndSaveRegex.MatchString(string(response.Body()[:]))
	}
}()

var baseWatchSchema = map[string]*schema.Schema{
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
	"assigned_policies": {
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
}

func unpackBaseWatch(s *schema.ResourceData) WatchGeneralData {
	d := &ResourceData{s}
	return WatchGeneralData{
		Name:        d.getString("name", false),
		Description: d.getString("description", false),
		Active:      d.getBoolRef("active", false),
	}
}

type AutoMapper func(field reflect.StructField, thing reflect.Value) map[string]interface{}

func checkForHcl(mapper AutoMapper) AutoMapper {
	return func(field reflect.StructField, thing reflect.Value) map[string]interface{} {
		if field.Tag.Get("hcl") != "" {
			return mapper(field, thing)
		}
		return map[string]interface{}{}
	}
}
func findInspector(kind reflect.Kind) AutoMapper {
	switch kind {
	case reflect.Struct:
		return func(f reflect.StructField, t reflect.Value) map[string]interface{} {
			return lookup(t.Interface())
		}
	case reflect.Ptr:
		return func(field reflect.StructField, thing reflect.Value) map[string]interface{} {
			deref := reflect.Indirect(thing)
			if deref.CanAddr() {
				result := deref.Interface()
				if deref.Kind() == reflect.Struct {
					result = []interface{}{lookup(deref.Interface())}
				}
				return map[string]interface{}{
					fieldToHcl(field): result,
				}
			}
			return map[string]interface{}{}
		}
	case reflect.Slice:
		return func(field reflect.StructField, thing reflect.Value) map[string]interface{} {
			return map[string]interface{}{
				fieldToHcl(field): castToInterfaceArr(thing.Interface().([]string)),
			}
		}
	}
	return func(field reflect.StructField, thing reflect.Value) map[string]interface{} {
		return map[string]interface{}{
			fieldToHcl(field): thing.Interface(),
		}
	}
}

// fieldToHcl this function is meant to use the HCL provided in the tag, or create a snake_case from the field name
// it actually works as expected, but dynamically working with these names was catching edge cases everywhere and
// it was/is a time sink to catch.
func fieldToHcl(field reflect.StructField) string {

	if field.Tag.Get("hcl") != "" {
		return field.Tag.Get("hcl")
	}
	var lowerFields []string
	rgx := regexp.MustCompile("([A-Z][a-z]+)")
	fields := rgx.FindAllStringSubmatch(field.Name, -1)
	for _, matches := range fields {
		for _, match := range matches[1:] {
			lowerFields = append(lowerFields, strings.ToLower(match))
		}
	}
	result := strings.Join(lowerFields, "_")
	return result
}

func lookup(payload interface{}) map[string]interface{} {

	values := map[string]interface{}{}
	var t = reflect.TypeOf(payload)
	var v = reflect.ValueOf(payload)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		thing := v.Field(i)
		typeInspector := findInspector(thing.Kind())
		for key, value := range typeInspector(field, thing) {
			if _, ok := values[key]; !ok {
				values[key] = value
			}
		}
	}
	return values
}

func anyHclPredicate(predicates ...HclPredicate) HclPredicate {
	return func(hcl string) bool {
		for _, predicate := range predicates {
			if predicate(hcl) {
				return true
			}
		}
		return false
	}
}
func allHclPredicate(predicates ...HclPredicate) HclPredicate {
	return func(hcl string) bool {
		for _, predicate := range predicates {
			if !predicate(hcl) {
				return false
			}
		}
		return true
	}
}

var noClass = ignoreHclPredicate("class", "rclass")

func ignoreHclPredicate(names ...string) HclPredicate {
	set := map[string]interface{}{}
	for _, name := range names {
		set[name] = nil
	}
	return func(hcl string) bool {
		_, found := set[hcl]
		return !found
	}
}

var defaultPacker = universalPack(noClass)

// universalPack consider making this a function that takes a predicate of what to include and returns
// a function that does the job. This would allow for the legacy code to specify which keys to keep and not
func universalPack(predicate HclPredicate) func(payload interface{}, d *schema.ResourceData) error {

	return func(payload interface{}, d *schema.ResourceData) error {
		setValue := mkLens(d)

		var errors []error

		values := lookup(payload)

		for hcl, value := range values {
			if predicate != nil && predicate(hcl) {
				errors = setValue(hcl, value)
			}
		}

		if errors != nil && len(errors) > 0 {
			return fmt.Errorf("failed saving state %q", errors)
		}
		return nil
	}
}

func mkResourceSchema(skeema map[string]*schema.Schema, packer PackFunc, unpack UnpackFunc, constructor Constructor) *schema.Resource {
	var reader = mkWatchRead(packer, constructor)
	return &schema.Resource{
		CreateContext: mkWatchCreate(unpack, reader),
		ReadContext:   reader,
		UpdateContext: mkWatchUpdate(unpack, reader),
		DeleteContext: deleteWatch,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: skeema,
	}
}
