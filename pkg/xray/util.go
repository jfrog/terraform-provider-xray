package xray

import (
	"bytes"
	"fmt"
	"math/rand"
	"text/template"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ResourceData struct{ *schema.ResourceData }

func (d *ResourceData) getSetRef(key string) *[]string {
	if v, ok := d.GetOkExists(key); ok {
		arr := castToStringArr(v.(*schema.Set).List())
		return &arr
	}
	return new([]string)
}

func (d *ResourceData) getListRef(key string) *[]string {
	if v, ok := d.GetOkExists(key); ok {
		arr := castToStringArr(v.([]interface{}))
		return &arr
	}
	return new([]string)
}

func castToStringArr(arr []interface{}) []string {
	cpy := make([]string, 0, len(arr))
	for _, r := range arr {
		cpy = append(cpy, r.(string))
	}
	return cpy
}

var randomInt = func() func() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Int
}()

func copyStringMap(source map[string]string, target map[string]string) map[string]string {
	for k, v := range source {
		target[k] = v
	}
	return target
}

func executeTemplate(name, temp string, fields interface{}) string {
	var tpl bytes.Buffer
	if err := template.Must(template.New(name).Parse(temp)).Execute(&tpl, fields); err != nil {
		panic(err)
	}

	return tpl.String()
}

func mkNames(name, resource string) (int, string, string) {
	id := randomInt()
	n := fmt.Sprintf("%s%d", name, id)
	return id, fmt.Sprintf("%s.%s", resource, n), n
}

func BoolPtr(v bool) *bool { return &v }

func IntPtr(v int) *int { return &v }

func Int64Ptr(v int64) *int64 { return &v }

func Float64Ptr(v float64) *float64 { return &v }

func StringPtr(v string) *string { return &v }
