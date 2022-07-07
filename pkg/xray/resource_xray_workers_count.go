package xray

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
)

func resourceXrayWorkersCount() *schema.Resource {
	newContentSchema := map[string]*schema.Schema{
		"new_content": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Type of resource to be watched. Options: `all-repos`, `repository`, `all-builds`, `build`, `project`, `all-projects`.",
		},
	}

	newExistingContentSchema := util.MergeMaps(
		newContentSchema,
		map[string]*schema.Schema{
			"existing_content": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "The ID number of a binary manager resource. Default value is `default`. To check the list of available binary managers, use the API call `${JFROG_URL}/xray/api/v1/binMgr` as an admin user, use `binMgrId` value. More info [here](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-GetBinaryManager)",
			},
		},
	)

	workersCountSchema := map[string]*schema.Schema{
		"index": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newExistingContentSchema,
			},
		},
		"persist": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newExistingContentSchema,
			},
		},
		"analysis": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newExistingContentSchema,
			},
		},
		"alert": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newExistingContentSchema,
			},
		},
		"impact_analysis": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newContentSchema,
			},
		},
		"notification": {
			Type:        schema.TypeSet,
			Required:    true,
			MinItems:    1,
			MaxItems:    1,
			Description: "",
			Elem: &schema.Resource{
				Schema: newContentSchema,
			},
		},
	}

	type NewContent struct {
		New int `json:"new_content"`
	}

	type NewExistingContent struct {
		NewContent
		Existing int `json:"existing_content"`
	}

	/*
		API returns the follow JSON structure:
		{
		    "index": {
		        "new_content": 4,
		        "existing_content": 2
		    },
		    "persist": {
		        "new_content": 4,
		        "existing_content": 2
		    },
		    "analysis": {
		        "new_content": 4,
		        "existing_content": 2
		    },
		    "alert": {
		        "new_content": 4,
		        "existing_content": 2
		    },
		    "impact_analysis": {
		        "new_content": 2
		    },
		    "notification": {
		        "new_content": 2
		    }
		}
	*/
	type WorkersCount struct {
		Index          NewExistingContent `json:"index"`
		Persist        NewExistingContent `json:"persist"`
		Analysis       NewExistingContent `json:"analysis"`
		Alert          NewExistingContent `json:"alert"`
		ImpactAnalysis NewContent         `json:"impact_analysis"`
		Notification   NewContent         `json:"notification"`
	}

	var newHclContentConstructor = func(src interface{}) map[string]interface{} {
		return map[string]interface{}{
			"new_content": src.(NewContent).New,
		}
	}

	var newExistingHclContentConstructor = func(src interface{}) map[string]interface{} {
		return map[string]interface{}{
			"new_content":      src.(NewExistingContent).New,
			"existing_content": src.(NewExistingContent).Existing,
		}
	}

	var packContent = func(d *schema.ResourceData, attr string, src interface{}, hclContentConstructor func(src interface{}) map[string]interface{}) []error {
		setValue := util.MkLens(d)

		resource := workersCountSchema[attr].Elem.(*schema.Resource)
		content := hclContentConstructor(src)
		return setValue(attr, schema.NewSet(schema.HashResource(resource), []interface{}{content}))
	}

	var packWorkersCount = func(d *schema.ResourceData, workersCount WorkersCount) diag.Diagnostics {
		var errors []error

		errors = append(errors, packContent(d, "index", workersCount.Index, newExistingHclContentConstructor)...)
		errors = append(errors, packContent(d, "persist", workersCount.Persist, newExistingHclContentConstructor)...)
		errors = append(errors, packContent(d, "analysis", workersCount.Analysis, newExistingHclContentConstructor)...)
		errors = append(errors, packContent(d, "alert", workersCount.Alert, newExistingHclContentConstructor)...)
		errors = append(errors, packContent(d, "impact_analysis", workersCount.ImpactAnalysis, newHclContentConstructor)...)
		errors = append(errors, packContent(d, "notification", workersCount.Notification, newHclContentConstructor)...)

		if len(errors) > 0 {
			return diag.Errorf("failed to pack workers count %q", errors)
		}

		return nil
	}

	var unpackContent = func(d *schema.ResourceData, attr string, constructor func(map[string]interface{}) interface{}) interface{} {
		var content interface{}
		if v, ok := d.GetOk(attr); ok {
			s := v.(*schema.Set).List()[0].(map[string]interface{})
			content = constructor(s)
		}

		return content
	}

	var newContentConstructor = func(s map[string]interface{}) interface{} {
		return NewContent{
			New: s["new_content"].(int),
		}
	}

	var newExistingContentConstructor = func(s map[string]interface{}) interface{} {
		return NewExistingContent{
			NewContent: newContentConstructor(s).(NewContent),
			Existing:   s["existing_content"].(int),
		}
	}

	var unpackWorkersCount = func(d *schema.ResourceData) WorkersCount {
		return WorkersCount{
			Index:          unpackContent(d, "index", newExistingContentConstructor).(NewExistingContent),
			Persist:        unpackContent(d, "persist", newExistingContentConstructor).(NewExistingContent),
			Analysis:       unpackContent(d, "analysis", newExistingContentConstructor).(NewExistingContent),
			Alert:          unpackContent(d, "alert", newExistingContentConstructor).(NewExistingContent),
			ImpactAnalysis: unpackContent(d, "impact_analysis", newContentConstructor).(NewContent),
			Notification:   unpackContent(d, "notification", newContentConstructor).(NewContent),
		}
	}

	var resourceXrayWorkersCountCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "Workers Count resource does not support create",
			Detail:   "Workers Count can only be updated. To manage this resource in Terraform, use `terraform import` to import it into the state.",
		}}
	}

	var resourceXrayWorkersCountRead = func(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		workersCount := WorkersCount{}
		resp, err := m.(*resty.Client).R().
			SetResult(&workersCount).
			Get("xray/api/v1/configuration/workersCount")
		if err != nil {
			return diag.FromErr(err)
		}

		hash := sha256.Sum256(resp.Body())
		d.SetId(fmt.Sprintf("%x", hash))

		return packWorkersCount(d, workersCount)
	}

	var resourceXrayWorkersCountUpdate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		workersCount := unpackWorkersCount(d)
		_, err := m.(*resty.Client).R().
			SetBody(workersCount).
			Put("xray/api/v1/configuration/workersCount")

		if err != nil {
			return diag.FromErr(err)
		}

		diagnostic := resourceXrayWorkersCountRead(ctx, d, m)
		if diagnostic != nil {
			return diagnostic
		}

		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  "Xray must be restarted",
			Detail:   "You must restart Xray to apply the changes.",
		}}
	}

	var resourceXrayWorkersCountDelete = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "Workers Count resource does not support delete",
			Detail:   "Workers Count can only be updated. To stop managing this resource in Terraform, use `terraform state rm` to removed it from the state. Then the resource can be removed from the configuration.",
		}}
	}

	return &schema.Resource{
		CreateContext: resourceXrayWorkersCountCreate,
		ReadContext:   resourceXrayWorkersCountRead,
		UpdateContext: resourceXrayWorkersCountUpdate,
		DeleteContext: resourceXrayWorkersCountDelete,
		Description:   "Configure the number of workers which enables you to control the number of workers for new content and existing content. Only works for self-hosted version!",

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: workersCountSchema,
	}
}
