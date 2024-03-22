package xray

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-shared/validator"
)

var validPackageTypes = []string{
	"alpine",
	"bower",
	"cargo",
	"chef",
	"cocoapods",
	"composer",
	"conan",
	"conda",
	"cran",
	"debian",
	"docker",
	"gems",
	"generic",
	"gitlfs",
	"go",
	"gradle",
	"helm",
	"ivy",
	"maven",
	"npm",
	"nuget",
	"opkg",
	"p2",
	"puppet",
	"pypi",
	"rpm",
	"sbt",
	"swift",
	"terraform",
	"terraformbackend",
	"vagrant",
	"vcs",
}

type VulnerableRange struct {
	VulnerableVersions []string `json:"vulnerable_versions"`
	FixedVersions      []string `json:"fixed_versions"`
}

type Component struct {
	Id                 string            `json:"id"`
	VulnerableVersions []string          `json:"vulnerable_versions"`
	FixedVersions      []string          `json:"fixed_versions"`
	VulnerableRanges   []VulnerableRange `json:"vulnerable_ranges"`
}

type Cve struct {
	Cve    string `json:"cve"`
	CvssV2 string `json:"cvss_v2"`
	CvssV3 string `json:"cvss_v3"`
}

type Source struct {
	Id   string `json:"source_id"`
	Name string `json:"name,omitempty"`
	Url  string `json:"url,omitempty"`
}

type CustomIssue struct {
	Id          string      `json:"id"`
	Description string      `json:"description"`
	Summary     string      `json:"summary"`
	Type        string      `json:"type"`
	Provider    string      `json:"provider"`
	PackageType string      `json:"package_type"`
	Severity    string      `json:"severity"`
	Components  []Component `json:"components"`
	Cves        []Cve       `json:"cves"`
	Sources     []Source    `json:"sources"`
}

func resourceXrayCustomIssue() *schema.Resource {
	var customIssueSchema = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the custom issue. It must not begin with 'xray' (case insensitive)",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.StringDoesNotMatch(
					regexp.MustCompile(`(?i)^xray`),
					"must not begin with 'xray' (case insensitive)",
				),
			),
		},
		"description": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Description of custom issue",
		},
		"summary": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Summary of custom issue",
		},
		"type": {
			Type:             schema.TypeString,
			Required:         true,
			Description:      "Type of custom issue. Valid values: other, performance, security, versions",
			ValidateDiagFunc: validator.StringInSlice(false, "other", "performance", "security", "versions"),
		},
		"provider_name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Provider of custom issue. It must not be 'jfrog' (case insensitive)",
			ValidateDiagFunc: validation.ToDiagFunc(
				validation.StringDoesNotMatch(
					regexp.MustCompile(`(?i)^jfrog$`),
					"must not be 'jfrog' (case insensitive)",
				),
			),
		},
		"package_type": {
			Type:             schema.TypeString,
			Required:         true,
			Description:      fmt.Sprintf("Package Type of custom issue. Valid values are: %s", strings.Join(validPackageTypes, ", ")),
			ValidateDiagFunc: validator.StringInSlice(false, validPackageTypes...),
		},
		"severity": {
			Type:             schema.TypeString,
			Required:         true,
			Description:      "Severity of custom issue. Valid values: Critical, High, Medium, Low, Information",
			ValidateDiagFunc: validator.StringInSlice(false, "Critical", "High", "Medium", "Low", "Information"),
		},
		"component": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "Component of custom issue",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"id": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "ID of the component",
					},
					"vulnerable_versions": {
						Type:        schema.TypeSet,
						Optional:    true,
						Description: "List of vulnerable versions",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"fixed_versions": {
						Type:        schema.TypeSet,
						Optional:    true,
						Description: "List of the fixed versions",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"vulnerable_ranges": {
						Type:        schema.TypeSet,
						Optional:    true,
						Description: "List of the vulnerable ranges",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"vulnerable_versions": {
									Type:        schema.TypeSet,
									Optional:    true,
									Description: "List of vulnerable versions",
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"fixed_versions": {
									Type:        schema.TypeSet,
									Optional:    true,
									Description: "List of the fixed versions",
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
					},
				},
			},
		},
		"cve": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "CVE of the custom issue",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"cve": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "CVE ID",
					},
					"cvss_v2": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "CVSS v2 score",
					},
					"cvss_v3": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "CVSS v3 score",
					},
				},
			},
		},
		"source": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "List of sources",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"id": {
						Type:        schema.TypeString,
						Required:    true,
						Description: "ID of the source, e.g. CVE",
					},
					"name": {
						Type:        schema.TypeString,
						Optional:    true,
						Description: "Name of the source",
					},
					"url": {
						Type:             schema.TypeString,
						Optional:         true,
						Description:      "URL of the source",
						ValidateDiagFunc: validation.ToDiagFunc(validation.IsURLWithHTTPorHTTPS),
					},
				},
			},
		},
	}

	var packCves = func(cves []Cve) []interface{} {
		var cs []interface{}

		for _, cve := range cves {
			c := map[string]interface{}{
				"cve":     cve.Cve,
				"cvss_v2": cve.CvssV2,
				"cvss_v3": cve.CvssV3,
			}

			cs = append(cs, c)
		}

		return cs
	}

	var packSources = func(sources []Source) []interface{} {
		var ss []interface{}

		for _, source := range sources {
			s := map[string]interface{}{
				"name": source.Name,
				"id":   source.Id,
				"url":  source.Url,
			}

			ss = append(ss, s)
		}

		return ss
	}

	var packComponents = func(components []Component) []interface{} {
		var cs []interface{}

		for _, component := range components {
			c := map[string]interface{}{
				"id":                  component.Id,
				"vulnerable_versions": component.VulnerableVersions,
				"fixed_versions":      component.FixedVersions,
			}

			var rs []interface{}
			for _, vulnerableRange := range component.VulnerableRanges {
				r := map[string]interface{}{
					"vulnerable_versions": vulnerableRange.VulnerableVersions,
					"fixed_versions":      vulnerableRange.FixedVersions,
				}

				rs = append(rs, r)
			}
			c["vulnerable_ranges"] = rs

			cs = append(cs, c)
		}

		return cs
	}

	var packCustomIssue = func(customIssue CustomIssue, d *schema.ResourceData) diag.Diagnostics {
		d.SetId(customIssue.Id)
		if err := d.Set("name", customIssue.Id); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("description", customIssue.Description); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("summary", customIssue.Summary); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("package_type", customIssue.PackageType); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("type", customIssue.Type); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("provider_name", customIssue.Provider); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("severity", customIssue.Severity); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("cve", packCves(customIssue.Cves)); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("source", packSources(customIssue.Sources)); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("component", packComponents(customIssue.Components)); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}

	var unpackComponents = func(d *schema.ResourceData) []Component {
		var components []Component

		if v, ok := d.GetOk("component"); ok {
			var unpackVulnerableRanges = func(vulnerableRanges interface{}) []VulnerableRange {
				var vs []VulnerableRange

				for _, vr := range vulnerableRanges.(*schema.Set).List() {
					f := vr.(map[string]interface{})

					vr := VulnerableRange{}

					if v, ok := f["vulnerable_versions"]; ok {
						vr.VulnerableVersions = sdk.CastToStringArr(v.(*schema.Set).List())
					}

					if v, ok := f["fixed_versions"]; ok {
						vr.FixedVersions = sdk.CastToStringArr(v.(*schema.Set).List())
					}

					vs = append(vs, vr)
				}

				return vs
			}

			for _, list := range v.(*schema.Set).List() {
				listMap := list.(map[string]interface{})
				component := Component{
					Id: listMap["id"].(string),
				}

				if v, ok := listMap["vulnerable_versions"]; ok {
					component.VulnerableVersions = sdk.CastToStringArr(v.(*schema.Set).List())
				}

				if v, ok := listMap["fixed_versions"]; ok {
					component.FixedVersions = sdk.CastToStringArr(v.(*schema.Set).List())
				}

				if v, ok := listMap["vulnerable_ranges"]; ok {
					component.VulnerableRanges = unpackVulnerableRanges(v)
				}

				components = append(components, component)
			}
		}

		return components
	}

	var unpackCves = func(d *schema.ResourceData) []Cve {
		var cves []Cve

		if v, ok := d.GetOk("cve"); ok {
			for _, list := range v.(*schema.Set).List() {
				listMap := list.(map[string]interface{})
				cve := Cve{
					Cve:    listMap["cve"].(string),
					CvssV2: listMap["cvss_v2"].(string),
					CvssV3: listMap["cvss_v3"].(string),
				}
				cves = append(cves, cve)
			}
		}

		return cves
	}

	var unpackSources = func(d *schema.ResourceData) []Source {
		var sources []Source

		if v, ok := d.GetOk("source"); ok {
			for _, list := range v.(*schema.Set).List() {
				listMap := list.(map[string]interface{})
				source := Source{
					Id:   listMap["id"].(string),
					Name: listMap["name"].(string),
					Url:  listMap["url"].(string),
				}
				sources = append(sources, source)
			}
		}

		return sources
	}

	var unpackCustomIssue = func(ctx context.Context, d *schema.ResourceData) (CustomIssue, error) {
		customIssue := CustomIssue{}

		customIssue.Id = d.Get("name").(string)
		if v, ok := d.GetOk("summary"); ok {
			customIssue.Summary = v.(string)
		}
		if v, ok := d.GetOk("description"); ok {
			customIssue.Description = v.(string)
		}
		if v, ok := d.GetOk("package_type"); ok {
			customIssue.PackageType = v.(string)
		}
		if v, ok := d.GetOk("type"); ok {
			customIssue.Type = v.(string)
		}
		if v, ok := d.GetOk("provider_name"); ok {
			customIssue.Provider = v.(string)
		}
		if v, ok := d.GetOk("severity"); ok {
			customIssue.Severity = v.(string)
		}

		customIssue.Components = unpackComponents(d)
		customIssue.Cves = unpackCves(d)
		customIssue.Sources = unpackSources(d)

		return customIssue, nil
	}

	var resourceXrayCustomIssueRead = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		customIssue := CustomIssue{}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetResult(&customIssue).
			SetPathParam("id", d.Id()).
			Get("xray/api/v2/events/{id}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.StatusCode() == http.StatusNotFound {
			d.SetId("")
			return diag.Errorf("custom issue (%s) not found, removing from state", d.Id())
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		return packCustomIssue(customIssue, d)
	}

	var resourceXrayCustomIssueCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		customIssue, err := unpackCustomIssue(ctx, d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetBody(customIssue).
			Post("xray/api/v1/events")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		d.SetId(customIssue.Id)

		return resourceXrayCustomIssueRead(ctx, d, m)
	}

	var resourceXrayCustomIssueUpdate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		customIssue, err := unpackCustomIssue(ctx, d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetPathParam("id", d.Id()).
			SetBody(customIssue).
			Put("xray/api/v1/events/{id}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		d.SetId(customIssue.Id)

		return resourceXrayCustomIssueRead(ctx, d, m)
	}

	var resourceXrayCustomIssueDelete = func(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		req, err := getRestyRequest(m.(util.ProvderMetadata).Client, "")
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetPathParam("id", d.Id()).
			Delete("xray/api/v1/events/{id}")
		if err != nil {
			return diag.FromErr(err)
		}
		if resp.StatusCode() == http.StatusInternalServerError {
			d.SetId("")
		}
		if resp.IsError() {
			return diag.Errorf("%s", resp.String())
		}

		d.SetId("")

		return nil
	}

	return &schema.Resource{
		CreateContext: resourceXrayCustomIssueCreate,
		ReadContext:   resourceXrayCustomIssueRead,
		UpdateContext: resourceXrayCustomIssueUpdate,
		DeleteContext: resourceXrayCustomIssueDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: customIssueSchema,
		Description: "Provides an Xray custom issue event resource. See [Xray Custom Issue](https://jfrog.com/help/r/xray-how-to-formally-raise-an-issue-regarding-an-indexed-artifact) " +
			"and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/issues) for more details.\n\n" +
			"~>Due to JFrog Xray REST API behavior, when `component.vulnerable_versions` or `component.fixed_versions` are " +
			"set, their values are mirrored in the `component.vulnerable_ranges` attribute, and vice versa. We recommend " +
			"setting all the `component` attribute values to match to avoid state drift.",
	}
}
