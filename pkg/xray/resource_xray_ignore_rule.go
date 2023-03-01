package xray

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
)

type IgnoreRule struct {
	Id            string        `json:"id,omitempty"`
	ProjectKey    string        `json:"-"`
	Author        string        `json:"author,omitempty"`
	Created       *time.Time    `json:"created,omitempty"`
	IsExpired     bool          `json:"is_expired,omitempty"`
	Notes         string        `json:"notes"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
	IgnoreFilters IgnoreFilters `json:"ignore_filters"`
}

type IgnoreFilters struct {
	Vulnerabilities  []string                      `json:"vulnerabilities,omitempty"`
	Licenses         []string                      `json:"licenses,omitempty"`
	CVEs             []string                      `json:"cves,omitempty"`
	Policies         []string                      `json:"policies,omitempty"`
	Watches          []string                      `json:"watches,omitempty"`
	DockerLayers     []string                      `json:"docker-layers,omitempty"`
	OperationalRisks []string                      `json:"operational_risk,omitempty"`
	ReleaseBundles   []IgnoreFilterNameVersion     `json:"release_bundles,omitempty"`
	Builds           []IgnoreFilterNameVersion     `json:"builds,omitempty"`
	Components       []IgnoreFilterNameVersion     `json:"components,omitempty"`
	Artifacts        []IgnoreFilterNameVersionPath `json:"artifacts,omitempty"`
}

type IgnoreFilterNameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type IgnoreFilterNameVersionPath struct {
	IgnoreFilterNameVersion
	Path string `json:"path,omitempty"`
}

func resourceXrayIgnoreRule() *schema.Resource {
	var ignoreRuleSchema = util.MergeMaps(
		getProjectKeySchema(true, ""),
		map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the ignore rule",
			},
			"notes": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Notes of the ignore rule",
			},
			"expiration_date": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringMatch(regexp.MustCompile(`^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$`), "Date must be in YYYY-MM-DD format")),
				Description:      "The Ignore Rule will be active until the expiration date. At that date it will automatically get deleted. The rule with the expiration date less than current day, will error out.",
			},
			"author": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"is_expired": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"vulnerabilities": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				Description:   "List of specific vulnerabilities to ignore. Omit to apply to all.",
				ConflictsWith: []string{"cves", "licenses", "operational_risk"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cves": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				Computed:      true, // If "vulnerabilities" is set to "any" and "cves" omitted (user can't set a conflicting attribute), the value "any" for "cves" will be returned in the response body from the Xray anyway. To avoid state drift this attribute is "Computed".
				Description:   "List of specific CVEs to ignore. Omit to apply to all.",
				ConflictsWith: []string{"vulnerabilities", "licenses", "operational_risk"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"licenses": {
				Type:        schema.TypeSet,
				Optional:    true,
				ForceNew:    true,
				Description: "List of specific licenses to ignore. Omit to apply to all.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"operational_risk": {
				Type:          schema.TypeList,
				Optional:      true,
				ForceNew:      true,
				Description:   "Operational risk to ignore. Only accept 'any'",
				ConflictsWith: []string{"vulnerabilities", "cves", "licenses"},
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"any"}, true)),
				},
			},
			"policies": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				Description:   "List of specific policies to ignore. Omit to apply to all.",
				ConflictsWith: []string{"watches"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"watches": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				Description:   "List of specific watches to ignore. Omit to apply to all.",
				ConflictsWith: []string{"policies"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"docker_layers": {
				Type:        schema.TypeSet,
				Optional:    true,
				ForceNew:    true,
				Description: "List of Docker layer SHA256 hashes to ignore. Omit to apply to all.",
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validation.ToDiagFunc(validation.StringMatch(regexp.MustCompile(`^[0-9a-z]{64}$`), "Must be SHA256 hash")),
				},
			},
			"release_bundle": {
				Type:        schema.TypeSet,
				Optional:    true,
				ForceNew:    true,
				Description: "List of specific release bundles to ignore. Omit to apply to all.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the release bundle",
						},
						"version": {
							Type:             schema.TypeString,
							Optional:         true,
							Description:      "Version of the release bundle",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
						},
					},
				},
			},
			"build": {
				Type:        schema.TypeSet,
				Optional:    true,
				ForceNew:    true,
				Description: "List of specific builds to ignore. Omit to apply to all.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the build",
						},
						"version": {
							Type:             schema.TypeString,
							Optional:         true,
							Description:      "Version of the build",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
						},
					},
				},
			},
			"component": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"build", "release_bundle"},
				Description:   "List of specific components to ignore. Omit to apply to all.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the component",
						},
						"version": {
							Type:             schema.TypeString,
							Optional:         true,
							Description:      "Version of the component",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
						},
					},
				},
			},
			"artifact": {
				Type:          schema.TypeSet,
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"build", "release_bundle"},
				Description:   "List of specific artifacts to ignore. Omit to apply to all.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the artifact. Wildcards are not supported.",
						},
						"version": {
							Type:             schema.TypeString,
							Optional:         true,
							Description:      "Version of the artifact",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
						},
						"path": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Path of the artifact. Must end with a '/'",
							ValidateDiagFunc: validation.ToDiagFunc(
								validation.All(
									validation.StringIsNotEmpty,
									validation.StringMatch(regexp.MustCompile(`^.+\/$`), "Must end with a '/'"),
								),
							),
						},
					},
				},
			},
		},
	)

	var packFilterNameVersion = func(filters []IgnoreFilterNameVersion) []interface{} {
		var fs []interface{}

		for _, filter := range filters {
			f := map[string]interface{}{
				"name":    filter.Name,
				"version": filter.Version,
			}

			fs = append(fs, f)
		}

		return fs
	}

	var packFilterNameVersionPath = func(filters []IgnoreFilterNameVersionPath) []interface{} {
		var fs []interface{}

		for _, filter := range filters {
			f := map[string]interface{}{
				"name":    filter.Name,
				"version": filter.Version,
				"path":    filter.Path,
			}

			fs = append(fs, f)
		}

		return fs
	}

	var packIgnoreRule = func(ignoreRule IgnoreRule, d *schema.ResourceData) diag.Diagnostics {
		if err := d.Set("id", ignoreRule.Id); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("notes", ignoreRule.Notes); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("author", ignoreRule.Author); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("created", ignoreRule.Created.Format(time.RFC3339)); err != nil {
			return diag.FromErr(err)
		}
		if ignoreRule.ExpiresAt != nil {
			if err := d.Set("expiration_date", ignoreRule.ExpiresAt.Format("2006-01-02")); err != nil {
				return diag.FromErr(err)
			}
		}
		if err := d.Set("is_expired", ignoreRule.IsExpired); err != nil {
			return diag.FromErr(err)
		}
		if len(ignoreRule.IgnoreFilters.Vulnerabilities) > 0 {
			if err := d.Set("vulnerabilities", ignoreRule.IgnoreFilters.Vulnerabilities); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.Licenses) > 0 {
			if err := d.Set("licenses", ignoreRule.IgnoreFilters.Licenses); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.CVEs) > 0 {
			if err := d.Set("cves", ignoreRule.IgnoreFilters.CVEs); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.OperationalRisks) > 0 {
			if err := d.Set("operational_risk", ignoreRule.IgnoreFilters.OperationalRisks); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.Watches) > 0 {
			if err := d.Set("watches", ignoreRule.IgnoreFilters.Watches); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.Policies) > 0 {
			if err := d.Set("policies", ignoreRule.IgnoreFilters.Policies); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(ignoreRule.IgnoreFilters.DockerLayers) > 0 {
			if err := d.Set("docker_layers", ignoreRule.IgnoreFilters.DockerLayers); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(packFilterNameVersion(ignoreRule.IgnoreFilters.ReleaseBundles)) > 0 {
			if err := d.Set("release_bundle", packFilterNameVersion(ignoreRule.IgnoreFilters.ReleaseBundles)); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(packFilterNameVersion(ignoreRule.IgnoreFilters.Builds)) > 0 {
			if err := d.Set("build", packFilterNameVersion(ignoreRule.IgnoreFilters.Builds)); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(packFilterNameVersion(ignoreRule.IgnoreFilters.Components)) > 0 {
			if err := d.Set("component", packFilterNameVersion(ignoreRule.IgnoreFilters.Components)); err != nil {
				return diag.FromErr(err)
			}
		}
		if len(packFilterNameVersionPath(ignoreRule.IgnoreFilters.Artifacts)) > 0 {
			if err := d.Set("artifact", packFilterNameVersionPath(ignoreRule.IgnoreFilters.Artifacts)); err != nil {
				return diag.FromErr(err)
			}
		}

		return nil
	}

	var unpackFilterNameVersion = func(attributeName string, d *schema.ResourceData) []IgnoreFilterNameVersion {
		var filters []IgnoreFilterNameVersion
		if v, ok := d.GetOkExists(attributeName); ok {
			for _, f := range v.(*schema.Set).List() {
				fMap := f.(map[string]interface{})
				filter := IgnoreFilterNameVersion{
					Name:    fMap["name"].(string),
					Version: fMap["version"].(string),
				}
				filters = append(filters, filter)
			}
		}

		return filters
	}

	var unpackFilterNameVersionPath = func(attributeName string, d *schema.ResourceData) []IgnoreFilterNameVersionPath {
		var filters []IgnoreFilterNameVersionPath
		if v, ok := d.GetOkExists(attributeName); ok {
			for _, f := range v.(*schema.Set).List() {
				fMap := f.(map[string]interface{})
				filter := IgnoreFilterNameVersionPath{
					IgnoreFilterNameVersion: IgnoreFilterNameVersion{
						Name:    fMap["name"].(string),
						Version: fMap["version"].(string),
					},
					Path: fMap["path"].(string),
				}
				filters = append(filters, filter)
			}
		}

		return filters
	}

	var unpackIgnnoreRule = func(d *schema.ResourceData) (IgnoreRule, error) {
		ignoreRule := IgnoreRule{}

		ignoreRule.Id = d.Get("id").(string)
		if v, ok := d.GetOk("project_key"); ok {
			ignoreRule.ProjectKey = v.(string)
		}
		if v, ok := d.GetOk("notes"); ok {
			ignoreRule.Notes = v.(string)
		}
		if v, ok := d.GetOk("expiration_date"); ok {
			expirationDate, err := time.Parse("2006-01-02", v.(string))
			if err != nil {
				return ignoreRule, err
			}
			ignoreRule.ExpiresAt = &expirationDate
		}

		ignoreFilters := IgnoreFilters{}
		data := &util.ResourceData{ResourceData: d}
		vulnerabilities := data.GetSet("vulnerabilities")
		if len(vulnerabilities) > 0 {
			ignoreFilters.Vulnerabilities = vulnerabilities
		}

		cves := data.GetSet("cves")
		if len(cves) > 0 {
			ignoreFilters.CVEs = cves
		}

		licenses := data.GetSet("licenses")
		if len(licenses) > 0 {
			ignoreFilters.Licenses = licenses
		}

		watches := data.GetSet("watches")
		if len(watches) > 0 {
			ignoreFilters.Watches = watches
		}

		policies := data.GetSet("policies")
		if len(policies) > 0 {
			ignoreFilters.Policies = policies
		}

		operationalRisks := data.GetList("operational_risk")
		if len(operationalRisks) > 0 {
			ignoreFilters.OperationalRisks = operationalRisks
		}

		dockerLayers := data.GetSet("docker_layers")
		if len(dockerLayers) > 0 {
			ignoreFilters.DockerLayers = dockerLayers
		}
		ignoreFilters.ReleaseBundles = unpackFilterNameVersion("release_bundle", d)
		ignoreFilters.Builds = unpackFilterNameVersion("build", d)
		ignoreFilters.Components = unpackFilterNameVersion("component", d)
		ignoreFilters.Artifacts = unpackFilterNameVersionPath("artifact", d)

		ignoreRule.IgnoreFilters = ignoreFilters

		return ignoreRule, nil
	}

	var resourceXrayIgnoreRuleRead = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		ignoreRule := IgnoreRule{}

		projectKey := d.Get("project_key").(string)
		req, err := getRestyRequest(m.(*resty.Client), projectKey)
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetResult(&ignoreRule).
			SetPathParams(map[string]string{
				"id": d.Id(),
			}).
			Get("xray/api/v1/ignore_rules/{id}")
		if err != nil {
			if resp != nil && resp.StatusCode() == http.StatusNotFound {
				tflog.Warn(ctx, fmt.Sprintf("Xray ignore rule (%s) not found, removing from state", d.Id()))
				d.SetId("")
			}
			return diag.FromErr(err)
		}

		return packIgnoreRule(ignoreRule, d)
	}

	var resourceXrayIgnoreRuleCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		ignoreRule, err := unpackIgnnoreRule(d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(*resty.Client), ignoreRule.ProjectKey)
		if err != nil {
			return diag.FromErr(err)
		}

		type IgnoreRuleCreateResponse struct {
			Info string `json:"info"`
		}

		response := IgnoreRuleCreateResponse{}

		_, err = req.
			SetBody(ignoreRule).
			SetResult(&response).
			Post("xray/api/v1/ignore_rules")
		if err != nil {
			return diag.FromErr(err)
		}

		// response is in this json structure:
		// {
		//   info": "Successfully added Ignore rule with id: c0e5b540-1988-42b2-6a86-b444cda1c521"
		// }
		// use regex to match the group for the ID
		re := regexp.MustCompile(`(?m)^Successfully added Ignore rule with id: (.+)$`)
		matches := re.FindStringSubmatch(response.Info)
		if len(matches) > 1 {
			d.SetId(matches[1])
		}

		return resourceXrayIgnoreRuleRead(ctx, d, m)
	}

	var resourceXrayIgnoreRuleDelete = func(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		ignoreRule, err := unpackIgnnoreRule(d)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := getRestyRequest(m.(*resty.Client), ignoreRule.ProjectKey)
		if err != nil {
			return diag.FromErr(err)
		}

		resp, err := req.
			SetPathParams(map[string]string{
				"id": d.Id(),
			}).
			Delete("xray/api/v1/ignore_rules/{id}")
		if err != nil && resp.StatusCode() == http.StatusInternalServerError {
			d.SetId("")
			return diag.FromErr(err)
		}

		return nil
	}
	return &schema.Resource{
		CreateContext: resourceXrayIgnoreRuleCreate,
		ReadContext:   resourceXrayIgnoreRuleRead,
		DeleteContext: resourceXrayIgnoreRuleDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema:      ignoreRuleSchema,
		Description: "Provides an Xray ignore rule resource. See [Xray Ignore Rules](https://www.jfrog.com/confluence/display/JFROG/Ignore+Rules) and [REST API](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-IGNORERULES) for more details. Notice: at least one of the 'vulnerabilities/cves/liceneses', 'component', and 'docker_layers/artifact/build/release_bundle' should not be empty. When selecting the ignore criteria, take note of the combinations you choose. Some combinations such as omitting everything is not allowed as it will ignore all future violations (in the watch or in the system).",
	}
}
