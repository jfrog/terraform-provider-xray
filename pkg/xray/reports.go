package xray

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-shared/validator"
	"golang.org/x/exp/slices"
)

var getReportSchema = func(filtersSchema map[string]*schema.Schema) map[string]*schema.Schema {
	return sdk.MergeMaps(
		getProjectKeySchema(false, ""),
		map[string]*schema.Schema{
			"report_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Report ID",
			},
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: validator.StringIsNotEmpty,
				Description:      "Name of the report.",
			},
			"resources": {
				Type:        schema.TypeSet,
				Required:    true,
				MaxItems:    1,
				Description: "The list of resources to include into the report.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"repository": {
							Type:        schema.TypeSet,
							Optional:    true,
							MinItems:    1,
							Description: "The list of repositories for the report. Only one type of resource can be set per report.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:             schema.TypeString,
										Required:         true,
										ValidateDiagFunc: validator.StringIsNotEmpty,
										Description:      "Repository name.",
									},
									"include_path_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "Include path patterns.",
									},
									"exclude_path_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "Exclude path patterns.",
									},
								},
							},
						},
						"builds": {
							Type:        schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The builds to include into the report. Only one type of resource can be set per report.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"names": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of build names. Only one of 'names' or '*_patterns' can be set.",
									},
									"include_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of include patterns. Only one of 'names' or '*_patterns' can be set.",
									},
									"exclude_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of exclude patterns. Only one of 'names' or '*_patterns' can be set.",
									},
									"number_of_latest_versions": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(1),
										Description:  "The number of latest build versions to include to the report.",
									},
								},
							},
						},
						"release_bundles": {
							Type:        schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The release bundles to include into the report. Only one type of resource can be set per report.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"names": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of release bundles names.",
									},
									"include_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of include patterns",
									},
									"exclude_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of exclude patterns",
									},
									"number_of_latest_versions": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(0),
										Description:  "The number of latest release bundle versions to include to the report.",
									},
								},
							},
						},
						"projects": {
							Type:        schema.TypeSet,
							Optional:    true,
							MaxItems:    1,
							Description: "The projects to include into the report. Only one type of resource can be set per report.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"names": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of project names.",
									},
									"include_key_patterns": {
										Type:        schema.TypeSet,
										Elem:        &schema.Schema{Type: schema.TypeString},
										Set:         schema.HashString,
										Optional:    true,
										Description: "The list of include patterns.",
									},
									"number_of_latest_versions": {
										Type:         schema.TypeInt,
										Optional:     true,
										Default:      1,
										ValidateFunc: validation.IntAtLeast(0),
										Description:  "The number of latest release bundle versions to include to the report.",
									},
								},
							},
						},
					},
				},
			},
			"filters": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Advanced filters.",
				Elem: &schema.Resource{
					Schema: filtersSchema,
				},
			},
		},
	)
}

type Report struct {
	ReportId   int        `json:"report_id,omitempty"`
	Name       string     `json:"name"`
	ProjectKey string     `json:"-"`
	Resources  *Resources `json:"resources,omitempty"`
	Filters    *Filters   `json:"filters"`
}

type Resources struct {
	Repositories   *[]Repository   `json:"repositories,omitempty"`
	Builds         *Builds         `json:"builds,omitempty"`
	ReleaseBundles *ReleaseBundles `json:"release_bundles,omitempty"`
	Projects       *Projects       `json:"projects,omitempty"`
}

type Repository struct {
	Name                string   `json:"name,omitempty"`
	IncludePathPatterns []string `json:"include_path_patterns,omitempty"`
	ExcludePathPatterns []string `json:"exclude_path_patterns,omitempty"`
}

type Builds struct {
	Names                  []string `json:"names,omitempty"`
	IncludePatterns        []string `json:"include_patterns,omitempty"`
	ExcludePatterns        []string `json:"exclude_patterns,omitempty"`
	NumberOfLatestVersions int      `json:"number_of_latest_versions,omitempty"`
}

type ReleaseBundles struct {
	Names                  []string `json:"names,omitempty"`
	IncludePatterns        []string `json:"include_patterns,omitempty"`
	ExcludePatterns        []string `json:"exclude_patterns,omitempty"`
	NumberOfLatestVersions int      `json:"number_of_latest_versions,omitempty"`
}

type Projects struct {
	Names                  []string `json:"names,omitempty"`
	IncludeKeyPatterns     []string `json:"include_key_patterns,omitempty"`
	NumberOfLatestVersions int      `json:"number_of_latest_versions,omitempty"`
}

type Filters struct {
	VulnerableComponent string           `json:"vulnerable_component,omitempty"` // Vulnerability report filter
	ImpactedArtifact    string           `json:"impacted_artifact,omitempty"`
	HasRemediation      bool             `json:"has_remediation,omitempty"`
	Cve                 string           `json:"cve,omitempty"`
	IssueId             string           `json:"issue_id,omitempty"`
	CvssScore           *CvssScore       `json:"cvss_score,omitempty"`
	Published           *StartAndEndDate `json:"published,omitempty"`
	Unknown             bool             `json:"unknown"` // Licenses report filter
	Unrecognized        bool             `json:"unrecognized"`
	LicenseNames        []string         `json:"license_names,omitempty"`
	LicensePatterns     []string         `json:"license_patterns"`
	Type                string           `json:"type,omitempty"` // Violations report filter
	WatchNames          []string         `json:"watch_names,omitempty"`
	WatchPatterns       []string         `json:"watch_patterns,omitempty"`
	PolicyNames         []string         `json:"policy_names,omitempty"`
	Updated             *StartAndEndDate `json:"updated"`
	SecurityFilters     *SecurityFilter  `json:"security_filters"`
	LicenseFilters      *LicenseFilter   `json:"license_filters"`
	Risks               []string         `json:"risks,omitempty"`     // Operational risks filter
	ScanDate            *StartAndEndDate `json:"scan_date,omitempty"` // Common attributes
	Component           string           `json:"component,omitempty"`
	Artifact            string           `json:"artifact,omitempty"`
	Severities          []string         `json:"severities,omitempty"`
}

type CvssScore struct {
	MinScore float64 `json:"min_score,omitempty"`
	MaxScore float64 `json:"max_score,omitempty"`
}

type StartAndEndDate struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type SecurityFilter struct {
	Cve             string     `json:"cve,omitempty"`
	IssueId         string     `json:"issue_id,omitempty"`
	CvssScore       *CvssScore `json:"cvss_score,omitempty"`
	SummaryContains string     `json:"summary_contains"`
	HasRemediation  bool       `json:"has_remediation,omitempty"`
}

type LicenseFilter struct {
	Unknown         bool     `json:"unknown"`
	Unrecognized    bool     `json:"unrecognized"`
	LicenseNames    []string `json:"license_names,omitempty"`
	LicensePatterns []string `json:"license_patterns"`
}

func unpackReport(d *schema.ResourceData, reportType string) *Report {
	report := Report{}

	if v, ok := d.GetOk("project_key"); ok {
		report.ProjectKey = v.(string)
	}
	report.Name = d.Get("name").(string)

	report.Resources = unpackResources(d.Get("resources").(*schema.Set))

	if reportType == "vulnerabilities" {
		report.Filters = unpackVulnerabilitiesFilters(d.Get("filters").(*schema.Set))
	}

	if reportType == "licenses" {
		report.Filters = unpackLicensesFilters(d.Get("filters").(*schema.Set))
	}

	if reportType == "violations" {
		report.Filters = unpackViolationsFilters(d.Get("filters").(*schema.Set))
	}

	if reportType == "operationalRisks" {
		report.Filters = unpackOperationalRisksFilters(d.Get("filters").(*schema.Set))
	}

	return &report
}

func unpackReportProjectKey(d *schema.ResourceData) *Report {
	report := Report{}

	if v, ok := d.GetOk("project_key"); ok {
		report.ProjectKey = v.(string)
	}

	return &report
}

func unpackResources(configured *schema.Set) *Resources {
	var resources Resources
	m := configured.List()[0].(map[string]interface{})

	if m["repository"] != nil {
		resources.Repositories = unpackRepository(m["repository"].(*schema.Set))
	}

	if m["builds"] != nil {
		resources.Builds = unpackBuilds(m["builds"].(*schema.Set))
	}

	if m["release_bundles"] != nil {
		resources.ReleaseBundles = unpackReleaseBundles(m["release_bundles"].(*schema.Set))
	}

	if m["release_bundles"] != nil {
		resources.Projects = unpackProjects(m["projects"].(*schema.Set))
	}

	return &resources
}

func unpackRepository(d *schema.Set) *[]Repository {
	repos := d.List()

	if len(d.List()) > 0 {
		var repositories []Repository
		for _, raw := range repos {
			f := raw.(map[string]interface{})
			repository := Repository{
				Name:                f["name"].(string),
				IncludePathPatterns: sdk.CastToStringArr(f["include_path_patterns"].(*schema.Set).List()),
				ExcludePathPatterns: sdk.CastToStringArr(f["exclude_path_patterns"].(*schema.Set).List()),
			}
			repositories = append(repositories, repository)
		}
		return &repositories
	}

	return nil
}

func unpackBuilds(d *schema.Set) *Builds {
	if len(d.List()) > 0 {
		var builds Builds
		f := d.List()[0].(map[string]interface{})
		builds = Builds{
			Names:                  sdk.CastToStringArr(f["names"].(*schema.Set).List()),
			IncludePatterns:        sdk.CastToStringArr(f["include_patterns"].(*schema.Set).List()),
			ExcludePatterns:        sdk.CastToStringArr(f["exclude_patterns"].(*schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int),
		}
		return &builds
	}

	return nil
}

func unpackReleaseBundles(d *schema.Set) *ReleaseBundles {
	if len(d.List()) > 0 {
		var releaseBundles ReleaseBundles
		f := d.List()[0].(map[string]interface{})
		releaseBundles = ReleaseBundles{
			Names:                  sdk.CastToStringArr(f["names"].(*schema.Set).List()),
			IncludePatterns:        sdk.CastToStringArr(f["include_patterns"].(*schema.Set).List()),
			ExcludePatterns:        sdk.CastToStringArr(f["exclude_patterns"].(*schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int),
		}
		return &releaseBundles
	}

	return nil
}

func unpackProjects(d *schema.Set) *Projects {
	if len(d.List()) > 0 {
		var projects Projects
		f := d.List()[0].(map[string]interface{})
		projects = Projects{
			Names:                  sdk.CastToStringArr(f["names"].(*schema.Set).List()),
			IncludeKeyPatterns:     sdk.CastToStringArr(f["include_key_patterns"].(*schema.Set).List()),
			NumberOfLatestVersions: f["number_of_latest_versions"].(int),
		}
		return &projects
	}

	return nil
}

func unpackVulnerabilitiesFilters(filter *schema.Set) *Filters {
	var filters Filters
	m := filter.List()[0].(map[string]interface{})

	if m["vulnerable_component"] != nil {
		filters.VulnerableComponent = m["vulnerable_component"].(string)
	}

	if m["impacted_artifact"] != nil {
		filters.ImpactedArtifact = m["impacted_artifact"].(string)
	}

	filters.HasRemediation = m["has_remediation"].(bool)

	if m["cve"] != nil {
		filters.Cve = m["cve"].(string)
	}

	if m["issue_id"] != nil {
		filters.IssueId = m["issue_id"].(string)
	}

	filters.Severities = sdk.CastToStringArr(m["severities"].(*schema.Set).List())

	if m["cvss_score"] != nil {
		filters.CvssScore = unpackCvssScore(m["cvss_score"].(*schema.Set))
	}

	if m["published"] != nil {
		filters.Published = unpackStartAndEndDate(m["published"].(*schema.Set))
	}

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*schema.Set))
	}

	return &filters
}

func unpackLicensesFilters(filter *schema.Set) *Filters {
	var filters Filters
	m := filter.List()[0].(map[string]interface{})

	if m["component"] != nil {
		filters.Component = m["component"].(string)
	}

	if m["artifact"] != nil {
		filters.Artifact = m["artifact"].(string)
	}

	filters.Unknown = m["unknown"].(bool)
	filters.Unrecognized = m["unrecognized"].(bool)

	filters.LicenseNames = sdk.CastToStringArr(m["license_names"].(*schema.Set).List())
	filters.LicensePatterns = sdk.CastToStringArr(m["license_patterns"].(*schema.Set).List())

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*schema.Set))
	}

	return &filters
}

func unpackViolationsSecurityFilters(filter *schema.Set) *SecurityFilter {
	var securityFilter SecurityFilter
	m := filter.List()[0].(map[string]interface{})

	if m["cve"] != nil {
		securityFilter.Cve = m["cve"].(string)
	}

	if m["issue_id"] != nil {
		securityFilter.IssueId = m["issue_id"].(string)
	}

	if m["cvss_score"] != nil {
		securityFilter.CvssScore = unpackCvssScore(m["cvss_score"].(*schema.Set))
	}

	if m["summary_contains"] != nil {
		securityFilter.IssueId = m["summary_contains"].(string)
	}

	securityFilter.HasRemediation = m["has_remediation"].(bool)

	return &securityFilter
}

func unpackViolationsFilters(filter *schema.Set) *Filters {
	var filters Filters
	m := filter.List()[0].(map[string]interface{})

	if len(m) > 0 {

		if m["type"] != nil {
			filters.Type = m["type"].(string)
		}

		filters.WatchNames = sdk.CastToStringArr(m["watch_names"].(*schema.Set).List())
		filters.WatchPatterns = sdk.CastToStringArr(m["watch_patterns"].(*schema.Set).List())

		if m["component"] != nil {
			filters.Component = m["component"].(string)
		}

		if m["artifact"] != nil {
			filters.Artifact = m["artifact"].(string)
		}

		filters.PolicyNames = sdk.CastToStringArr(m["policy_names"].(*schema.Set).List())
		filters.Severities = sdk.CastToStringArr(m["severities"].(*schema.Set).List())

		if m["updated"].(*schema.Set).Len() > 0 {
			filters.Updated = unpackStartAndEndDate(m["updated"].(*schema.Set))
		}

		if m["security_filters"].(*schema.Set).Len() > 0 {
			filters.SecurityFilters = unpackViolationsSecurityFilters(m["security_filters"].(*schema.Set))
		}

		if m["license_filters"].(*schema.Set).Len() > 0 {
			filters.LicenseFilters = unpackViolationsLicensesFilters(m["license_filters"].(*schema.Set))
		}

		return &filters
	}
	return nil
}

func unpackViolationsLicensesFilters(filter *schema.Set) *LicenseFilter {
	var filters LicenseFilter
	m := filter.List()[0].(map[string]interface{})

	filters.Unknown = m["unknown"].(bool)
	filters.Unrecognized = m["unrecognized"].(bool)

	filters.LicenseNames = sdk.CastToStringArr(m["license_names"].(*schema.Set).List())
	filters.LicensePatterns = sdk.CastToStringArr(m["license_patterns"].(*schema.Set).List())

	return &filters
}

func unpackOperationalRisksFilters(filter *schema.Set) *Filters {
	var filters Filters
	m := filter.List()[0].(map[string]interface{})

	if m["component"] != nil {
		filters.Component = m["component"].(string)
	}
	if m["artifact"] != nil {
		filters.Artifact = m["artifact"].(string)
	}

	filters.Risks = sdk.CastToStringArr(m["risks"].(*schema.Set).List())

	if m["scan_date"] != nil {
		filters.ScanDate = unpackStartAndEndDate(m["scan_date"].(*schema.Set))
	}

	return &filters
}

func unpackCvssScore(d *schema.Set) *CvssScore {
	var cvssScore CvssScore

	if len(d.List()) > 0 {
		f := d.List()[0].(map[string]interface{})
		cvssScore = CvssScore{
			MinScore: f["min_score"].(float64),
			MaxScore: f["max_score"].(float64),
		}
		return &cvssScore
	}

	return nil
}

func unpackStartAndEndDate(d *schema.Set) *StartAndEndDate {
	var dates StartAndEndDate

	if len(d.List()) > 0 {
		f := d.List()[0].(map[string]interface{})
		dates = StartAndEndDate{
			Start: f["start"].(string),
			End:   f["end"].(string),
		}
		return &dates
	}

	return nil
}

func resourceXrayVulnerabilitiesReportCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return createReport("vulnerabilities", d, m)
}

func resourceXrayLicensesReportCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return createReport("licenses", d, m)
}

func resourceXrayViolationsReportCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return createReport("violations", d, m)
}

func resourceXrayOperationalRisksReportCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return createReport("operationalRisks", d, m)
}

func resourceXrayReportRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	report := Report{}

	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, projectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := req.
		SetResult(&report).
		SetPathParam("reportId", d.Id()).
		Get("xray/api/v1/reports/{reportId}")
	if err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			tflog.Warn(ctx, fmt.Sprintf("Xray report (%s) not found, removing from state", d.Id()))
			d.SetId("")
		}
		return diag.FromErr(err)
	}

	return nil
}

func resourceXrayReportDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, projectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	resp, err := req.
		SetPathParams(map[string]string{
			"reportId": d.Id(),
		}).
		Delete("xray/api/v1/reports/{reportId}")
	if err != nil && resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return diag.FromErr(err)
	}
	return nil
}

func createReport(reportType string, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	report := unpackReport(d, reportType)
	req, err := getRestyRequest(m.(util.ProvderMetadata).Client, report.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	_, err = req.SetBody(report).SetResult(&report).
		Post("xray/api/v1/reports/" + reportType)

	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fmt.Sprintf("%d", report.ReportId))

	return nil
}

func reportResourceDiff(_ context.Context, diff *schema.ResourceDiff, v interface{}) error {
	reportResources := diff.Get("resources").(*schema.Set).List()
	if len(reportResources) == 0 {
		return nil
	}

	// Verify only one resource attribute is set.
	for _, reportResource := range reportResources {
		r := reportResource.(map[string]interface{})

		var resourceCounter int

		if r["repository"].(*schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if r["builds"].(*schema.Set).Len() > 0 {
			resourceCounter += 1
		}
		if r["release_bundles"].(*schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if r["projects"].(*schema.Set).Len() > 0 {
			resourceCounter += 1
		}

		if resourceCounter > 1 {
			return fmt.Errorf("request payload is invalid as only one resource per report is allowed")
		}
	}
	// Verify filter fields
	reportFilters := diff.Get("filters").(*schema.Set).List()
	for _, reportFilter := range reportFilters {
		r := reportFilter.(map[string]interface{})

		if len(reportFilters) == 0 {
			return nil
		}
		// Check violations filter
		var watchCounter int
		if r["watch_names"] != nil && r["watch_names"].(*schema.Set).Len() > 0 {
			watchCounter += 1
		}

		if r["watch_patterns"] != nil && r["watch_patterns"].(*schema.Set).Len() > 0 {
			watchCounter += 1
		}

		if watchCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'watch_names' or 'watch_patterns' is allowed in the violations filter")
		}
		// Check vulnerabilities filter
		var secFilterCounter int
		if r["cve"] != nil && r["cve"] != "" {
			secFilterCounter += 1
		}

		if r["issue_id"] != nil && r["issue_id"] != "" {
			secFilterCounter += 1
		}

		if secFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'cve' or 'issue_id' is allowed in the vulnerabilities filter")
		}

		var severitiesFilterCounter int
		if r["severities"] != nil && r["severities"].(*schema.Set).Len() > 0 {
			severitiesFilterCounter += 1
		}

		if r["cvss_score"] != nil && r["cvss_score"].(*schema.Set).Len() > 0 {
			severitiesFilterCounter += 1
		}

		if severitiesFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'severities' or 'cvss_score' is allowed in the vulnerabilities filter")
		}

		// Check license filter in violations report
		var nestedLicenseFilterCounter int
		if r["license_filters"] != nil && r["license_filters"].(*schema.Set).Len() > 0 {
			m := r["license_filters"].(*schema.Set).List()[0].(map[string]interface{})
			if m["license_names"] != nil && m["license_names"].(*schema.Set).Len() > 0 {
				nestedLicenseFilterCounter += 1
			}
			if m["license_patterns"] != nil && m["license_patterns"].(*schema.Set).Len() > 0 {
				nestedLicenseFilterCounter += 1
			}
		}

		if nestedLicenseFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'license_names' or 'license_patterns' is allowed in the license filter")
		}

		// Check license filter in license report
		var licenseFilterCounter int
		if r["license_names"] != nil && r["license_names"].(*schema.Set).Len() > 0 {
			licenseFilterCounter += 1
		}

		if r["license_patterns"] != nil && r["license_patterns"].(*schema.Set).Len() > 0 {
			licenseFilterCounter += 1
		}

		if licenseFilterCounter > 1 {
			return fmt.Errorf("request payload is invalid. Only one of 'license_names' or 'license_patterns' is allowed in the license filter")
		}

		// Verify severities in Vulnerabilities and Violations filters
		if r["severities"] != nil && r["severities"].(*schema.Set).Len() > 0 {
			for _, severity := range r["severities"].(*schema.Set).List() {
				if !slices.Contains([]string{"Low", "Medium", "High", "Critical"}, severity.(string)) {
					return fmt.Errorf("'severity' attribute value must be one or several of 'Low', 'Medium', 'High', 'Critical'")
				}
			}
		}

		// Verify risks in Operational Risks filter
		if r["risks"] != nil && r["risks"].(*schema.Set).Len() > 0 {
			for _, severity := range r["risks"].(*schema.Set).List() {
				if !slices.Contains([]string{"None", "Low", "Medium", "High"}, severity.(string)) {
					return fmt.Errorf("'risks' attribute value must be one or several of 'None', 'Low', 'Medium', 'High'")
				}
			}
		}

	}
	return nil
}
