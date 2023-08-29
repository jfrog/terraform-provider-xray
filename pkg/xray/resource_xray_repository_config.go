package xray

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-shared/validator"
	"golang.org/x/exp/slices"
)

type RepoConfiguration struct {
	// Omitempty is used because 'vuln_contextual_analysis' is not supported by self-hosted Xray installation.
	VulnContextualAnalysis *bool      `json:"vuln_contextual_analysis,omitempty"`
	RetentionInDays        int        `json:"retention_in_days,omitempty"`
	Exposures              *Exposures `json:"exposures,omitempty"`
}

type Exposures struct {
	ScannersCategory map[string]bool `json:"scanners_category"`
}

type PathsConfiguration struct {
	Patterns       []Pattern         `json:"patterns,omitempty"`
	OtherArtifacts AllOtherArtifacts `json:"all_other_artifacts,omitempty"`
}

type Pattern struct {
	Include           string `json:"include"`
	Exclude           string `json:"exclude"`
	IndexNewArtifacts bool   `json:"index_new_artifacts"`
	RetentionInDays   int    `json:"retention_in_days"`
}

type AllOtherArtifacts struct {
	IndexNewArtifacts bool `json:"index_new_artifacts"`
	RetentionInDays   int  `json:"retention_in_days"`
}

type RepositoryConfiguration struct {
	RepoName string `json:"repo_name"`
	// Pointer is used to be able to verify if the RepoConfig or PathsConfiguration struct is nil
	RepoConfig      *RepoConfiguration  `json:"repo_config,omitempty"`
	RepoPathsConfig *PathsConfiguration `json:"repo_paths_config,omitempty"`
}

var exposuresPackageTypes = func(xrayVersion string) []string {
	packageTypes := []string{"docker", "terraformbackend"}

	if ok, err := sdk.CheckVersion(xrayVersion, "3.78.9"); err == nil && ok {
		packageTypes = append(packageTypes, "maven", "npm", "pypi")
	}

	return packageTypes
}

var vulnContextualAnalysisPackageTypes = func(xrayVersion string) []string {
	packageTypes := []string{"docker"}

	if ok, err := sdk.CheckVersion(xrayVersion, "3.77.4"); err == nil && ok {
		packageTypes = append(packageTypes, "maven")
	}

	return packageTypes
}

func resourceXrayRepositoryConfig() *schema.Resource {
	var repositoryConfigSchema = map[string]*schema.Schema{
		"repo_name": {
			Type:             schema.TypeString,
			Required:         true,
			Description:      "Repository name.",
			ValidateDiagFunc: validator.StringIsNotEmpty,
		},
		"config": {
			Type:          schema.TypeSet,
			Optional:      true,
			MaxItems:      1,
			Description:   "Single repository configuration. Only one of 'config' or 'paths_config' can be set.",
			ConflictsWith: []string{"paths_config"},
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"vuln_contextual_analysis": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Only for SaaS instances, will be available after Xray 3.59. Enables vulnerability contextual analysis. Must be set together with `exposures`. Supported for Docker, OCI, and Maven package types.",
					},
					"retention_in_days": {
						Type:             schema.TypeInt,
						Optional:         true,
						Default:          90,
						Description:      "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
						ValidateDiagFunc: validator.IntAtLeast(0),
					},
					"exposures": {
						Type:        schema.TypeSet,
						Optional:    true,
						MinItems:    1,
						MaxItems:    1,
						Description: "Enables Xray to perform scans for multiple categories that cover security issues in your configurations and the usage of open source libraries in your code. Available only to CLOUD (SaaS)/SELF HOSTED for ENTERPRISE X and ENTERPRISE+ with Advanced DevSecOps. Must be set together with `vuln_contextual_analysis`. Supported for Docker, Maven, NPM, PyPi, and Terraform Backend package type.",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"scanners_category": {
									Type:     schema.TypeSet,
									Required: true,
									MaxItems: 1,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"services": {
												Type:        schema.TypeBool,
												Optional:    true,
												Description: "Detect whether common OSS libraries and services are configured securely, so application can be easily hardened by default.",
											},
											"secrets": {
												Type:        schema.TypeBool,
												Optional:    true,
												Description: "Detect any secret left exposed in any containers stored in Artifactory to stop any accidental leak of internal tokens or credentials.",
											},
											"iac": {
												Type:        schema.TypeBool,
												Optional:    true,
												Description: "Scans IaC files stored in Artifactory for early detection of cloud and infrastructure misconfigurations to prevent attacks and data leak. Only supported by Terraform Backend package type.",
											},
											"applications": {
												Type:        schema.TypeBool,
												Optional:    true,
												Description: "Detect whether common OSS libraries and services are used securely by the application.",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"paths_config": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: `Enables you to set a more granular retention period. It enables you to scan future artifacts within the specific path, and set a retention period for the historical data of artifacts after they are scanned`,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"pattern": {
						Type:        schema.TypeList,
						Required:    true,
						MinItems:    1,
						Description: `Pattern, applied to the repositories.`,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"include": {
									Type:             schema.TypeString,
									Required:         true,
									Description:      `Include pattern.`,
									ValidateDiagFunc: validator.StringIsNotEmpty,
								},
								"exclude": {
									Type:             schema.TypeString,
									Optional:         true,
									Description:      `Exclude pattern.`,
									ValidateDiagFunc: validator.StringIsNotEmpty,
								},
								"index_new_artifacts": {
									Type:        schema.TypeBool,
									Optional:    true,
									Default:     true,
									Description: `If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.`,
								},
								"retention_in_days": {
									Type:             schema.TypeInt,
									Optional:         true,
									Default:          90,
									Description:      `The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.`,
									ValidateDiagFunc: validator.IntAtLeast(0),
								},
							},
						},
					},
					"all_other_artifacts": {
						Type:        schema.TypeSet,
						Required:    true,
						Description: `If you select by pattern, you must define a retention period for all other artifacts in the repository in the All Other Artifacts setting.`,
						MinItems:    1,
						MaxItems:    1,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"index_new_artifacts": {
									Type:        schema.TypeBool,
									Optional:    true,
									Default:     true,
									Description: `If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.`,
								},
								"retention_in_days": {
									Type:             schema.TypeInt,
									Optional:         true,
									Default:          90,
									Description:      `The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.`,
									ValidateDiagFunc: validator.IntAtLeast(0),
								},
							},
						},
					},
				},
			},
		},
	}

	var unpackPattern = func(s []interface{}) []Pattern {
		var patterns []Pattern

		for _, raw := range s {
			data := raw.(map[string]interface{})
			pattern := Pattern{
				Include:           data["include"].(string),
				Exclude:           data["exclude"].(string),
				IndexNewArtifacts: data["index_new_artifacts"].(bool),
				RetentionInDays:   data["retention_in_days"].(int),
			}
			patterns = append(patterns, pattern)
		}

		return patterns
	}

	var unpackAllOtherArtifacts = func(config *schema.Set) AllOtherArtifacts {
		allOtherArtifacts := AllOtherArtifacts{}

		if config != nil {
			data := config.List()[0].(map[string]interface{})
			allOtherArtifacts.IndexNewArtifacts = data["index_new_artifacts"].(bool)
			allOtherArtifacts.RetentionInDays = data["retention_in_days"].(int)
		}

		return allOtherArtifacts
	}

	var unpackRepoPathConfig = func(config *schema.Set) *PathsConfiguration {
		repoPathsConfiguration := new(PathsConfiguration)
		configList := config.List()
		if len(configList) == 0 {
			return nil
		}

		m := configList[0].(map[string]interface{})

		otherArtifacts := unpackAllOtherArtifacts(m["all_other_artifacts"].(*schema.Set))
		repoPathsConfiguration.OtherArtifacts = otherArtifacts

		repoPathsConfiguration.Patterns = unpackPattern(m["pattern"].([]interface{}))

		return repoPathsConfiguration
	}

	var unpackExposures = func(config *schema.Set, xrayVersion, packageType string) *Exposures {
		if !slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
			return nil
		}

		if len(config.List()) == 0 {
			return nil
		}

		e := config.List()[0].(map[string]interface{})
		s := e["scanners_category"].(*schema.Set)
		if len(s.List()) == 0 {
			return nil
		}

		category := s.List()[0].(map[string]interface{})

		exposures := Exposures{}

		switch packageType {
		case "docker":
			exposures.ScannersCategory = map[string]bool{
				"services_scan":     category["services"].(bool),
				"secrets_scan":      category["secrets"].(bool),
				"applications_scan": category["applications"].(bool),
			}
		case "maven":
			exposures.ScannersCategory = map[string]bool{
				"secrets_scan": category["secrets"].(bool),
			}
		case "npm", "pypi":
			exposures.ScannersCategory = map[string]bool{
				"secrets_scan":      category["secrets"].(bool),
				"applications_scan": category["applications"].(bool),
			}
		case "terraformbackend":
			exposures.ScannersCategory = map[string]bool{
				"iac_scan": category["iac"].(bool),
			}
		}

		return &exposures
	}

	var unpackRepoConfig = func(config *schema.Set, xrayVersion, packageType string) *RepoConfiguration {
		repoConfig := new(RepoConfiguration)

		if config != nil {
			data := config.List()[0].(map[string]interface{})
			if slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
				vulnContextualAnalysis := data["vuln_contextual_analysis"].(bool)
				repoConfig.VulnContextualAnalysis = &vulnContextualAnalysis
			}
			repoConfig.RetentionInDays = data["retention_in_days"].(int)
			repoConfig.Exposures = unpackExposures(data["exposures"].(*schema.Set), xrayVersion, packageType)
		}

		return repoConfig
	}

	var unpackRepositoryConfig = func(s *schema.ResourceData, xrayVersion, packageType string) RepositoryConfiguration {
		d := &sdk.ResourceData{ResourceData: s}

		repositoryConfig := RepositoryConfiguration{
			RepoName: d.GetString("repo_name", false),
		}

		if v, ok := s.GetOk("config"); ok {
			repositoryConfig.RepoConfig = unpackRepoConfig(v.(*schema.Set), xrayVersion, packageType)
		}

		if v, ok := s.GetOk("paths_config"); ok {
			repositoryConfig.RepoPathsConfig = unpackRepoPathConfig(v.(*schema.Set))
		}
		return repositoryConfig
	}

	var packExposures = func(exposures *Exposures, packageType string) []interface{} {
		scannersCategory := map[string]bool{
			"services":     false,
			"secrets":      false,
			"iac":          false,
			"applications": false,
		}

		switch packageType {
		case "docker":
			scannersCategory["services"] = exposures.ScannersCategory["services_scan"]
			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
			scannersCategory["applications"] = exposures.ScannersCategory["applications_scan"]
		case "maven":
			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
		case "npm", "pypi":
			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
			scannersCategory["applications"] = exposures.ScannersCategory["applications_scan"]
		case "terraformbackend":
			scannersCategory["iac"] = exposures.ScannersCategory["iac_scan"]
		}

		return []interface{}{
			map[string][]map[string]bool{
				"scanners_category": {scannersCategory},
			},
		}
	}

	var packGeneralRepoConfig = func(repoConfig *RepoConfiguration, xrayVersion, packageType string) []interface{} {
		if repoConfig == nil {
			return []interface{}{}
		}

		m := map[string]interface{}{
			"retention_in_days": repoConfig.RetentionInDays,
		}

		if slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
			m["vuln_contextual_analysis"] = *repoConfig.VulnContextualAnalysis
		}

		if slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
			m["exposures"] = packExposures(repoConfig.Exposures, packageType)
		}

		return []interface{}{m}
	}

	var packAllOtherArtifacts = func(otherArtifacts AllOtherArtifacts) []interface{} {
		m := map[string]interface{}{
			"index_new_artifacts": otherArtifacts.IndexNewArtifacts,
			"retention_in_days":   otherArtifacts.RetentionInDays,
		}

		return []interface{}{m}
	}

	var packPatterns = func(patterns []Pattern) []interface{} {
		var ps []interface{}

		for _, pattern := range patterns {
			p := map[string]interface{}{
				"include":             pattern.Include,
				"exclude":             pattern.Exclude,
				"index_new_artifacts": pattern.IndexNewArtifacts,
				"retention_in_days":   pattern.RetentionInDays,
			}

			ps = append(ps, p)
		}

		return ps
	}

	var packRepoPathsConfigList = func(repoPathsConfig *PathsConfiguration) []interface{} {
		if repoPathsConfig == nil {
			return []interface{}{}
		}

		m := map[string]interface{}{
			"pattern":             packPatterns(repoPathsConfig.Patterns),
			"all_other_artifacts": packAllOtherArtifacts(repoPathsConfig.OtherArtifacts),
		}

		return []interface{}{m}
	}

	var packRepositoryConfig = func(ctx context.Context, repositoryConfig RepositoryConfiguration, d *schema.ResourceData, xrayVersion, packageType string) diag.Diagnostics {
		if err := d.Set("repo_name", repositoryConfig.RepoName); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("config", packGeneralRepoConfig(repositoryConfig.RepoConfig, xrayVersion, packageType)); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("paths_config", packRepoPathsConfigList(repositoryConfig.RepoPathsConfig)); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}

	var getPackageType = func(client *resty.Client, repoKey string) (repoType string, err error) {
		type Repository struct {
			PackageType string `json:"packageType"`
		}

		repo := Repository{}

		_, err = client.R().
			SetResult(&repo).
			SetPathParam("repoKey", repoKey).
			Get("artifactory/api/repositories/{repoKey}")
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return "", err
		}

		return repo.PackageType, nil
	}

	var resourceXrayRepositoryConfigRead = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		repositoryConfig := RepositoryConfiguration{}
		repoName := d.Id()

		metadata := m.(sdk.ProvderMetadata)

		resp, err := metadata.Client.R().
			SetResult(&repositoryConfig).
			SetPathParam("repo_name", repoName).
			Get("xray/api/v1/repos_config/{repo_name}")

		if err != nil {
			if resp != nil && resp.StatusCode() != http.StatusOK {
				tflog.Error(ctx, fmt.Sprintf("Repo (%s) is either not indexed or does not exist", repoName))
				d.SetId("")
			}
			return diag.FromErr(err)
		}

		packageType, err := getPackageType(metadata.Client, repoName)
		if err != nil {
			return diag.FromErr(err)
		}

		return packRepositoryConfig(ctx, repositoryConfig, d, metadata.XrayVersion, packageType)
	}

	var resourceXrayRepositoryConfigCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		metadata := m.(sdk.ProvderMetadata)
		packageType, err := getPackageType(metadata.Client, d.Get("repo_name").(string))
		if err != nil {
			return diag.FromErr(err)
		}

		repositoryConfig := unpackRepositoryConfig(d, metadata.XrayVersion, packageType)

		_, err = metadata.Client.R().SetBody(&repositoryConfig).Put("xray/api/v1/repos_config")
		if err != nil {
			return diag.FromErr(err)
		}

		d.SetId(repositoryConfig.RepoName)
		return resourceXrayRepositoryConfigRead(ctx, d, m)
	}

	// No delete functionality provided by API.
	// Delete function will return a warning and remove the Id from the state.
	// The option with restoring a default configuration is not viable, because the default can be changed.
	var resourceXrayRepositoryConfigDelete = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
		tflog.Warn(ctx, fmt.Sprintf("There is no delete dunctionality in the API, so the configuration is not "+
			"removed from the Artifactory, but (%s) is removed from the Terraform state", d.Id()))
		d.SetId("")

		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  "No delete functionality provided by API",
			Detail:   "Delete function will return a warning and remove the Id from the Terraform state. The actual repository configuration will remain unchanged.",
		}}
	}

	return &schema.Resource{
		CreateContext: resourceXrayRepositoryConfigCreate,
		ReadContext:   resourceXrayRepositoryConfigRead,
		UpdateContext: resourceXrayRepositoryConfigCreate,
		DeleteContext: resourceXrayRepositoryConfigDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema:      repositoryConfigSchema,
		Description: "Provides an Xray repository config resource. See [Xray Indexing Resources](https://www.jfrog.com/confluence/display/JFROG/Indexing+Xray+Resources#IndexingXrayResources-SetaRetentionPeriod) and [REST API](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-UpdateRepositoriesConfigurations) for more details.",
	}

}
