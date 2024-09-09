package xray

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-shared/util/sdk"
	"github.com/jfrog/terraform-provider-shared/validator"
)

const (
	PoliciesEndpoint = "xray/api/v2/policies"
	PolicyEndpoint   = "xray/api/v2/policies/{name}"
)

var validPackageTypesSupportedXraySecPolicies = []string{
	"alpine",
	"bower",
	"cargo",
	"composer",
	"conan",
	"conda",
	"cran",
	"debian",
	"docker",
	"generic",
	"go",
	"huggingface",
	"maven",
	"npm",
	"nuget",
	"oci",
	"pypi",
	"rpm",
	"rubygems",
	"terraformbe",
}

var commonActionsSchema = map[string]*schema.Schema{
	"webhooks": {
		Type:        schema.TypeSet,
		Optional:    true,
		Description: "A list of Xray-configured webhook URLs to be invoked if a violation is triggered.",
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	},
	"mails": {
		Type:        schema.TypeSet,
		Optional:    true,
		Description: "A list of email addressed that will get emailed when a violation is triggered.",
		Elem: &schema.Schema{
			Type:             schema.TypeString,
			ValidateDiagFunc: validator.IsEmail,
		},
	},
	"block_download": {
		Type:        schema.TypeSet,
		Required:    true,
		MaxItems:    1,
		Description: "Block download of artifacts that meet the Artifact Filter and Severity Filter specifications for this watch",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"unscanned": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: "Whether or not to block download of artifacts that meet the artifact `filters` for the associated `xray_watch` resource but have not been scanned yet. Can not be set to `true` if attribute `active` is `false`. Default value is `false`.",
				},
				"active": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: "Whether or not to block download of artifacts that meet the artifact and severity `filters` for the associated `xray_watch` resource. Default value is `false`.",
				},
			},
		},
	},
	"block_release_bundle_distribution": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Blocks Release Bundle distribution to Edge nodes if a violation is found. Default value is `false`.",
	},
	"block_release_bundle_promotion": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Blocks Release Bundle promotion if a violation is found. Default value is `false`.",
	},
	"fail_build": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Whether or not the related CI build should be marked as failed if a violation is triggered. This option is only available when the policy is applied to an `xray_watch` resource with a `type` of `builds`. Default value is `false`.",
	},
	"notify_deployer": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Sends an email message to component deployer with details about the generated Violations. Default value is `false`.",
	},
	"notify_watch_recipients": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Sends an email message to all configured recipients inside a specific watch with details about the generated Violations. Default value is `false`.",
	},
	"create_ticket_enabled": {
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Create Jira Ticket for this Policy Violation. Requires configured Jira integration. Default value is `false`.",
	},
	"build_failure_grace_period_in_days": {
		Type:             schema.TypeInt,
		Optional:         true,
		Description:      "Allow grace period for certain number of days. All violations will be ignored during this time. To be used only if `fail_build` is enabled.",
		ValidateDiagFunc: validator.IntAtLeast(0),
	},
}

var getPolicySchema = func(criteriaSchema map[string]*schema.Schema, actionsSchema map[string]*schema.Schema) map[string]*schema.Schema {
	return sdk.MergeMaps(
		getProjectKeySchema(false, ""),
		map[string]*schema.Schema{
			"name": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "Name of the policy (must be unique)",
				ValidateDiagFunc: validator.StringIsNotEmpty,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "More verbose description of the policy",
			},
			"type": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Type of the policy",
				ValidateDiagFunc: validator.StringInSlice(false, "security", "license", "operational_risk"),
			},
			"author": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User, who created the policy",
			},
			"created": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Creation timestamp",
			},
			"modified": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Modification timestamp",
			},
			"rule": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "A list of user-defined rules allowing you to trigger violations for specific vulnerability or license breaches by setting a license or security criteria, with a corresponding set of automatic actions according to your needs. Rules are processed according to the ascending order in which they are placed in the Rules list on the Policy. If a rule is met, the subsequent rules in the list will not be applied.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "Name of the rule",
							ValidateDiagFunc: validator.StringIsNotEmpty,
						},
						"priority": {
							Type:             schema.TypeInt,
							Required:         true,
							ValidateDiagFunc: validator.IntAtLeast(1),
							Description:      "Integer describing the rule priority. Must be at least 1",
						},
						"criteria": {
							Type:        schema.TypeSet,
							Required:    true,
							MinItems:    1,
							MaxItems:    1,
							Description: "The set of security conditions to examine when an scanned artifact is scanned.",
							Elem: &schema.Resource{
								Schema: criteriaSchema,
							},
						},
						"actions": {
							Type:        schema.TypeSet,
							MaxItems:    1,
							Required:    true,
							Description: "Specifies the actions to take once a security policy violation has been triggered.",
							Elem: &schema.Resource{
								Schema: actionsSchema,
							},
						},
					},
				},
			},
		},
	)
}

type PolicyCVSSRangeAPIModel struct {
	To   *float64 `json:"to,omitempty"`
	From *float64 `json:"from,omitempty"`
}

type PolicyExposuresAPIModel struct {
	MinSeverity  *string `json:"min_severity,omitempty"`
	Secrets      *bool   `json:"secrets,omitempty"`
	Applications *bool   `json:"applications,omitempty"`
	Services     *bool   `json:"services,omitempty"`
	Iac          *bool   `json:"iac,omitempty"`
}

type OperationalRiskCriteriaAPIModel struct {
	UseAndCondition               bool   `json:"use_and_condition"`
	IsEOL                         bool   `json:"is_eol"`
	ReleaseDateGreaterThanMonths  int64  `json:"release_date_greater_than_months,omitempty"`
	NewerVersionsGreaterThan      int64  `json:"newer_versions_greater_than,omitempty"`
	ReleaseCadencePerYearLessThan int64  `json:"release_cadence_per_year_less_than,omitempty"`
	CommitsLessThan               int64  `json:"commits_less_than,omitempty"`
	CommittersLessThan            int64  `json:"committers_less_than,omitempty"`
	Risk                          string `json:"risk,omitempty"`
}

type PolicyRuleCriteriaAPIModel struct {
	// Security Criteria
	MinimumSeverity string                   `json:"min_severity,omitempty"` // Omitempty is used because the empty field is conflicting with CVSSRange
	CVSSRange       *PolicyCVSSRangeAPIModel `json:"cvss_range,omitempty"`
	// Omitempty is used in FixVersionDependant because an empty field throws an error in Xray below 3.44.3
	FixVersionDependant bool                     `json:"fix_version_dependant,omitempty"`
	ApplicableCVEsOnly  bool                     `json:"applicable_cves_only,omitempty"`
	MaliciousPackage    bool                     `json:"malicious_package,omitempty"`
	VulnerabilityIds    []string                 `json:"vulnerability_ids,omitempty"`
	Exposures           *PolicyExposuresAPIModel `json:"exposures,omitempty"`
	PackageName         string                   `json:"package_name,omitempty"`
	PackageType         string                   `json:"package_type,omitempty"`
	PackageVersions     []string                 `json:"package_versions,omitempty"`
	// We use pointer for CVSSRange to address nil-verification for non-primitive types.
	// Unlike primitive types, when the non-primitive type in the struct is set
	// to nil, the empty key will be created in the JSON body anyway.
	// Since CVSSRange is conflicting with MinimumSeverity, Xray will throw an error if .
	// Pointer can be set to nil value, so we can remove CVSSRange entirely only
	// if it's a pointer.
	// The nil pointer is used in conjunction with the omitempty flag in the JSON tag,
	// to remove the key completely in the payload.

	// License Criteria
	AllowUnknown           *bool    `json:"allow_unknown,omitempty"`            // Omitempty is used because the empty field is conflicting with MultiLicensePermissive
	MultiLicensePermissive *bool    `json:"multi_license_permissive,omitempty"` // Omitempty is used because the empty field is conflicting with AllowUnknown
	BannedLicenses         []string `json:"banned_licenses,omitempty"`
	AllowedLicenses        []string `json:"allowed_licenses,omitempty"`

	// Operational Risk custom criteria
	OperationalRiskCustom  *OperationalRiskCriteriaAPIModel `json:"op_risk_custom,omitempty"`
	OperationalRiskMinRisk string                           `json:"op_risk_min_risk,omitempty"`
}

type BlockDownloadSettingsAPIModel struct {
	Unscanned bool `json:"unscanned"`
	Active    bool `json:"active"`
}

type PolicyRuleActionsAPIModel struct {
	Webhooks                       []string                      `json:"webhooks,omitempty"`
	Mails                          []string                      `json:"mails,omitempty"`
	FailBuild                      bool                          `json:"fail_build"`
	BlockDownload                  BlockDownloadSettingsAPIModel `json:"block_download"`
	BlockReleaseBundleDistribution bool                          `json:"block_release_bundle_distribution"`
	BlockReleaseBundlePromotion    bool                          `json:"block_release_bundle_promotion"`
	NotifyWatchRecipients          bool                          `json:"notify_watch_recipients"`
	NotifyDeployer                 bool                          `json:"notify_deployer"`
	CreateJiraTicketEnabled        bool                          `json:"create_ticket_enabled"`
	FailureGracePeriodDays         int64                         `json:"build_failure_grace_period_in_days,omitempty"`
	// License Actions
	CustomSeverity string `json:"custom_severity,omitempty"`
}

type PolicyRuleAPIModel struct {
	Name     string                      `json:"name"`
	Priority int64                       `json:"priority"`
	Criteria *PolicyRuleCriteriaAPIModel `json:"criteria"`
	Actions  PolicyRuleActionsAPIModel   `json:"actions"`
}

type PolicyAPIModel struct {
	Name        string                `json:"name"`
	Type        string                `json:"type"`
	ProjectKey  string                `json:"-"`
	Author      string                `json:"author,omitempty"` // Omitempty is used because the field is computed
	Description string                `json:"description"`
	Rules       *[]PolicyRuleAPIModel `json:"rules"`
	Created     string                `json:"created,omitempty"`  // Omitempty is used because the field is computed
	Modified    string                `json:"modified,omitempty"` // Omitempty is used because the field is computed
}

type PolicyError struct {
	Error string `json:"error"`
}

func unpackPolicy(d *schema.ResourceData) (*PolicyAPIModel, error) {
	policy := new(PolicyAPIModel)

	policy.Name = d.Get("name").(string)
	if v, ok := d.GetOk("type"); ok {
		policy.Type = v.(string)
	}
	if v, ok := d.GetOk("project_key"); ok {
		policy.ProjectKey = v.(string)
	}
	if v, ok := d.GetOk("description"); ok {
		policy.Description = v.(string)
	}
	if v, ok := d.GetOk("author"); ok {
		policy.Author = v.(string)
	}
	policyRules, err := unpackRules(d.Get("rule").(*schema.Set), policy.Type)
	policy.Rules = &policyRules

	return policy, err
}

func unpackRules(configured *schema.Set, policyType string) (policyRules []PolicyRuleAPIModel, err error) {
	var rules []PolicyRuleAPIModel

	for _, raw := range configured.List() {
		rule := new(PolicyRuleAPIModel)
		data := raw.(map[string]interface{})
		rule.Name = data["name"].(string)
		rule.Priority = data["priority"].(int64)

		rule.Criteria, err = unpackCriteria(data["criteria"].(*schema.Set), policyType)
		if v, ok := data["actions"]; ok {
			rule.Actions = unpackActions(v.(*schema.Set))
		}
		rules = append(rules, *rule)
	}

	return rules, err
}

func unpackSecurityCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteriaAPIModel {
	criteria := new(PolicyRuleCriteriaAPIModel)

	if v, ok := tfCriteria["fix_version_dependant"]; ok {
		criteria.FixVersionDependant = v.(bool)
	}
	if v, ok := tfCriteria["applicable_cves_only"]; ok {
		criteria.ApplicableCVEsOnly = v.(bool)
	}
	if v, ok := tfCriteria["malicious_package"]; ok {
		criteria.MaliciousPackage = v.(bool)
	}
	if v, ok := tfCriteria["vulnerability_ids"]; ok {
		criteria.VulnerabilityIds = sdk.CastToStringArr(v.(*schema.Set).List())
	}
	if _, ok := tfCriteria["exposures"]; ok {
		criteria.Exposures = unpackExposures(tfCriteria["exposures"].([]interface{}))
	}
	if v, ok := tfCriteria["package_name"]; ok {
		criteria.PackageName = v.(string)
	}
	if v, ok := tfCriteria["package_type"]; ok {
		criteria.PackageType = v.(string)
	}
	if v, ok := tfCriteria["package_versions"]; ok {
		criteria.PackageVersions = sdk.CastToStringArr(v.(*schema.Set).List())
	}
	// This is also picky about not allowing empty values to be set
	cvss := unpackCVSSRange(tfCriteria["cvss_range"].([]interface{}))
	if cvss == nil {
		criteria.MinimumSeverity = tfCriteria["min_severity"].(string)
	} else {
		criteria.CVSSRange = cvss
	}

	return criteria
}

func unpackLicenseCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteriaAPIModel {
	criteria := new(PolicyRuleCriteriaAPIModel)
	if v, ok := tfCriteria["allow_unknown"]; ok {
		criteria.AllowUnknown = sdk.BoolPtr(v.(bool))
	}
	if v, ok := tfCriteria["banned_licenses"]; ok {
		criteria.BannedLicenses = unpackLicenses(v.(*schema.Set))
	}
	if v, ok := tfCriteria["allowed_licenses"]; ok {
		criteria.AllowedLicenses = unpackLicenses(v.(*schema.Set))
	}
	if v, ok := tfCriteria["multi_license_permissive"]; ok {
		criteria.MultiLicensePermissive = sdk.BoolPtr(v.(bool))
	}

	return criteria
}

func unpackOperationalRiskCustomCriteria(tfCriteria map[string]interface{}) *OperationalRiskCriteriaAPIModel {
	criteria := OperationalRiskCriteriaAPIModel{}
	if v, ok := tfCriteria["use_and_condition"]; ok {
		criteria.UseAndCondition = v.(bool)
	}
	if v, ok := tfCriteria["is_eol"]; ok {
		criteria.IsEOL = v.(bool)
	}
	if v, ok := tfCriteria["release_date_greater_than_months"]; ok {
		criteria.ReleaseDateGreaterThanMonths = v.(int64)
	}
	if v, ok := tfCriteria["newer_versions_greater_than"]; ok {
		criteria.NewerVersionsGreaterThan = v.(int64)
	}
	if v, ok := tfCriteria["release_cadence_per_year_less_than"]; ok {
		criteria.ReleaseCadencePerYearLessThan = v.(int64)
	}
	if v, ok := tfCriteria["commits_less_than"]; ok {
		criteria.CommitsLessThan = v.(int64)
	}
	if v, ok := tfCriteria["committers_less_than"]; ok {
		criteria.CommittersLessThan = v.(int64)
	}
	if v, ok := tfCriteria["risk"]; ok {
		criteria.Risk = v.(string)
	}

	return &criteria
}

func unpackOperationalRiskCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteriaAPIModel {
	criteria := new(PolicyRuleCriteriaAPIModel)
	if v, ok := tfCriteria["op_risk_custom"]; ok {
		custom := v.([]interface{})
		if len(custom) > 0 {
			criteria.OperationalRiskCustom = unpackOperationalRiskCustomCriteria(custom[0].(map[string]interface{}))
		}
	}
	if v, ok := tfCriteria["op_risk_min_risk"]; ok {
		criteria.OperationalRiskMinRisk = v.(string)
	}

	return criteria
}

func unpackCriteria(d *schema.Set, policyType string) (*PolicyRuleCriteriaAPIModel, error) {
	tfCriteria := d.List()
	if len(tfCriteria) == 0 {
		return nil, nil
	}

	m := tfCriteria[0].(map[string]interface{}) // We made this a list of one to make schema validation easier
	var criteria *PolicyRuleCriteriaAPIModel
	// criteria := new(PolicyRuleCriteria)
	// The API doesn't allow both severity and license criteria to be _set_, even if they have empty values
	// So we have to figure out which group is actually empty and not even set it
	if policyType == "license" {
		criteria = unpackLicenseCriteria(m)
	} else if policyType == "security" {
		criteria = unpackSecurityCriteria(m)
	} else if policyType == "operational_risk" {
		criteria = unpackOperationalRiskCriteria(m)
	}

	return criteria, nil
}

func Float64Ptr(v float64) *float64 { return &v }

func StringPtr(v string) *string { return &v }

func unpackCVSSRange(l []interface{}) *PolicyCVSSRangeAPIModel {
	if len(l) == 0 {
		return nil
	}

	m := l[0].(map[string]interface{})
	cvssrange := &PolicyCVSSRangeAPIModel{
		From: Float64Ptr(m["from"].(float64)),
		To:   Float64Ptr(m["to"].(float64)),
	}
	return cvssrange
}

func unpackExposures(l []interface{}) *PolicyExposuresAPIModel {
	if len(l) == 0 {
		return nil
	}

	m := l[0].(map[string]interface{})
	exposures := &PolicyExposuresAPIModel{
		MinSeverity:  StringPtr(m["min_severity"].(string)),
		Secrets:      sdk.BoolPtr(m["secrets"].(bool)),
		Applications: sdk.BoolPtr(m["applications"].(bool)),
		Services:     sdk.BoolPtr(m["services"].(bool)),
		Iac:          sdk.BoolPtr(m["iac"].(bool)),
	}
	return exposures
}

func unpackLicenses(d *schema.Set) []string {
	var licenses []string
	for _, license := range d.List() {
		licenses = append(licenses, license.(string))
	}
	return licenses
}

func unpackActions(l *schema.Set) PolicyRuleActionsAPIModel {
	actions := PolicyRuleActionsAPIModel{}
	policyActions := l.List()

	if len(policyActions) > 0 {
		m := policyActions[0].(map[string]interface{}) // We made this a list of one to make schema validation easier
		if v, ok := m["webhooks"]; ok {
			m := v.(*schema.Set).List()
			var webhooks []string
			for _, hook := range m {
				webhooks = append(webhooks, hook.(string))
			}
			actions.Webhooks = webhooks
		}
		if v, ok := m["mails"]; ok {
			m := v.(*schema.Set).List()
			var mails []string
			for _, mail := range m {
				mails = append(mails, mail.(string))
			}
			actions.Mails = mails
		}
		if v, ok := m["fail_build"]; ok {
			actions.FailBuild = v.(bool)
		}

		if v, ok := m["block_download"]; ok {
			if len(v.(*schema.Set).List()) > 0 {
				vList := v.(*schema.Set).List()
				vMap := vList[0].(map[string]interface{})

				actions.BlockDownload = BlockDownloadSettingsAPIModel{
					Unscanned: vMap["unscanned"].(bool),
					Active:    vMap["active"].(bool),
				}
			} else {
				actions.BlockDownload = BlockDownloadSettingsAPIModel{
					Unscanned: false,
					Active:    false,
				}
				// Setting this false/false block feels like it _should_ work, since putting a false/false block in the terraform resource works fine
				// However, it doesn't, and we end up getting this diff when running acceptance tests when this is optional in the schema
				// rule.0.actions.0.block_download.#:           "1" => "0"
				// rule.0.actions.0.block_download.0.active:    "false" => ""
				// rule.0.actions.0.block_download.0.unscanned: "false" => ""
			}
		}

		if v, ok := m["block_release_bundle_distribution"]; ok {
			actions.BlockReleaseBundleDistribution = v.(bool)
		}
		if v, ok := m["block_release_bundle_promotion"]; ok {
			actions.BlockReleaseBundlePromotion = v.(bool)
		}
		if v, ok := m["notify_watch_recipients"]; ok {
			actions.NotifyWatchRecipients = v.(bool)
		}
		if v, ok := m["notify_deployer"]; ok {
			actions.NotifyDeployer = v.(bool)
		}
		if v, ok := m["create_ticket_enabled"]; ok {
			actions.CreateJiraTicketEnabled = v.(bool)
		}
		if v, ok := m["build_failure_grace_period_in_days"]; ok {
			actions.FailureGracePeriodDays = v.(int64)
		}
		if v, ok := m["custom_severity"]; ok {
			actions.CustomSeverity = v.(string)
		}

		return actions
	}
	return actions
}

func packRules(rules []PolicyRuleAPIModel, policyType string) []interface{} {
	var rs []interface{}

	for _, rule := range rules {
		var criteria []interface{}
		var isLicense bool

		switch policyType {
		case "license":
			criteria = packLicenseCriteria(rule.Criteria)
			isLicense = true
		case "security":
			criteria = packSecurityCriteria(rule.Criteria)
			isLicense = false
		case "operational_risk":
			criteria = packOperationalRiskCriteria(rule.Criteria)
			isLicense = false
		}

		r := map[string]interface{}{
			"name":     rule.Name,
			"priority": rule.Priority,
			"criteria": criteria,
			"actions":  packActions(rule.Actions, isLicense),
		}

		rs = append(rs, r)
	}

	return rs
}

func packOperationalRiskCriteria(criteria *PolicyRuleCriteriaAPIModel) []interface{} {
	m := map[string]interface{}{}

	if len(criteria.OperationalRiskMinRisk) > 0 {
		m["op_risk_min_risk"] = criteria.OperationalRiskMinRisk
	}
	if criteria.OperationalRiskCustom != nil {
		m["op_risk_custom"] = packOperationalRiskCustom(criteria.OperationalRiskCustom)
	}

	return []interface{}{m}
}

func packOperationalRiskCustom(custom *OperationalRiskCriteriaAPIModel) []interface{} {
	m := map[string]interface{}{
		"use_and_condition":                  custom.UseAndCondition,
		"is_eol":                             custom.IsEOL,
		"release_date_greater_than_months":   custom.ReleaseDateGreaterThanMonths,
		"newer_versions_greater_than":        custom.NewerVersionsGreaterThan,
		"release_cadence_per_year_less_than": custom.ReleaseCadencePerYearLessThan,
		"commits_less_than":                  custom.CommitsLessThan,
		"committers_less_than":               custom.CommittersLessThan,
		"risk":                               custom.Risk,
	}

	return []interface{}{m}
}

func packLicenseCriteria(criteria *PolicyRuleCriteriaAPIModel) []interface{} {

	m := map[string]interface{}{}

	if criteria.BannedLicenses != nil {
		m["banned_licenses"] = criteria.BannedLicenses
	}
	if criteria.AllowedLicenses != nil {
		m["allowed_licenses"] = criteria.AllowedLicenses
	}
	m["allow_unknown"] = criteria.AllowUnknown
	m["multi_license_permissive"] = criteria.MultiLicensePermissive

	return []interface{}{m}
}

func packSecurityCriteria(criteria *PolicyRuleCriteriaAPIModel) []interface{} {
	m := map[string]interface{}{}
	// cvss_range and min_severity are conflicting, only one can be present in the JSON
	m["cvss_range"] = packCVSSRange(criteria.CVSSRange)
	m["vulnerability_ids"] = criteria.VulnerabilityIds
	minSeverity := criteria.MinimumSeverity
	// This is only needed for versions before 3.60.2 because a Xray API bug where it returns "Unknown" for "All severities" min severity setting
	// See release note: https://www.jfrog.com/confluence/display/JFROG/Xray+Release+Notes#XrayReleaseNotes-Xray3.60.2
	// Issue: XRAY-9271
	if criteria.MinimumSeverity == "Unknown" {
		minSeverity = "All severities"
	}
	m["min_severity"] = minSeverity
	m["fix_version_dependant"] = criteria.FixVersionDependant
	m["applicable_cves_only"] = criteria.ApplicableCVEsOnly
	m["malicious_package"] = criteria.MaliciousPackage
	m["exposures"] = packExposures(criteria.Exposures)
	m["package_name"] = criteria.PackageName
	m["package_type"] = criteria.PackageType
	m["package_versions"] = criteria.PackageVersions

	return []interface{}{m}
}

func packCVSSRange(cvss *PolicyCVSSRangeAPIModel) []interface{} {
	if cvss == nil {
		return []interface{}{}
	}
	m := map[string]interface{}{
		"from": *cvss.From,
		"to":   *cvss.To,
	}
	return []interface{}{m}
}

func packExposures(exposures *PolicyExposuresAPIModel) []interface{} {
	if exposures == nil {
		return []interface{}{}
	}
	m := map[string]interface{}{
		"min_severity": *exposures.MinSeverity,
		"secrets":      *exposures.Secrets,
		"applications": *exposures.Applications,
		"services":     *exposures.Services,
		"iac":          *exposures.Iac,
	}
	return []interface{}{m}
}

func packActions(actions PolicyRuleActionsAPIModel, license bool) []interface{} {
	m := map[string]interface{}{
		"block_download":                     packBlockDownload(actions.BlockDownload),
		"webhooks":                           actions.Webhooks,
		"mails":                              actions.Mails,
		"fail_build":                         actions.FailBuild,
		"block_release_bundle_distribution":  actions.BlockReleaseBundleDistribution,
		"block_release_bundle_promotion":     actions.BlockReleaseBundlePromotion,
		"notify_watch_recipients":            actions.NotifyWatchRecipients,
		"notify_deployer":                    actions.NotifyDeployer,
		"create_ticket_enabled":              actions.CreateJiraTicketEnabled,
		"build_failure_grace_period_in_days": actions.FailureGracePeriodDays,
	}

	if license {
		m["custom_severity"] = actions.CustomSeverity
	}

	return []interface{}{m}
}

func packBlockDownload(bd BlockDownloadSettingsAPIModel) []interface{} {
	m := map[string]interface{}{}
	m["unscanned"] = bd.Unscanned
	m["active"] = bd.Active
	return []interface{}{m}
}

func packPolicy(policy PolicyAPIModel, d *schema.ResourceData) diag.Diagnostics {
	if err := d.Set("name", policy.Name); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("type", policy.Type); err != nil {
		return diag.FromErr(err)
	}
	if len(policy.Description) > 0 {
		if err := d.Set("description", policy.Description); err != nil {
			return diag.FromErr(err)
		}
	}
	if err := d.Set("author", policy.Author); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("created", policy.Created); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("modified", policy.Modified); err != nil {
		return diag.FromErr(err)
	}
	if policy.Rules != nil {
		if err := d.Set("rule", packRules(*policy.Rules, policy.Type)); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func resourceXrayPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy, err := unpackPolicy(d)
	// Warning or errors can be collected in a slice type
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, policy.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	var policyError PolicyError
	resp, err := req.
		SetBody(policy).
		SetError(&policyError).
		Post("xray/api/v2/policies")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("%s", policyError.Error)
	}

	d.SetId(policy.Name)
	return resourceXrayPolicyRead(ctx, d, m)
}

func resourceXrayPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var policy PolicyAPIModel

	projectKey := d.Get("project_key").(string)
	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, projectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	var policyError PolicyError
	resp, err := req.
		SetResult(&policy).
		SetPathParam("name", d.Id()).
		SetError(&policyError).
		Get("xray/api/v2/policies/{name}")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		d.SetId("")
		return diag.Errorf("policy (%s) not found, removing from state", d.Id())
	}
	if resp.IsError() {
		return diag.Errorf("%s", policyError.Error)
	}

	return packPolicy(policy, d)
}

func resourceXrayPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy, err := unpackPolicy(d)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, policy.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	var policyError PolicyError
	resp, err := req.
		SetBody(policy).
		SetPathParams(map[string]string{
			"name": d.Id(),
		}).
		SetError(&policyError).
		Put("xray/api/v2/policies/{name}")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("%s", policyError.Error)
	}

	d.SetId(policy.Name)
	return resourceXrayPolicyRead(ctx, d, m)
}

func resourceXrayPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy, err := unpackPolicy(d)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := getRestyRequest(m.(util.ProviderMetadata).Client, policy.ProjectKey)
	if err != nil {
		return diag.FromErr(err)
	}

	var policyError PolicyError
	resp, err := req.
		SetPathParams(map[string]string{
			"name": d.Id(),
		}).
		SetError(&policyError).
		Delete("xray/api/v2/policies/{name}")
	if err != nil {
		return diag.FromErr(err)
	}
	if resp.IsError() {
		return diag.Errorf("%s", policyError.Error)
	}

	d.SetId("")

	return nil
}
