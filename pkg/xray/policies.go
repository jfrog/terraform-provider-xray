package xray

import (
	"context"
	"log"
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/util"
)

type PolicyCVSSRange struct {
	To   *float64 `json:"to,omitempty"`
	From *float64 `json:"from,omitempty"`
}

type OperationalRiskCriteria struct {
	UseAndCondition               bool   `json:"use_and_condition"`
	IsEOL                         bool   `json:"is_eol"`
	ReleaseDateGreaterThanMonths  int    `json:"release_date_greater_than_months"`
	NewerVersionsGreaterThan      int    `json:"newer_versions_greater_than"`
	ReleaseCadencePerYearLessThan int    `json:"release_cadence_per_year_less_than"`
	CommitsLessThan               int    `json:"commits_less_than"`
	CommittersLessThan            int    `json:"committers_less_than"`
	Risk                          string `json:"risk"`
}

type PolicyRuleCriteria struct {
	// Security Criteria
	MinimumSeverity string           `json:"min_severity,omitempty"` // Omitempty is used because the empty field is conflicting with CVSSRange
	CVSSRange       *PolicyCVSSRange `json:"cvss_range,omitempty"`
	// Omitempty is used in FixVersionDependant because an empty field throws an error in Xray below 3.44.3
	FixVersionDependant bool `json:"fix_version_dependant,omitempty"`
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
	OperationalRiskCustom  *OperationalRiskCriteria `json:"op_risk_custom,omitempty"`
	OperationalRiskMinRisk string                   `json:"op_risk_min_risk,omitempty"`
}

type BlockDownloadSettings struct {
	Unscanned bool `json:"unscanned"`
	Active    bool `json:"active"`
}

type PolicyRuleActions struct {
	Webhooks                []string              `json:"webhooks"`
	Mails                   []string              `json:"mails"`
	FailBuild               bool                  `json:"fail_build"`
	BlockDownload           BlockDownloadSettings `json:"block_download"`
	BlockReleaseBundle      bool                  `json:"block_release_bundle_distribution"`
	NotifyWatchRecipients   bool                  `json:"notify_watch_recipients"`
	NotifyDeployer          bool                  `json:"notify_deployer"`
	CreateJiraTicketEnabled bool                  `json:"create_ticket_enabled"`
	FailureGracePeriodDays  int                   `json:"build_failure_grace_period_in_days"`
	// License Actions
	CustomSeverity string `json:"custom_severity"`
}

type PolicyRule struct {
	Name     string              `json:"name"`
	Priority int                 `json:"priority"`
	Criteria *PolicyRuleCriteria `json:"criteria"`
	Actions  PolicyRuleActions   `json:"actions"`
}

type Policy struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Author      string        `json:"author,omitempty"` // Omitempty is used because the field is computed
	Description string        `json:"description"`
	Rules       *[]PolicyRule `json:"rules"`
	Created     string        `json:"created,omitempty"`  // Omitempty is used because the field is computed
	Modified    string        `json:"modified,omitempty"` // Omitempty is used because the field is computed
}

func unpackPolicy(d *schema.ResourceData) (*Policy, error) {
	policy := new(Policy)

	policy.Name = d.Get("name").(string)
	if v, ok := d.GetOk("type"); ok {
		policy.Type = v.(string)
	}
	if v, ok := d.GetOk("description"); ok {
		policy.Description = v.(string)
	}
	if v, ok := d.GetOk("author"); ok {
		policy.Author = v.(string)
	}
	policyRules, err := unpackRules(d.Get("rule").([]interface{}), policy.Type)
	policy.Rules = &policyRules

	return policy, err
}

func unpackRules(configured []interface{}, policyType string) (policyRules []PolicyRule, err error) {
	var rules []PolicyRule

	if configured != nil {
		for _, raw := range configured {
			rule := new(PolicyRule)
			data := raw.(map[string]interface{})
			rule.Name = data["name"].(string)
			rule.Priority = data["priority"].(int)

			rule.Criteria, err = unpackCriteria(data["criteria"].(*schema.Set), policyType)
			if v, ok := data["actions"]; ok {
				rule.Actions = unpackActions(v.(*schema.Set))
			}
			rules = append(rules, *rule)
		}
	}

	return rules, err
}

func unpackSecurityCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteria {
	criteria := new(PolicyRuleCriteria)

	if v, ok := tfCriteria["fix_version_dependant"]; ok {
		criteria.FixVersionDependant = v.(bool)
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

func unpackLicenseCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteria {
	criteria := new(PolicyRuleCriteria)
	if v, ok := tfCriteria["allow_unknown"]; ok {
		criteria.AllowUnknown = util.BoolPtr(v.(bool))
	}
	if v, ok := tfCriteria["banned_licenses"]; ok {
		criteria.BannedLicenses = unpackLicenses(v.(*schema.Set))
	}
	if v, ok := tfCriteria["allowed_licenses"]; ok {
		criteria.AllowedLicenses = unpackLicenses(v.(*schema.Set))
	}
	if v, ok := tfCriteria["multi_license_permissive"]; ok {
		criteria.MultiLicensePermissive = util.BoolPtr(v.(bool))
	}

	return criteria
}

func unpackOperationalRiskCustomCriteria(tfCriteria map[string]interface{}) *OperationalRiskCriteria {
	criteria := new(OperationalRiskCriteria)
	if v, ok := tfCriteria["use_and_condition"]; ok {
		criteria.UseAndCondition = v.(bool)
	}
	if v, ok := tfCriteria["is_eol"]; ok {
		criteria.IsEOL = v.(bool)
	}
	if v, ok := tfCriteria["release_date_greater_than_months"]; ok {
		criteria.ReleaseDateGreaterThanMonths = v.(int)
	}
	if v, ok := tfCriteria["newer_versions_greater_than"]; ok {
		criteria.NewerVersionsGreaterThan = v.(int)
	}
	if v, ok := tfCriteria["release_cadence_per_year_less_than"]; ok {
		criteria.ReleaseCadencePerYearLessThan = v.(int)
	}
	if v, ok := tfCriteria["commits_less_than"]; ok {
		criteria.CommitsLessThan = v.(int)
	}
	if v, ok := tfCriteria["committers_less_than"]; ok {
		criteria.CommittersLessThan = v.(int)
	}
	if v, ok := tfCriteria["risk"]; ok {
		criteria.Risk = v.(string)
	}

	return criteria
}

func unpackOperationalRiskCriteria(tfCriteria map[string]interface{}) *PolicyRuleCriteria {
	criteria := new(PolicyRuleCriteria)
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

func unpackCriteria(d *schema.Set, policyType string) (*PolicyRuleCriteria, error) {
	tfCriteria := d.List()
	if len(tfCriteria) == 0 {
		return nil, nil
	}

	m := tfCriteria[0].(map[string]interface{}) // We made this a list of one to make schema validation easier
	var criteria *PolicyRuleCriteria
	// criteria := new(PolicyRuleCriteria)
	// The API doesn't allow both severity and license criteria to be _set_, even if they have empty values
	// So we have to figure out which group is actually empty and not even set it
	if policyType == "license" {
		criteria = unpackLicenseCriteria(m)
		// if v, ok := m["allow_unknown"]; ok {
		// 	criteria.AllowUnknown = utils.BoolPtr(v.(bool))
		// }
		// if v, ok := m["banned_licenses"]; ok {
		// 	criteria.BannedLicenses = unpackLicenses(v.(*schema.Set))
		// }
		// if v, ok := m["allowed_licenses"]; ok {
		// 	criteria.AllowedLicenses = unpackLicenses(v.(*schema.Set))
		// }
		// if v, ok := m["multi_license_permissive"]; ok {
		// 	criteria.MultiLicensePermissive = util.BoolPtr(v.(bool))
		// }
	} else if policyType == "security" {
		criteria = unpackSecurityCriteria(m)
		// minSev := m["min_severity"].(string)
		// cvss := unpackCVSSRange(m["cvss_range"].([]interface{}))
		// if v, ok := m["fix_version_dependant"]; ok {
		// 	criteria.FixVersionDependant = v.(bool)
		// }
		//
		// // This is also picky about not allowing empty values to be set
		// if cvss == nil {
		// 	criteria.MinimumSeverity = minSev
		// } else {
		// 	criteria.CVSSRange = cvss
		// }
	} else if policyType == "operational_risk" {
		criteria = unpackOperationalRiskCriteria(m)
	}

	return criteria, nil
}

func Float64Ptr(v float64) *float64 { return &v }

func unpackCVSSRange(l []interface{}) *PolicyCVSSRange {
	if len(l) == 0 {
		return nil
	}

	m := l[0].(map[string]interface{})
	cvssrange := &PolicyCVSSRange{
		From: Float64Ptr(m["from"].(float64)),
		To:   Float64Ptr(m["to"].(float64)),
	}
	return cvssrange
}

func unpackLicenses(d *schema.Set) []string {
	var licenses []string
	for _, license := range d.List() {
		licenses = append(licenses, license.(string))
	}
	return licenses
}

func unpackActions(l *schema.Set) PolicyRuleActions {
	actions := PolicyRuleActions{}
	policyActions := l.List()
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

			actions.BlockDownload = BlockDownloadSettings{
				Unscanned: vMap["unscanned"].(bool),
				Active:    vMap["active"].(bool),
			}
		} else {
			actions.BlockDownload = BlockDownloadSettings{
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
		actions.BlockReleaseBundle = v.(bool)
	}

	if v, ok := m["notify_watch_recipients"]; ok {
		actions.NotifyWatchRecipients = v.(bool)
	}
	if v, ok := m["block_release_bundle_distribution"]; ok {
		actions.BlockReleaseBundle = v.(bool)
	}
	if v, ok := m["notify_deployer"]; ok {
		actions.NotifyDeployer = v.(bool)
	}
	if v, ok := m["create_ticket_enabled"]; ok {
		actions.CreateJiraTicketEnabled = v.(bool)
	}
	if v, ok := m["build_failure_grace_period_in_days"]; ok {
		actions.FailureGracePeriodDays = v.(int)
	}
	if v, ok := m["custom_severity"]; ok {
		actions.CustomSeverity = v.(string)
	}

	return actions
}

func packRules(rules []PolicyRule, policyType string) []interface{} {
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

func packOperationalRiskCriteria(criteria *PolicyRuleCriteria) []interface{} {
	m := map[string]interface{}{}

	if len(criteria.OperationalRiskMinRisk) > 0 {
		m["op_risk_min_risk"] = criteria.OperationalRiskMinRisk
	}
	if criteria.OperationalRiskCustom != nil {
		m["op_risk_custom"] = packOperationalRiskCustom(criteria.OperationalRiskCustom)
	}

	return []interface{}{m}
}

func packOperationalRiskCustom(custom *OperationalRiskCriteria) []interface{} {
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

func packLicenseCriteria(criteria *PolicyRuleCriteria) []interface{} {

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

func packSecurityCriteria(criteria *PolicyRuleCriteria) []interface{} {
	m := map[string]interface{}{}
	// cvss_range and min_severity are conflicting, only one can be present in the JSON
	m["cvss_range"] = packCVSSRange(criteria.CVSSRange)
	m["min_severity"] = criteria.MinimumSeverity
	m["fix_version_dependant"] = criteria.FixVersionDependant

	return []interface{}{m}
}

func packCVSSRange(cvss *PolicyCVSSRange) []interface{} {
	if cvss == nil {
		return []interface{}{}
	}
	m := map[string]interface{}{
		"from": *cvss.From,
		"to":   *cvss.To,
	}
	return []interface{}{m}
}

func packActions(actions PolicyRuleActions, license bool) []interface{} {

	m := map[string]interface{}{
		"block_download":                     packBlockDownload(actions.BlockDownload),
		"webhooks":                           actions.Webhooks,
		"mails":                              actions.Mails,
		"fail_build":                         actions.FailBuild,
		"block_release_bundle_distribution":  actions.BlockReleaseBundle,
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

func packBlockDownload(bd BlockDownloadSettings) []interface{} {

	m := map[string]interface{}{}
	m["unscanned"] = bd.Unscanned
	m["active"] = bd.Active
	return []interface{}{m}
}

func packPolicy(policy Policy, d *schema.ResourceData) diag.Diagnostics {
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
	if err := d.Set("rule", packRules(*policy.Rules, policy.Type)); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceXrayPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy, err := unpackPolicy(d)
	// Warning or errors can be collected in a slice type
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = m.(*resty.Client).R().SetBody(policy).Post("xray/api/v2/policies")
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(policy.Name)
	return resourceXrayPolicyRead(ctx, d, m)
}

func resourceXrayPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy := Policy{}

	resp, err := m.(*resty.Client).R().SetResult(&policy).Get("xray/api/v2/policies/" + d.Id())
	if err != nil {
		if resp != nil && resp.StatusCode() == http.StatusNotFound {
			log.Printf("[WARN] Xray policy (%s) not found, removing from state", d.Id())
			d.SetId("")
		}
		return diag.FromErr(err)
	}
	packPolicy(policy, d)
	return nil
}

func resourceXrayPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	policy, err := unpackPolicy(d)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = m.(*resty.Client).R().SetBody(policy).Put("xray/api/v2/policies/" + d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(policy.Name)
	return resourceXrayPolicyRead(ctx, d, m)
}

func resourceXrayPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	resp, err := m.(*resty.Client).R().Delete("xray/api/v2/policies/" + d.Id())
	if err != nil && resp.StatusCode() == http.StatusInternalServerError {
		d.SetId("")
		return diag.FromErr(err)
	}
	return nil
}
