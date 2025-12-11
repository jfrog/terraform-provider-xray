package xray

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"

	//"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/samber/lo"
)

var _ resource.Resource = &SecurityPolicyResource{}

func NewSecurityPolicyResource() resource.Resource {
	return &SecurityPolicyResource{
		PolicyResource: PolicyResource{
			TypeName: "xray_security_policy",
		},
	}
}

type SecurityPolicyResource struct {
	PolicyResource
}

func (r *SecurityPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *SecurityPolicyResource) toCriteriaAPIModel(ctx context.Context, criteriaElems []attr.Value) (*PolicyRuleCriteriaAPIModel, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	var criteria *PolicyRuleCriteriaAPIModel
	if len(criteriaElems) > 0 {
		attrs := criteriaElems[0].(types.Object).Attributes()

		var vulnerabilityIds []string
		d := attrs["vulnerability_ids"].(types.List).ElementsAs(ctx, &vulnerabilityIds, false)
		if d.HasError() {
			diags.Append(d...)
		}

		var cvssRange *PolicyCVSSRangeAPIModel
		cvssRangeElems := attrs["cvss_range"].(types.List).Elements()
		if len(cvssRangeElems) > 0 {
			attrs := cvssRangeElems[0].(types.Object).Attributes()

			cvssRange = &PolicyCVSSRangeAPIModel{
				From: attrs["from"].(types.Float64).ValueFloat64Pointer(),
				To:   attrs["to"].(types.Float64).ValueFloat64Pointer(),
			}
		}

		var exposures *PolicyExposuresAPIModel
		exposuresElem := attrs["exposures"].(types.List).Elements()
		if len(exposuresElem) > 0 {
			attrs := exposuresElem[0].(types.Object).Attributes()

			exposures = &PolicyExposuresAPIModel{
				MinSeverity:  attrs["min_severity"].(types.String).ValueStringPointer(),
				Secrets:      attrs["secrets"].(types.Bool).ValueBoolPointer(),
				Applications: attrs["applications"].(types.Bool).ValueBoolPointer(),
				Services:     attrs["services"].(types.Bool).ValueBoolPointer(),
				Iac:          attrs["iac"].(types.Bool).ValueBoolPointer(),
			}
		}

		var packageVersions []string
		d = attrs["package_versions"].(types.List).ElementsAs(ctx, &packageVersions, false)
		if d.HasError() {
			diags.Append(d...)
		}

		criteria = &PolicyRuleCriteriaAPIModel{
			MinimumSeverity:     attrs["min_severity"].(types.String).ValueString(),
			CVSSRange:           cvssRange,
			FixVersionDependant: attrs["fix_version_dependant"].(types.Bool).ValueBoolPointer(),
			ApplicableCVEsOnly:  attrs["applicable_cves_only"].(types.Bool).ValueBoolPointer(),
			MaliciousPackage:    attrs["malicious_package"].(types.Bool).ValueBoolPointer(),
			VulnerabilityIds:    vulnerabilityIds,
			Exposures:           exposures,
			PackageName:         attrs["package_name"].(types.String).ValueString(),
			PackageType:         attrs["package_type"].(types.String).ValueString(),
			PackageVersions:     packageVersions,
		}
	}

	return criteria, diags
}

func (r SecurityPolicyResource) toAPIModel(ctx context.Context, plan PolicyResourceModel, policy *PolicyAPIModel) diag.Diagnostics {
	return plan.toAPIModel(ctx, policy, r.toCriteriaAPIModel, toActionsAPIModel)
}

func (r *SecurityPolicyResource) fromCriteriaAPIModel(ctx context.Context, criteriaAPIModel *PolicyRuleCriteriaAPIModel) (types.List, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	criteriaSet := types.ListNull(securityCriteriaSetElementType)
	if criteriaAPIModel != nil {
		minimumSeverity := types.StringNull()
		if criteriaAPIModel.MinimumSeverity != "" {
			minimumSeverity = types.StringValue(criteriaAPIModel.MinimumSeverity)
		}

		cvssRangeList := types.ListNull(cvssRangeElementType)
		if criteriaAPIModel.CVSSRange != nil {
			cvssRange, d := types.ObjectValue(
				cvssRangeAttrType,
				map[string]attr.Value{
					"from": types.Float64PointerValue(criteriaAPIModel.CVSSRange.From),
					"to":   types.Float64PointerValue(criteriaAPIModel.CVSSRange.To),
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			cr, d := types.ListValue(
				cvssRangeElementType,
				[]attr.Value{cvssRange},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			cvssRangeList = cr
		}

		vulnerabilityIDs, d := types.ListValueFrom(ctx, types.StringType, criteriaAPIModel.VulnerabilityIds)
		if d.HasError() {
			diags.Append(d...)
		}

		exposuresList := types.ListNull(exposuresElementType)
		if criteriaAPIModel.Exposures != nil {
			var minSeverity *string
			if criteriaAPIModel.Exposures.MinSeverity != nil {
				s := lo.Capitalize(*criteriaAPIModel.Exposures.MinSeverity)
				minSeverity = &s
			}

			exposures, d := types.ObjectValue(
				exposuresAttrType,
				map[string]attr.Value{
					"min_severity": types.StringPointerValue(minSeverity),
					"secrets":      types.BoolPointerValue(criteriaAPIModel.Exposures.Secrets),
					"applications": types.BoolPointerValue(criteriaAPIModel.Exposures.Applications),
					"services":     types.BoolPointerValue(criteriaAPIModel.Exposures.Services),
					"iac":          types.BoolPointerValue(criteriaAPIModel.Exposures.Iac),
				},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			es, d := types.ListValue(
				exposuresElementType,
				[]attr.Value{exposures},
			)
			if d.HasError() {
				diags.Append(d...)
			}

			exposuresList = es
		}

		packageName := types.StringNull()
		if criteriaAPIModel.PackageName != "" {
			packageName = types.StringValue(criteriaAPIModel.PackageName)
		}

		packageType := types.StringNull()
		if criteriaAPIModel.PackageType != "" {
			packageType = types.StringValue(criteriaAPIModel.PackageType)
		}

		packageVersions, d := types.ListValueFrom(ctx, types.StringType, criteriaAPIModel.PackageVersions)
		if d.HasError() {
			diags.Append(d...)
		}

		criteria, d := types.ObjectValue(
			securityCriteriaAttrTypes,
			map[string]attr.Value{
				"min_severity":          minimumSeverity,
				"fix_version_dependant": types.BoolPointerValue(criteriaAPIModel.FixVersionDependant),
				"applicable_cves_only":  types.BoolPointerValue(criteriaAPIModel.ApplicableCVEsOnly),
				"malicious_package":     types.BoolPointerValue(criteriaAPIModel.MaliciousPackage),
				"cvss_range":            cvssRangeList,
				"vulnerability_ids":     vulnerabilityIDs,
				"exposures":             exposuresList,
				"package_name":          packageName,
				"package_type":          packageType,
				"package_versions":      packageVersions,
			},
		)
		if d.HasError() {
			diags.Append(d...)
		}
		cs, d := types.ListValueFrom(
			ctx,
			securityCriteriaSetElementType,
			[]attr.Value{criteria},
		)
		if d.HasError() {
			diags.Append(d...)
		}

		criteriaSet = cs
	}

	return criteriaSet, diags
}

func (r SecurityPolicyResource) fromAPIModel(ctx context.Context, policy PolicyAPIModel, plan *PolicyResourceModel) diag.Diagnostics {
	return plan.fromAPIModel(ctx, policy, r.fromCriteriaAPIModel, fromActionsAPIModel)
}

var cvssRangeAttrType = map[string]attr.Type{
	"from": types.Float64Type,
	"to":   types.Float64Type,
}

var cvssRangeElementType = types.ObjectType{
	AttrTypes: cvssRangeAttrType,
}

var exposuresAttrType = map[string]attr.Type{
	"min_severity": types.StringType,
	"secrets":      types.BoolType,
	"applications": types.BoolType,
	"services":     types.BoolType,
	"iac":          types.BoolType,
}

var exposuresElementType = types.ObjectType{
	AttrTypes: exposuresAttrType,
}

var securityCriteriaAttrTypes = map[string]attr.Type{
	"min_severity":          types.StringType,
	"fix_version_dependant": types.BoolType,
	"applicable_cves_only":  types.BoolType,
	"malicious_package":     types.BoolType,
	"cvss_range":            types.ListType{ElemType: cvssRangeElementType},
	"vulnerability_ids":     types.ListType{ElemType: types.StringType},
	"exposures":             types.ListType{ElemType: exposuresElementType},
	"package_name":          types.StringType,
	"package_type":          types.StringType,
	"package_versions":      types.ListType{ElemType: types.StringType},
}

var securityCriteriaSetElementType = types.ObjectType{
	AttrTypes: securityCriteriaAttrTypes,
}

var blockDownloadAttrTypes = map[string]attr.Type{
	"unscanned": types.BoolType,
	"active":    types.BoolType,
}

var blockDownloadElementType = types.ObjectType{
	AttrTypes: blockDownloadAttrTypes,
}

var securityRuleAttrTypes = map[string]attr.Type{
	"name":     types.StringType,
	"priority": types.Int64Type,
	"criteria": types.ListType{ElemType: securityCriteriaSetElementType},
	"actions":  types.ListType{ElemType: actionsListElementType},
}

var securityRuleSetElementType = types.ObjectType{
	AttrTypes: securityRuleAttrTypes,
}

var securityPolicyCriteriaBlocks = map[string]schema.Block{
	"cvss_range": schema.ListNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"from": schema.Float64Attribute{
					Required: true,
					Validators: []validator.Float64{
						float64validator.Between(0, 10),
					},
					Description: "The beginning of the range of CVS scores (from 1-10, float) to flag.",
				},
				"to": schema.Float64Attribute{
					Required: true,
					Validators: []validator.Float64{
						float64validator.Between(0, 10),
					},
					Description: "The end of the range of CVS scores (from 1-10, float) to flag. ",
				},
			},
		},
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
		},
		Description: "The CVSS score range to apply to the rule. This is used for a fine-grained control, rather than using the predefined severities. The score range is based on CVSS v3 scoring, and CVSS v2 score is CVSS v3 score is not available.",
	},
	"exposures": schema.ListNestedBlock{
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"min_severity": schema.StringAttribute{
					Optional: true,
					Computed: true,
					Default:  stringdefault.StaticString("All severities"),
					Validators: []validator.String{
						stringvalidator.OneOf("All severities", "Critical", "High", "Medium", "Low"),
					},
					MarkdownDescription: "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
				},
				"secrets": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Secrets exposures.",
				},
				"applications": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Applications exposures.",
				},
				"services": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Services exposures.",
				},
				"iac": schema.BoolAttribute{
					Optional:    true,
					Computed:    true,
					Default:     booldefault.StaticBool(true),
					Description: "Iac exposures.",
				},
			},
		},
		Validators: []validator.List{
			listvalidator.SizeAtMost(1),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("min_severity"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("malicious_package"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("vulnerability_ids"),
			),
		},
		Description: "Creates policy rules for specific exposures.\n\n~>Only supported by JFrog Advanced Security",
	},
}

var securityPolicyCriteriaAttrs = map[string]schema.Attribute{
	"min_severity": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.OneOf("All severities", "Critical", "High", "Medium", "Low"),
			stringvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
		},
		Description: "The minimum security vulnerability severity that will be impacted by the policy. Valid values: `All Severities`, `Critical`, `High`, `Medium`, `Low`",
	},
	"fix_version_dependant": schema.BoolAttribute{
		Optional:    true,
		Description: "Issues that do not have a fixed version are not generated until a fixed version is available. Must be `false` with `malicious_package` enabled.",
	},
	"applicable_cves_only": schema.BoolAttribute{
		Optional:    true,
		Description: "Mark to skip CVEs that are not applicable in the context of the artifact. The contextual analysis operation might be long and affect build time if the `fail_build` action is set.\n\n~>Only supported by JFrog Advanced Security",
	},
	"malicious_package": schema.BoolAttribute{
		Optional:    true,
		Description: "Generating a violation on a malicious package.",
	},
	"vulnerability_ids": schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.List{
			listvalidator.SizeAtLeast(1),
			listvalidator.UniqueValues(),
			listvalidator.ValueStringsAre(
				stringvalidator.RegexMatches(regexp.MustCompile(`(CVE\W*\d{4}\W+\d{4,}|XRAY-\d{4,})`), "invalid Vulnerability, must be a valid CVE or Xray ID, example CVE-2021-12345, XRAY-1234"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("malicious_package"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("min_severity"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("cvss_range"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("exposures"),
			),
			listvalidator.ConflictsWith(
				path.MatchRelative().AtParent().AtName("package_name"),
				path.MatchRelative().AtParent().AtName("package_type"),
				path.MatchRelative().AtParent().AtName("package_versions"),
			),
		},
		Description: "Creates policy rules for specific vulnerability IDs that you input. You can add multiple vulnerabilities IDs. CVEs and Xray IDs are supported. Example - CVE-2015-20107, XRAY-2344",
	},
	"package_name": schema.StringAttribute{
		Optional:    true,
		Description: "The package name to create a rule for",
		Validators: []validator.String{
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("package_type"),
			),
		},
	},
	"package_type": schema.StringAttribute{
		Optional: true,
		Validators: []validator.String{
			stringvalidator.OneOf(validPackageTypesSupportedXraySecPolicies...),
			stringvalidator.AlsoRequires(
				path.MatchRelative().AtParent().AtName("package_name"),
			),
		},
		Description: "The package type to create a rule for",
	},
	"package_versions": schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Validators: []validator.List{
			listvalidator.ValueStringsAre(
				stringvalidator.RegexMatches(regexp.MustCompile(`((^(\(|\[)((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))\,((\d+\.)?(\d+\.)?(\*|\d+)|(\s*))(\)|\])$|^\[(\d+\.)?(\d+\.)?(\*|\d+)\]$))`), "invalid Range, must be one of the follows: Any Version: (,) or Specific Version: [1.2], [3] or Range: (1,), [,1.2.3], (4.5.0,6.5.2]"),
			),
		},
		Description: "package versions to apply the rule on can be (,) for any version or an open range (1,4) or closed [1,4] or one version [1]",
	},
}

func (r *SecurityPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:    1,
		Attributes: policySchemaAttrs,
		Blocks:     policyBlocks(securityPolicyCriteriaAttrs, securityPolicyCriteriaBlocks, commonActionsAttrs, commonActionsBlocks),
		Description: "Creates an Xray policy using V2 of the underlying APIs. Please note: " +
			"It's only compatible with Bearer token auth method (Identity and Access => Access Tokens)",
	}
}

func (r *SecurityPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r SecurityPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data PolicyResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If rule is not configured, return without warning.
	if data.Rules.IsNull() || data.Rules.IsUnknown() {
		return
	}

	// Check for duplicate rule names
	ruleNames := make(map[string]int)
	for idx, rule := range data.Rules.Elements() {
		ruleAttrs := rule.(types.Object).Attributes()
		ruleName := ruleAttrs["name"].(types.String)

		// Skip unknown values (e.g., from dynamic blocks with unknown input)
		if ruleName.IsUnknown() {
			continue
		}

		name := ruleName.ValueString()
		if firstIdx, exists := ruleNames[name]; exists {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtListIndex(idx).AtName("name"),
				"Duplicate Rule Name",
				fmt.Sprintf("Rule name %q is duplicated. First occurrence at rule index %d. Each rule must have a unique name.", name, firstIdx),
			)
		} else {
			ruleNames[name] = idx
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	for _, rule := range data.Rules.Elements() {
		ruleAttrs := rule.(types.Object).Attributes()
		criteria := ruleAttrs["criteria"].(types.List)
		attrs := criteria.Elements()[0].(types.Object).Attributes()

		fixVersionDependant := attrs["fix_version_dependant"].(types.Bool).ValueBool()
		minSeverity := attrs["min_severity"].(types.String).ValueString()
		cvssRange := attrs["cvss_range"].(types.List)
		maliciousPackage := attrs["malicious_package"].(types.Bool).ValueBool()

		if maliciousPackage && minSeverity != "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtListIndex(0).AtName("criteria").AtListIndex(0).AtName("malicious_package"),
				"Invalid Attribute Configuration",
				"malicious_package cannot be set to 'true' if min_severity is set",
			)
			return
		}

		if maliciousPackage && !cvssRange.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtListIndex(0).AtName("criteria").AtListIndex(0).AtName("malicious_package"),
				"Invalid Attribute Configuration",
				"malicious_package cannot be set to 'true' if cvss_range is set",
			)
			return
		}

		if maliciousPackage && fixVersionDependant {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtListIndex(0).AtName("criteria").AtListIndex(0).AtName("fix_version_dependant"),
				"Invalid Attribute Configuration",
				"fix_version_dependant must be set to 'false' if malicious_package is 'true'",
			)
			return
		}

		packageName := attrs["package_name"].(types.String)
		packagType := attrs["package_type"].(types.String)
		packageVersions := attrs["package_versions"].(types.List)

		if fixVersionDependant && (!packageName.IsNull() || !packagType.IsNull() || !packageVersions.IsNull()) {
			resp.Diagnostics.AddAttributeError(
				path.Root("rules").AtListIndex(0).AtName("criteria").AtListIndex(0).AtName("fix_version_dependant"),
				"Invalid Attribute Configuration",
				"fix_version_dependant must be set to 'false' if any package attribute is set",
			)
			return
		}
	}
}

func (r *SecurityPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.PolicyResource.Create(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *SecurityPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	r.PolicyResource.Read(ctx, r.fromAPIModel, req, resp)
}

func (r *SecurityPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.PolicyResource.Update(ctx, r.toAPIModel, r.fromAPIModel, req, resp)
}

func (r *SecurityPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	r.PolicyResource.Delete(ctx, req, resp)
}

// ImportState imports the resource into the Terraform state.
func (r *SecurityPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	r.PolicyResource.ImportState(ctx, req, resp)
}
