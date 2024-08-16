package xray

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

var _ resource.Resource = &RepoConfigResource{}

func NewRepositoryConfigResource() resource.Resource {
	return &RepoConfigResource{
		TypeName: "xray_repository_config",
	}
}

type RepoConfigResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type RepoConfigResourceModel struct {
	RepoName    types.String `tfsdk:"repo_name"`
	JASEnabled  types.Bool   `tfsdk:"jas_enabled"`
	Config      types.Set    `tfsdk:"config"`
	PathsConfig types.Set    `tfsdk:"paths_config"`
}

func (m RepoConfigResourceModel) toAPIModel(ctx context.Context, xrayVersion, packageType string, apiModel *RepositoryConfigurationAPIModel) (ds diag.Diagnostics) {
	var repoConfig *RepoConfigurationAPIModel
	if !m.Config.IsNull() && len(m.Config.Elements()) > 0 {
		c := m.Config.Elements()[0].(types.Object)
		configAttrs := c.Attributes()

		var vulnContextualAnalysis *bool
		var exposures *ExposuresAPIModel

		if m.JASEnabled.ValueBool() {
			if slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
				vulnContextualAnalysis = configAttrs["vuln_contextual_analysis"].(types.Bool).ValueBoolPointer()
			}

			if slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
				exps := configAttrs["exposures"].(types.Set).Elements()

				if len(exps) > 0 {
					expsAttrs := exps[0].(types.Object).Attributes()
					scannerCategory := expsAttrs["scanners_category"].(types.Set).Elements()

					if len(scannerCategory) > 0 {
						scannerCategoryAttrs := scannerCategory[0].(types.Object).Attributes()

						exp := ExposuresAPIModel{}

						switch packageType {
						case "docker":
							exp.ScannersCategory = map[string]bool{
								"services_scan":     scannerCategoryAttrs["services"].(types.Bool).ValueBool(),
								"secrets_scan":      scannerCategoryAttrs["secrets"].(types.Bool).ValueBool(),
								"applications_scan": scannerCategoryAttrs["applications"].(types.Bool).ValueBool(),
							}
						case "maven":
							exp.ScannersCategory = map[string]bool{
								"secrets_scan": scannerCategoryAttrs["secrets"].(types.Bool).ValueBool(),
							}
						case "npm", "pypi":
							exp.ScannersCategory = map[string]bool{
								"secrets_scan":      scannerCategoryAttrs["secrets"].(types.Bool).ValueBool(),
								"applications_scan": scannerCategoryAttrs["applications"].(types.Bool).ValueBool(),
							}
						case "terraformbackend":
							exp.ScannersCategory = map[string]bool{
								"iac_scan": scannerCategoryAttrs["iac"].(types.Bool).ValueBool(),
							}
						}

						exposures = &exp
					}
				}
			}
		}

		repoConfig = &RepoConfigurationAPIModel{
			RetentionInDays:        configAttrs["retention_in_days"].(types.Int64).ValueInt64(),
			Exposures:              exposures,
			VulnContextualAnalysis: vulnContextualAnalysis,
		}
	}

	var pathsConfig *PathsConfigurationAPIModel
	if !m.PathsConfig.IsNull() && len(m.PathsConfig.Elements()) > 0 {
		c := m.PathsConfig.Elements()[0].(types.Object)
		configAttrs := c.Attributes()
		patternsSet := configAttrs["pattern"].(types.Set)

		patterns := lo.Map(
			patternsSet.Elements(),
			func(elem attr.Value, _ int) PatternAPIModel {
				attrs := elem.(types.Object).Attributes()

				return PatternAPIModel{
					Include:           attrs["include"].(types.String).ValueString(),
					Exclude:           attrs["exclude"].(types.String).ValueString(),
					IndexNewArtifacts: attrs["index_new_artifacts"].(types.Bool).ValueBool(),
					RetentionInDays:   attrs["retention_in_days"].(types.Int64).ValueInt64(),
				}
			},
		)

		allOtherArtifacts := configAttrs["all_other_artifacts"].(types.Set).Elements()[0]
		allOtherArtifactsAttrs := allOtherArtifacts.(types.Object).Attributes()

		pathsConfig = &PathsConfigurationAPIModel{
			Patterns: patterns,
			OtherArtifacts: AllOtherArtifactsAPIModel{
				IndexNewArtifacts: allOtherArtifactsAttrs["index_new_artifacts"].(types.Bool).ValueBool(),
				RetentionInDays:   allOtherArtifactsAttrs["retention_in_days"].(types.Int64).ValueInt64(),
			},
		}
	}

	*apiModel = RepositoryConfigurationAPIModel{
		RepoName:        m.RepoName.ValueString(),
		RepoConfig:      repoConfig,
		RepoPathsConfig: pathsConfig,
	}

	return
}

var configExposuresScannersCategoryResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"services":     types.BoolType,
	"secrets":      types.BoolType,
	"iac":          types.BoolType,
	"applications": types.BoolType,
}

var configExposuresScannersCategorySetResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: configExposuresScannersCategoryResourceModelAttributeTypes,
}

var configExposuresResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"scanners_category": types.SetType{
		ElemType: configExposuresScannersCategorySetResourceModelElementTypes,
	},
}

var configExposuresSetResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: configExposuresResourceModelAttributeTypes,
}

var configResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"vuln_contextual_analysis": types.BoolType,
	"retention_in_days":        types.Int64Type,
	"exposures": types.SetType{
		ElemType: configExposuresSetResourceModelElementTypes,
	},
}

var configSetResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: configResourceModelAttributeTypes,
}

var pathsConfigPatternResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"include":             types.StringType,
	"exclude":             types.StringType,
	"index_new_artifacts": types.BoolType,
	"retention_in_days":   types.Int64Type,
}

var pathsConfigPatternResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: pathsConfigPatternResourceModelAttributeTypes,
}

var pathsConfigAllOtherArtifactsResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"index_new_artifacts": types.BoolType,
	"retention_in_days":   types.Int64Type,
}

var pathsConfigAllOtherArtifactsResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: pathsConfigAllOtherArtifactsResourceModelAttributeTypes,
}

var pathsConfigResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"pattern": types.SetType{
		ElemType: pathsConfigPatternResourceModelElementTypes,
	},
	"all_other_artifacts": types.SetType{
		ElemType: pathsConfigAllOtherArtifactsResourceModelElementTypes,
	},
}

var pathsConfigSetResourceModelElementTypes types.ObjectType = types.ObjectType{
	AttrTypes: pathsConfigResourceModelAttributeTypes,
}

func (m *RepoConfigResourceModel) fromAPIModel(_ context.Context, xrayVersion, packageType string, apiModel RepositoryConfigurationAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	m.RepoName = types.StringValue(apiModel.RepoName)
	m.Config = types.SetNull(configSetResourceModelElementTypes)

	if apiModel.RepoConfig != nil {
		vulnContextualAnalysis := types.BoolNull()
		exposures := types.SetNull(configExposuresSetResourceModelElementTypes)

		if m.JASEnabled.ValueBool() {
			if apiModel.RepoConfig.VulnContextualAnalysis != nil && slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
				vulnContextualAnalysis = types.BoolPointerValue(apiModel.RepoConfig.VulnContextualAnalysis)
			}

			if apiModel.RepoConfig.Exposures != nil && slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
				scannersCategoryAttrValues := map[string]attr.Value{
					"services":     types.BoolNull(),
					"secrets":      types.BoolNull(),
					"iac":          types.BoolNull(),
					"applications": types.BoolNull(),
				}

				switch packageType {
				case "docker":
					scannersCategoryAttrValues["services"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["services_scan"])
					scannersCategoryAttrValues["secrets"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["secrets_scan"])
					scannersCategoryAttrValues["applications"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["applications_scan"])
				case "maven":
					scannersCategoryAttrValues["secrets"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["secrets_scan"])
				case "npm", "pypi":
					scannersCategoryAttrValues["secrets"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["secrets_scan"])
					scannersCategoryAttrValues["applications"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["applications_scan"])
				case "terraformbackend":
					scannersCategoryAttrValues["iac"] = types.BoolValue(apiModel.RepoConfig.Exposures.ScannersCategory["iac_scan"])
				}

				scannersCategory, d := types.ObjectValue(
					configExposuresScannersCategoryResourceModelAttributeTypes,
					scannersCategoryAttrValues,
				)
				if d != nil {
					diags.Append(d...)
				}

				scannersCategorySet, d := types.SetValue(
					configExposuresScannersCategorySetResourceModelElementTypes,
					[]attr.Value{scannersCategory},
				)
				if d != nil {
					diags.Append(d...)
				}

				exposure, d := types.ObjectValue(
					configExposuresResourceModelAttributeTypes,
					map[string]attr.Value{
						"scanners_category": scannersCategorySet,
					},
				)
				if d != nil {
					diags.Append(d...)
				}

				exposuresSet, d := types.SetValue(
					configExposuresSetResourceModelElementTypes,
					[]attr.Value{exposure},
				)
				if d != nil {
					diags.Append(d...)
				}

				exposures = exposuresSet
			}
		}

		config, d := types.ObjectValue(
			configResourceModelAttributeTypes,
			map[string]attr.Value{
				"retention_in_days":        types.Int64Value(apiModel.RepoConfig.RetentionInDays),
				"vuln_contextual_analysis": vulnContextualAnalysis,
				"exposures":                exposures,
			},
		)
		if d != nil {
			diags.Append(d...)
		}

		configSet, d := types.SetValue(
			configSetResourceModelElementTypes,
			[]attr.Value{config},
		)
		if d != nil {
			diags.Append(d...)
		}
		m.Config = configSet
	}

	m.PathsConfig = types.SetNull(pathsConfigSetResourceModelElementTypes)

	if apiModel.RepoPathsConfig != nil {
		patterns := lo.Map(
			apiModel.RepoPathsConfig.Patterns,
			func(pattern PatternAPIModel, _ int) attr.Value {
				p, d := types.ObjectValue(
					pathsConfigPatternResourceModelAttributeTypes,
					map[string]attr.Value{
						"include":             types.StringValue(pattern.Include),
						"exclude":             types.StringValue(pattern.Exclude),
						"index_new_artifacts": types.BoolValue(pattern.IndexNewArtifacts),
						"retention_in_days":   types.Int64Value(pattern.RetentionInDays),
					},
				)
				if d != nil {
					diags.Append(d...)
				}

				return p
			},
		)

		patternSet, d := types.SetValue(
			pathsConfigPatternResourceModelElementTypes,
			patterns,
		)
		if d != nil {
			diags.Append(d...)
		}

		allOtherArtifacts, d := types.ObjectValue(
			pathsConfigAllOtherArtifactsResourceModelAttributeTypes,
			map[string]attr.Value{
				"index_new_artifacts": types.BoolValue(apiModel.RepoPathsConfig.OtherArtifacts.IndexNewArtifacts),
				"retention_in_days":   types.Int64Value(apiModel.RepoPathsConfig.OtherArtifacts.RetentionInDays),
			},
		)
		if d != nil {
			diags.Append(d...)
		}

		allOtherArtifactsSet, d := types.SetValue(
			pathsConfigAllOtherArtifactsResourceModelElementTypes,
			[]attr.Value{allOtherArtifacts},
		)
		if d != nil {
			diags.Append(d...)
		}

		pathsConfig, d := types.ObjectValue(
			pathsConfigResourceModelAttributeTypes,
			map[string]attr.Value{
				"pattern":             patternSet,
				"all_other_artifacts": allOtherArtifactsSet,
			},
		)
		if d != nil {
			diags.Append(d...)
		}

		pathsConfigSet, d := types.SetValue(
			pathsConfigSetResourceModelElementTypes,
			[]attr.Value{pathsConfig},
		)
		if d != nil {
			diags.Append(d...)
		}
		m.PathsConfig = pathsConfigSet
	}

	return diags
}

type RepositoryConfigurationAPIModel struct {
	RepoName string `json:"repo_name"`
	// Pointer is used to be able to verify if the RepoConfig or PathsConfiguration struct is nil
	RepoConfig      *RepoConfigurationAPIModel  `json:"repo_config,omitempty"`
	RepoPathsConfig *PathsConfigurationAPIModel `json:"repo_paths_config,omitempty"`
}

type RepoConfigurationAPIModel struct {
	// Omitempty is used because 'vuln_contextual_analysis' is not supported by self-hosted Xray installation.
	VulnContextualAnalysis *bool              `json:"vuln_contextual_analysis,omitempty"`
	RetentionInDays        int64              `json:"retention_in_days,omitempty"`
	Exposures              *ExposuresAPIModel `json:"exposures,omitempty"`
}

type ExposuresAPIModel struct {
	ScannersCategory map[string]bool `json:"scanners_category"`
}

type PathsConfigurationAPIModel struct {
	Patterns       []PatternAPIModel         `json:"patterns,omitempty"`
	OtherArtifacts AllOtherArtifactsAPIModel `json:"all_other_artifacts,omitempty"`
}

type PatternAPIModel struct {
	Include           string `json:"include"`
	Exclude           string `json:"exclude"`
	IndexNewArtifacts bool   `json:"index_new_artifacts"`
	RetentionInDays   int64  `json:"retention_in_days"`
}

type AllOtherArtifactsAPIModel struct {
	IndexNewArtifacts bool  `json:"index_new_artifacts"`
	RetentionInDays   int64 `json:"retention_in_days"`
}

func (r *RepoConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"repo_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Repository name.",
			},
			"jas_enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Specified if JFrog Advanced Security is enabled or not. Default to 'false'",
			},
		},
		Blocks: map[string]schema.Block{
			"config": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"vuln_contextual_analysis": schema.BoolAttribute{
							Optional:    true,
							Description: "Only for SaaS instances, will be available after Xray 3.59. Enables vulnerability contextual analysis. Must be set together with `exposures`. Supported for Docker, OCI, and Maven package types.",
						},
						"retention_in_days": schema.Int64Attribute{
							Optional: true,
							Computed: true,
							Default:  int64default.StaticInt64(90),
							Validators: []validator.Int64{
								int64validator.AtLeast(0),
							},
							Description: "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
						},
					},
					Blocks: map[string]schema.Block{
						"exposures": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Blocks: map[string]schema.Block{
									"scanners_category": schema.SetNestedBlock{
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"services": schema.BoolAttribute{
													Optional:    true,
													Description: "Detect whether common OSS libraries and services are configured securely, so application can be easily hardened by default.",
												},
												"secrets": schema.BoolAttribute{
													Optional:    true,
													Description: "Detect any secret left exposed in any containers stored in Artifactory to stop any accidental leak of internal tokens or credentials.",
												},
												"iac": schema.BoolAttribute{
													Optional:    true,
													Description: "Scans IaC files stored in Artifactory for early detection of cloud and infrastructure misconfigurations to prevent attacks and data leak. Only supported by Terraform Backend package type.",
												},
												"applications": schema.BoolAttribute{
													Optional:    true,
													Description: "Detect whether common OSS libraries and services are used securely by the application.",
												},
											},
										},
										Validators: []validator.Set{
											setvalidator.SizeAtMost(1),
										},
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtMost(1),
							},
							Description: "Enables Xray to perform scans for multiple categories that cover security issues in your configurations and the usage of open source libraries in your code. Available only to CLOUD (SaaS)/SELF HOSTED for ENTERPRISE X and ENTERPRISE+ with Advanced DevSecOps. Must be set together with `vuln_contextual_analysis`. Supported for Docker, Maven, NPM, PyPi, and Terraform Backend package type.",
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeAtMost(1),
					setvalidator.AtLeastOneOf(path.MatchRoot("paths_config")),
				},
				Description: "Single repository configuration. Only one of 'config' or 'paths_config' can be set.",
			},
			"paths_config": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"pattern": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"include": schema.StringAttribute{
										Required: true,
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
										Description: "Include pattern.",
									},
									"exclude": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.LengthAtLeast(1),
										},
										Description: "Exclude pattern.",
									},
									"index_new_artifacts": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Default:     booldefault.StaticBool(true),
										Description: "If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.",
									},
									"retention_in_days": schema.Int64Attribute{
										Optional: true,
										Computed: true,
										Default:  int64default.StaticInt64(90),
										Validators: []validator.Int64{
											int64validator.AtLeast(0),
										},
										Description: "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Description: "Pattern, applied to the repositories.",
						},
						"all_other_artifacts": schema.SetNestedBlock{
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"index_new_artifacts": schema.BoolAttribute{
										Optional:    true,
										Computed:    true,
										Default:     booldefault.StaticBool(true),
										Description: "If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.",
									},
									"retention_in_days": schema.Int64Attribute{
										Optional: true,
										Computed: true,
										Default:  int64default.StaticInt64(90),
										Validators: []validator.Int64{
											int64validator.AtLeast(0),
										},
										Description: "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeBetween(1, 1),
							},
							Description: "If you select by pattern, you must define a retention period for all other artifacts in the repository in the All Other Artifacts setting.",
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeAtMost(1),
					setvalidator.AtLeastOneOf(path.MatchRoot("config")),
				},
				Description: "Enables you to set a more granular retention period. It enables you to scan future artifacts within the specific path, and set a retention period for the historical data of artifacts after they are scanned",
			},
		},
		Description: "Provides an Xray repository config resource. See [Xray Indexing Resources](https://www.jfrog.com/confluence/display/JFROG/Indexing+Xray+Resources#IndexingXrayResources-SetaRetentionPeriod) and [REST API](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-UpdateRepositoriesConfigurations) for more details.",
	}
}

func (r *RepoConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *RepoConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r RepoConfigResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data RepoConfigResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If jas_enabled is not configured, return without warning.
	if data.JASEnabled.IsNull() || data.JASEnabled.IsUnknown() {
		return
	}

	// If config is not configured, return without warning.
	if data.Config.IsNull() {
		return
	}

	if !data.JASEnabled.ValueBool() {
		configs := data.Config.Elements()
		if len(configs) == 0 {
			return
		}

		config := configs[0].(types.Object)
		attrs := config.Attributes()

		if v, ok := attrs["vuln_contextual_analysis"]; ok && !v.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("config").AtListIndex(0).AtName("vuln_contextual_analysis"),
				"Invalid Attribute Configuration",
				"config.vuln_contextual_analysis can not be set when jas_enabled is set to 'true'",
			)
			return
		}

		if v, ok := attrs["exposures"]; ok && !v.IsNull() && len(v.(types.Set).Elements()) > 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("config").AtListIndex(0).AtName("exposures"),
				"Invalid Attribute Configuration",
				"config.exposures can not be set when jas_enabled is set to 'true'",
			)
			return
		}
	}
}

func (r *RepoConfigResource) getPackageType(repoName string) (string, error) {

	type Repository struct {
		PackageType string `json:"packageType"`
	}

	var repo Repository

	resp, err := r.ProviderData.Client.R().
		SetResult(&repo).
		SetPathParam("repoKey", repoName).
		Get("artifactory/api/repositories/{repoKey}")

	if err != nil {
		return "", err
	}

	if resp.IsError() {
		return "", fmt.Errorf(resp.String())
	}

	return repo.PackageType, nil
}

func (r *RepoConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan RepoConfigResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	packageType, err := r.getPackageType(plan.RepoName.ValueString())
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
	}

	var repoConfig RepositoryConfigurationAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, r.ProviderData.XrayVersion, packageType, &repoConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.ProviderData.Client.R().
		SetBody(repoConfig).
		Put("xray/api/v1/repos_config")
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RepoConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state RepoConfigResourceModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var repoConfig RepositoryConfigurationAPIModel

	repoName := state.RepoName.ValueString()

	response, err := r.ProviderData.Client.R().
		SetPathParam("repo_name", repoName).
		SetResult(&repoConfig).
		Get("xray/api/v1/repos_config/{repo_name}")

	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	packageType, err := r.getPackageType(repoName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to get repository data",
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, r.ProviderData.XrayVersion, packageType, repoConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *RepoConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	go util.SendUsageResourceUpdate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan RepoConfigResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	packageType, err := r.getPackageType(plan.RepoName.ValueString())
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
	}

	var repoConfig RepositoryConfigurationAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, r.ProviderData.XrayVersion, packageType, &repoConfig)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.ProviderData.Client.R().
		SetBody(repoConfig).
		Put("xray/api/v1/repos_config")
	if err != nil {
		utilfw.UnableToUpdateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToUpdateResourceError(resp, response.String())
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *RepoConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	resp.Diagnostics.AddWarning(
		"No delete functionality provided by API",
		"Delete function will return a warning and remove the Id from the Terraform state. The actual repository configuration will remain unchanged.",
	)

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *RepoConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)

	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("repo_name"), parts[0])...)

		jasEnabled, err := strconv.ParseBool(parts[1])
		if err != nil {
			resp.Diagnostics.AddError(
				"failed to parse import field 'jas_enabled'",
				err.Error(),
			)
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("jas_enabled"), jasEnabled)...)
	}
}

var exposuresPackageTypes = func(xrayVersion string) []string {
	packageTypes := []string{"docker", "terraformbackend"}

	if ok, err := util.CheckVersion(xrayVersion, "3.78.9"); err == nil && ok {
		packageTypes = append(packageTypes, "maven", "npm", "pypi")
	}

	return packageTypes
}

var vulnContextualAnalysisPackageTypes = func(xrayVersion string) []string {
	packageTypes := []string{"docker"}

	if ok, err := util.CheckVersion(xrayVersion, "3.77.4"); err == nil && ok {
		packageTypes = append(packageTypes, "maven")
	}

	return packageTypes
}

//
// func ResourceXrayRepositoryConfig() *schema.Resource {
// 	var repositoryConfigSchema = map[string]*schema.Schema{
// 		"repo_name": {
// 			Type:             schema.TypeString,
// 			Required:         true,
// 			Description:      "Repository name.",
// 			ValidateDiagFunc: validator.StringIsNotEmpty,
// 		},
// 		"jas_enabled": {
// 			Type:        schema.TypeBool,
// 			Optional:    true,
// 			Default:     false,
// 			Description: "Specified if JFrog Advanced Security is enabled or not. Default to 'false'",
// 		},
// 		"config": {
// 			Type:         schema.TypeSet,
// 			Optional:     true,
// 			MaxItems:     1,
// 			Description:  "Single repository configuration. Only one of 'config' or 'paths_config' can be set.",
// 			AtLeastOneOf: []string{"paths_config"},
// 			Elem: &schema.Resource{
// 				Schema: map[string]*schema.Schema{
// 					"vuln_contextual_analysis": {
// 						Type:        schema.TypeBool,
// 						Optional:    true,
// 						Description: "Only for SaaS instances, will be available after Xray 3.59. Enables vulnerability contextual analysis. Must be set together with `exposures`. Supported for Docker, OCI, and Maven package types.",
// 					},
// 					"retention_in_days": {
// 						Type:             schema.TypeInt,
// 						Optional:         true,
// 						Default:          90,
// 						Description:      "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
// 						ValidateDiagFunc: validator.IntAtLeast(0),
// 					},
// 					"exposures": {
// 						Type:        schema.TypeSet,
// 						Optional:    true,
// 						MaxItems:    1,
// 						Description: "Enables Xray to perform scans for multiple categories that cover security issues in your configurations and the usage of open source libraries in your code. Available only to CLOUD (SaaS)/SELF HOSTED for ENTERPRISE X and ENTERPRISE+ with Advanced DevSecOps. Must be set together with `vuln_contextual_analysis`. Supported for Docker, Maven, NPM, PyPi, and Terraform Backend package type.",
// 						Elem: &schema.Resource{
// 							Schema: map[string]*schema.Schema{
// 								"scanners_category": {
// 									Type:     schema.TypeSet,
// 									Required: true,
// 									MaxItems: 1,
// 									Elem: &schema.Resource{
// 										Schema: map[string]*schema.Schema{
// 											"services": {
// 												Type:        schema.TypeBool,
// 												Optional:    true,
// 												Description: "Detect whether common OSS libraries and services are configured securely, so application can be easily hardened by default.",
// 											},
// 											"secrets": {
// 												Type:        schema.TypeBool,
// 												Optional:    true,
// 												Description: "Detect any secret left exposed in any containers stored in Artifactory to stop any accidental leak of internal tokens or credentials.",
// 											},
// 											"iac": {
// 												Type:        schema.TypeBool,
// 												Optional:    true,
// 												Description: "Scans IaC files stored in Artifactory for early detection of cloud and infrastructure misconfigurations to prevent attacks and data leak. Only supported by Terraform Backend package type.",
// 											},
// 											"applications": {
// 												Type:        schema.TypeBool,
// 												Optional:    true,
// 												Description: "Detect whether common OSS libraries and services are used securely by the application.",
// 											},
// 										},
// 									},
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 		"paths_config": {
// 			Type:         schema.TypeSet,
// 			Optional:     true,
// 			MaxItems:     1,
// 			Description:  "Enables you to set a more granular retention period. It enables you to scan future artifacts within the specific path, and set a retention period for the historical data of artifacts after they are scanned",
// 			AtLeastOneOf: []string{"config"},
// 			Elem: &schema.Resource{
// 				Schema: map[string]*schema.Schema{
// 					"pattern": {
// 						Type:        schema.TypeList,
// 						Required:    true,
// 						MinItems:    1,
// 						Description: "Pattern, applied to the repositories.",
// 						Elem: &schema.Resource{
// 							Schema: map[string]*schema.Schema{
// 								"include": {
// 									Type:             schema.TypeString,
// 									Required:         true,
// 									Description:      "Include pattern.",
// 									ValidateDiagFunc: validator.StringIsNotEmpty,
// 								},
// 								"exclude": {
// 									Type:             schema.TypeString,
// 									Optional:         true,
// 									Description:      "Exclude pattern.",
// 									ValidateDiagFunc: validator.StringIsNotEmpty,
// 								},
// 								"index_new_artifacts": {
// 									Type:        schema.TypeBool,
// 									Optional:    true,
// 									Default:     true,
// 									Description: "If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.",
// 								},
// 								"retention_in_days": {
// 									Type:             schema.TypeInt,
// 									Optional:         true,
// 									Default:          90,
// 									Description:      "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
// 									ValidateDiagFunc: validator.IntAtLeast(0),
// 								},
// 							},
// 						},
// 					},
// 					"all_other_artifacts": {
// 						Type:        schema.TypeSet,
// 						Required:    true,
// 						Description: "If you select by pattern, you must define a retention period for all other artifacts in the repository in the All Other Artifacts setting.",
// 						MinItems:    1,
// 						MaxItems:    1,
// 						Elem: &schema.Resource{
// 							Schema: map[string]*schema.Schema{
// 								"index_new_artifacts": {
// 									Type:        schema.TypeBool,
// 									Optional:    true,
// 									Default:     true,
// 									Description: "If checked, Xray will scan newly added artifacts in the path. Note that existing artifacts will not be scanned. If the folder contains existing artifacts that have been scanned, and you do not want to index new artifacts in that folder, you can choose not to index that folder.",
// 								},
// 								"retention_in_days": {
// 									Type:             schema.TypeInt,
// 									Optional:         true,
// 									Default:          90,
// 									Description:      "The artifact will be retained for the number of days you set here, after the artifact is scanned. This will apply to all artifacts in the repository.",
// 									ValidateDiagFunc: validator.IntAtLeast(0),
// 								},
// 							},
// 						},
// 					},
// 				},
// 			},
// 		},
// 	}
//
// 	var unpackPattern = func(s []interface{}) []Pattern {
// 		var patterns []Pattern
//
// 		for _, raw := range s {
// 			data := raw.(map[string]interface{})
// 			pattern := Pattern{
// 				Include:           data["include"].(string),
// 				Exclude:           data["exclude"].(string),
// 				IndexNewArtifacts: data["index_new_artifacts"].(bool),
// 				RetentionInDays:   data["retention_in_days"].(int),
// 			}
// 			patterns = append(patterns, pattern)
// 		}
//
// 		return patterns
// 	}
//
// 	var unpackAllOtherArtifacts = func(config *schema.Set) AllOtherArtifacts {
// 		allOtherArtifacts := AllOtherArtifacts{}
//
// 		if config != nil {
// 			data := config.List()[0].(map[string]interface{})
// 			allOtherArtifacts.IndexNewArtifacts = data["index_new_artifacts"].(bool)
// 			allOtherArtifacts.RetentionInDays = data["retention_in_days"].(int)
// 		}
//
// 		return allOtherArtifacts
// 	}
//
// 	var unpackRepoPathConfig = func(config *schema.Set) *PathsConfiguration {
// 		repoPathsConfiguration := new(PathsConfiguration)
// 		configList := config.List()
// 		if len(configList) == 0 {
// 			return nil
// 		}
//
// 		m := configList[0].(map[string]interface{})
//
// 		otherArtifacts := unpackAllOtherArtifacts(m["all_other_artifacts"].(*schema.Set))
// 		repoPathsConfiguration.OtherArtifacts = otherArtifacts
//
// 		repoPathsConfiguration.Patterns = unpackPattern(m["pattern"].([]interface{}))
//
// 		return repoPathsConfiguration
// 	}
//
// 	var unpackExposures = func(config *schema.Set, xrayVersion, packageType string) *Exposures {
// 		if !slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
// 			return nil
// 		}
//
// 		if len(config.List()) == 0 {
// 			return nil
// 		}
//
// 		e := config.List()[0].(map[string]interface{})
// 		s := e["scanners_category"].(*schema.Set)
// 		if len(s.List()) == 0 {
// 			return nil
// 		}
//
// 		category := s.List()[0].(map[string]interface{})
//
// 		exposures := Exposures{}
//
// 		switch packageType {
// 		case "docker":
// 			exposures.ScannersCategory = map[string]bool{
// 				"services_scan":     category["services"].(bool),
// 				"secrets_scan":      category["secrets"].(bool),
// 				"applications_scan": category["applications"].(bool),
// 			}
// 		case "maven":
// 			exposures.ScannersCategory = map[string]bool{
// 				"secrets_scan": category["secrets"].(bool),
// 			}
// 		case "npm", "pypi":
// 			exposures.ScannersCategory = map[string]bool{
// 				"secrets_scan":      category["secrets"].(bool),
// 				"applications_scan": category["applications"].(bool),
// 			}
// 		case "terraformbackend":
// 			exposures.ScannersCategory = map[string]bool{
// 				"iac_scan": category["iac"].(bool),
// 			}
// 		}
//
// 		return &exposures
// 	}
//
// 	var unpackRepoConfig = func(_ context.Context, config *schema.Set, xrayVersion, packageType string, jasEnabled bool) *RepoConfiguration {
// 		repoConfig := new(RepoConfiguration)
//
// 		if config != nil {
// 			data := config.List()[0].(map[string]interface{})
// 			repoConfig.RetentionInDays = data["retention_in_days"].(int)
//
// 			if jasEnabled {
// 				if slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
// 					vulnContextualAnalysis := data["vuln_contextual_analysis"].(bool)
// 					repoConfig.VulnContextualAnalysis = &vulnContextualAnalysis
// 				}
// 				repoConfig.Exposures = unpackExposures(data["exposures"].(*schema.Set), xrayVersion, packageType)
// 			}
// 		}
//
// 		return repoConfig
// 	}
//
// 	var unpackRepositoryConfig = func(ctx context.Context, s *schema.ResourceData, xrayVersion, packageType string) RepositoryConfiguration {
// 		d := &sdk.ResourceData{ResourceData: s}
//
// 		repositoryConfig := RepositoryConfiguration{
// 			RepoName: d.GetString("repo_name", false),
// 		}
//
// 		jasEnabled := d.GetBool("jas_enabled", false)
//
// 		if v, ok := s.GetOk("config"); ok {
// 			repositoryConfig.RepoConfig = unpackRepoConfig(ctx, v.(*schema.Set), xrayVersion, packageType, jasEnabled)
// 		}
//
// 		if v, ok := s.GetOk("paths_config"); ok {
// 			repositoryConfig.RepoPathsConfig = unpackRepoPathConfig(v.(*schema.Set))
// 		}
// 		return repositoryConfig
// 	}
//
// 	var packExposures = func(exposures *Exposures, packageType string) []interface{} {
// 		scannersCategory := map[string]bool{
// 			"services":     false,
// 			"secrets":      false,
// 			"iac":          false,
// 			"applications": false,
// 		}
//
// 		switch packageType {
// 		case "docker":
// 			scannersCategory["services"] = exposures.ScannersCategory["services_scan"]
// 			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
// 			scannersCategory["applications"] = exposures.ScannersCategory["applications_scan"]
// 		case "maven":
// 			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
// 		case "npm", "pypi":
// 			scannersCategory["secrets"] = exposures.ScannersCategory["secrets_scan"]
// 			scannersCategory["applications"] = exposures.ScannersCategory["applications_scan"]
// 		case "terraformbackend":
// 			scannersCategory["iac"] = exposures.ScannersCategory["iac_scan"]
// 		}
//
// 		return []interface{}{
// 			map[string][]map[string]bool{
// 				"scanners_category": {scannersCategory},
// 			},
// 		}
// 	}
//
// 	var packGeneralRepoConfig = func(repoConfig *RepoConfiguration, xrayVersion, packageType string, jasEnabled bool) []interface{} {
// 		if repoConfig == nil {
// 			return []interface{}{}
// 		}
//
// 		m := map[string]interface{}{
// 			"retention_in_days": repoConfig.RetentionInDays,
// 		}
//
// 		if jasEnabled {
// 			if repoConfig.VulnContextualAnalysis != nil && slices.Contains(vulnContextualAnalysisPackageTypes(xrayVersion), packageType) {
// 				m["vuln_contextual_analysis"] = *repoConfig.VulnContextualAnalysis
// 			}
//
// 			if repoConfig.Exposures != nil && slices.Contains(exposuresPackageTypes(xrayVersion), packageType) {
// 				m["exposures"] = packExposures(repoConfig.Exposures, packageType)
// 			}
// 		}
//
// 		return []interface{}{m}
// 	}
//
// 	var packAllOtherArtifacts = func(otherArtifacts AllOtherArtifacts) []interface{} {
// 		m := map[string]interface{}{
// 			"index_new_artifacts": otherArtifacts.IndexNewArtifacts,
// 			"retention_in_days":   otherArtifacts.RetentionInDays,
// 		}
//
// 		return []interface{}{m}
// 	}
//
// 	var packPatterns = func(patterns []Pattern) []interface{} {
// 		var ps []interface{}
//
// 		for _, pattern := range patterns {
// 			p := map[string]interface{}{
// 				"include":             pattern.Include,
// 				"exclude":             pattern.Exclude,
// 				"index_new_artifacts": pattern.IndexNewArtifacts,
// 				"retention_in_days":   pattern.RetentionInDays,
// 			}
//
// 			ps = append(ps, p)
// 		}
//
// 		return ps
// 	}
//
// 	var packRepoPathsConfigList = func(repoPathsConfig *PathsConfiguration) []interface{} {
// 		if repoPathsConfig == nil {
// 			return []interface{}{}
// 		}
//
// 		m := map[string]interface{}{
// 			"pattern":             packPatterns(repoPathsConfig.Patterns),
// 			"all_other_artifacts": packAllOtherArtifacts(repoPathsConfig.OtherArtifacts),
// 		}
//
// 		return []interface{}{m}
// 	}
//
// 	var packRepositoryConfig = func(repositoryConfig RepositoryConfiguration, d *schema.ResourceData, xrayVersion, packageType string) diag.Diagnostics {
// 		if err := d.Set("repo_name", repositoryConfig.RepoName); err != nil {
// 			return diag.FromErr(err)
// 		}
//
// 		jasEnabled := false
// 		if v, ok := d.GetOk("jas_enabled"); ok {
// 			jasEnabled = v.(bool)
// 		}
//
// 		if err := d.Set("config", packGeneralRepoConfig(repositoryConfig.RepoConfig, xrayVersion, packageType, jasEnabled)); err != nil {
// 			return diag.FromErr(err)
// 		}
// 		if err := d.Set("paths_config", packRepoPathsConfigList(repositoryConfig.RepoPathsConfig)); err != nil {
// 			return diag.FromErr(err)
// 		}
//
// 		return nil
// 	}
//
// 	var getPackageType = func(client *resty.Client, repoKey string) (repoType string, err error) {
// 		type Repository struct {
// 			PackageType string `json:"packageType"`
// 		}
//
// 		repo := Repository{}
//
// 		_, err = client.R().
// 			SetResult(&repo).
// 			SetPathParam("repoKey", repoKey).
// 			Get("artifactory/api/repositories/{repoKey}")
// 		if err != nil {
// 			fmt.Printf("err: %v\n", err)
// 			return "", err
// 		}
//
// 		return repo.PackageType, nil
// 	}
//
// 	var resourceXrayRepositoryConfigRead = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
// 		repositoryConfig := RepositoryConfiguration{}
// 		repoName := d.Id()
//
// 		metadata := m.(util.ProviderMetadata)
//
// 		resp, err := metadata.Client.R().
// 			SetResult(&repositoryConfig).
// 			SetPathParam("repo_name", repoName).
// 			Get("xray/api/v1/repos_config/{repo_name}")
//
// 		if err != nil {
// 			return diag.FromErr(err)
// 		}
// 		if resp.IsError() {
// 			d.SetId("")
// 			return diag.Errorf("repo (%s) is either not indexed or does not exist", repoName)
// 		}
//
// 		packageType, err := getPackageType(metadata.Client, repoName)
// 		if err != nil {
// 			return diag.FromErr(err)
// 		}
//
// 		return packRepositoryConfig(repositoryConfig, d, metadata.XrayVersion, packageType)
// 	}
//
// 	var resourceXrayRepositoryConfigCreate = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
// 		metadata := m.(util.ProviderMetadata)
// 		packageType, err := getPackageType(metadata.Client, d.Get("repo_name").(string))
// 		if err != nil {
// 			return diag.FromErr(err)
// 		}
//
// 		repositoryConfig := unpackRepositoryConfig(ctx, d, metadata.XrayVersion, packageType)
//
// 		resp, err := metadata.Client.R().SetBody(&repositoryConfig).Put("xray/api/v1/repos_config")
// 		if err != nil {
// 			return diag.FromErr(err)
// 		}
// 		if resp.IsError() {
// 			return diag.Errorf("%s", resp.String())
// 		}
//
// 		d.SetId(repositoryConfig.RepoName)
// 		return resourceXrayRepositoryConfigRead(ctx, d, m)
// 	}
//
// 	// No delete functionality provided by API.
// 	// Delete function will return a warning and remove the Id from the state.
// 	// The option with restoring a default configuration is not viable, because the default can be changed.
// 	var resourceXrayRepositoryConfigDelete = func(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
// 		tflog.Warn(ctx, fmt.Sprintf("There is no delete dunctionality in the API, so the configuration is not "+
// 			"removed from the Artifactory, but (%s) is removed from the Terraform state", d.Id()))
// 		d.SetId("")
//
// 		return diag.Diagnostics{{
// 			Severity: diag.Warning,
// 			Summary:  "No delete functionality provided by API",
// 			Detail:   "Delete function will return a warning and remove the Id from the Terraform state. The actual repository configuration will remain unchanged.",
// 		}}
// 	}
//
// 	var jasEnabledResourceDiff = func(ctx context.Context, diff *schema.ResourceDiff, v interface{}) error {
// 		jasEnabled := false
// 		if v, ok := diff.GetOk("jas_enabled"); ok {
// 			jasEnabled = v.(bool)
// 		}
//
// 		if !jasEnabled {
// 			configSet := diff.Get("config").(*schema.Set).List()
// 			if len(configSet) == 0 {
// 				return nil
// 			}
//
// 			config := configSet[0].(map[string]interface{})
//
// 			if v, ok := config["vuln_contextual_analysis"]; ok && v.(bool) {
// 				return fmt.Errorf("config.vuln_contextual_analysis can not be set when jas_enabled is set to 'true'")
// 			}
//
// 			tflog.Debug(ctx, "jasEnabledResourceDiff", map[string]any{
// 				"config":              config,
// 				"config['exposures']": config["exposures"],
// 			})
// 			if v, ok := config["exposures"]; ok && v.(*schema.Set).Len() > 0 {
// 				return fmt.Errorf("config.exposures can not be set when jas_enabled is set to 'true'")
// 			}
// 		}
//
// 		return nil
// 	}
//
// 	return &schema.Resource{
// 		CreateContext: resourceXrayRepositoryConfigCreate,
// 		ReadContext:   resourceXrayRepositoryConfigRead,
// 		UpdateContext: resourceXrayRepositoryConfigCreate,
// 		DeleteContext: resourceXrayRepositoryConfigDelete,
//
// 		Importer: &schema.ResourceImporter{
// 			StateContext: func(_ context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
// 				parts := strings.SplitN(d.Id(), ":", 2)
//
// 				if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
// 					d.SetId(parts[0])
// 					jasEnabled, err := strconv.ParseBool(parts[1])
// 					if err != nil {
// 						return nil, err
// 					}
// 					d.Set("jas_enabled", jasEnabled)
// 				}
//
// 				return []*schema.ResourceData{d}, nil
// 			},
// 		},
//
// 		CustomizeDiff: jasEnabledResourceDiff,
//
// 		Schema:      repositoryConfigSchema,
// 		Description: "Provides an Xray repository config resource. See [Xray Indexing Resources](https://www.jfrog.com/confluence/display/JFROG/Indexing+Xray+Resources#IndexingXrayResources-SetaRetentionPeriod) and [REST API](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-UpdateRepositoriesConfigurations) for more details.",
// 	}
// }
