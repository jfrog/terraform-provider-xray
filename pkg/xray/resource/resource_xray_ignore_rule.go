package xray

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
)

const (
	IgnoreRulesEndpoint = "xray/api/v1/ignore_rules"
	IgnoreRuleEndpoint  = "xray/api/v1/ignore_rules/{id}"
)

var _ resource.Resource = &IgnoreRuleResource{}

func NewIgnoreRuleResource() resource.Resource {
	return &IgnoreRuleResource{
		TypeName: "xray_ignore_rule",
	}
}

type IgnoreRuleResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

func (r *IgnoreRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

type IgnoreRuleResourceModel struct {
	ID               types.String `tfsdk:"id"`
	ProjectKey       types.String `tfsdk:"project_key"`
	Notes            types.String `tfsdk:"notes"`
	ExpiredAt        types.String `tfsdk:"expiration_date"`
	Author           types.String `tfsdk:"author"`
	Created          types.String `tfsdk:"created"`
	IsExpired        types.Bool   `tfsdk:"is_expired"`
	Vulnerabilities  types.Set    `tfsdk:"vulnerabilities"`
	CVEs             types.Set    `tfsdk:"cves"`
	Licenses         types.Set    `tfsdk:"licenses"`
	OperationalRisks types.Set    `tfsdk:"operational_risk"`
	Policies         types.Set    `tfsdk:"policies"`
	Watches          types.Set    `tfsdk:"watches"`
	DockerLayers     types.Set    `tfsdk:"docker_layers"`
	ReleaseBundles   types.Set    `tfsdk:"release_bundle"`
	Builds           types.Set    `tfsdk:"build"`
	Components       types.Set    `tfsdk:"component"`
	Artifacts        types.Set    `tfsdk:"artifact"`
}

func unpackFilterNameVersion(elem attr.Value, _ int) IgnoreFilterNameVersionAPIModel {
	attrs := elem.(types.Object).Attributes()
	return IgnoreFilterNameVersionAPIModel{
		Name:    attrs["name"].(types.String).ValueString(),
		Version: attrs["version"].(types.String).ValueString(),
	}
}

func unpackFilterNameVersionProject(projectKey string) func(elem attr.Value, _ int) IgnoreFilterNameVersionProjectAPIModel {
	return func(elem attr.Value, _ int) IgnoreFilterNameVersionProjectAPIModel {
		attrs := elem.(types.Object).Attributes()
		return IgnoreFilterNameVersionProjectAPIModel{
			IgnoreFilterNameVersionAPIModel: IgnoreFilterNameVersionAPIModel{
				Name:    attrs["name"].(types.String).ValueString(),
				Version: attrs["version"].(types.String).ValueString(),
			},
			Project: projectKey,
		}
	}
}

func unpackFilterNameVersionPath(elem attr.Value, _ int) IgnoreFilterNameVersionPathAPIModel {
	attrs := elem.(types.Object).Attributes()
	return IgnoreFilterNameVersionPathAPIModel{
		IgnoreFilterNameVersionAPIModel: IgnoreFilterNameVersionAPIModel{
			Name:    attrs["name"].(types.String).ValueString(),
			Version: attrs["version"].(types.String).ValueString(),
		},
		Path: attrs["path"].(types.String).ValueString(),
	}
}

func (m IgnoreRuleResourceModel) toAPIModel(ctx context.Context, apiModel *IgnoreRuleAPIModel) (ds diag.Diagnostics) {
	var created *time.Time
	if m.Created.ValueString() != "" {
		parsedTime, err := time.Parse("2006-01-02", m.Created.ValueString())
		if err != nil {
			ds.AddError(
				"failed to parse date/time string",
				err.Error(),
			)
		}
		created = &parsedTime
	}

	var expiresAt *time.Time
	if m.ExpiredAt.ValueString() != "" {
		parsedTime, err := time.ParseInLocation("2006-01-02", m.ExpiredAt.ValueString(), time.Local)
		if err != nil {
			ds.AddError(
				"failed to parse date/time string",
				err.Error(),
			)
		}
		expiresAt = &parsedTime
	}

	var vulnerabilities []string
	ds.Append(m.Vulnerabilities.ElementsAs(ctx, &vulnerabilities, false)...)

	var cves []string
	ds.Append(m.CVEs.ElementsAs(ctx, &cves, false)...)

	var licenses []string
	ds.Append(m.Licenses.ElementsAs(ctx, &licenses, false)...)

	var watches []string
	ds.Append(m.Watches.ElementsAs(ctx, &watches, false)...)

	var policies []string
	ds.Append(m.Policies.ElementsAs(ctx, &policies, false)...)

	var operationalRisks []string
	ds.Append(m.OperationalRisks.ElementsAs(ctx, &operationalRisks, false)...)

	var dockerLayers []string
	ds.Append(m.DockerLayers.ElementsAs(ctx, &dockerLayers, false)...)

	releaseBundles := lo.Map(
		m.ReleaseBundles.Elements(),
		unpackFilterNameVersion,
	)

	builds := lo.Map(
		m.Builds.Elements(),
		unpackFilterNameVersionProject(m.ProjectKey.ValueString()),
	)

	components := lo.Map(
		m.Components.Elements(),
		unpackFilterNameVersion,
	)

	artifacts := lo.Map(
		m.Artifacts.Elements(),
		unpackFilterNameVersionPath,
	)

	ignoreFilters := IgnoreFiltersAPIModel{
		Vulnerabilities:  vulnerabilities,
		CVEs:             cves,
		Licenses:         licenses,
		Watches:          watches,
		Policies:         policies,
		OperationalRisks: operationalRisks,
		DockerLayers:     dockerLayers,
		ReleaseBundles:   releaseBundles,
		Builds:           builds,
		Components:       components,
		Artifacts:        artifacts,
	}

	*apiModel = IgnoreRuleAPIModel{
		ID:            m.ID.ValueString(),
		Author:        m.Author.ValueString(),
		Created:       created,
		IsExpired:     m.IsExpired.ValueBool(),
		Notes:         m.Notes.ValueString(),
		ExpiresAt:     expiresAt,
		IgnoreFilters: ignoreFilters,
	}

	return
}

var nameVersionPathResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"name":    types.StringType,
	"version": types.StringType,
	"path":    types.StringType,
}

var nameVersionPathSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: nameVersionPathResourceModelAttributeTypes,
}

var nameVersionResourceModelAttributeTypes map[string]attr.Type = map[string]attr.Type{
	"name":    types.StringType,
	"version": types.StringType,
}

var nameVersionSetResourceModelAttributeTypes types.ObjectType = types.ObjectType{
	AttrTypes: nameVersionResourceModelAttributeTypes,
}

func packNameVersion(models []IgnoreFilterNameVersionAPIModel) (basetypes.SetValue, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	nameVersions := lo.Map(
		models,
		func(property IgnoreFilterNameVersionAPIModel, _ int) attr.Value {
			nameVersionMap := map[string]attr.Value{
				"name":    types.StringNull(),
				"version": types.StringNull(),
			}

			if property.Name != "" {
				nameVersionMap["name"] = types.StringValue(property.Name)
			}

			if property.Version != "" {
				nameVersionMap["version"] = types.StringValue(property.Version)
			}

			return types.ObjectValueMust(
				nameVersionResourceModelAttributeTypes,
				nameVersionMap,
			)
		},
	)

	nameVersionSet, d := types.SetValue(
		nameVersionSetResourceModelAttributeTypes,
		nameVersions,
	)
	if d != nil {
		diags.Append(d...)
	}

	return nameVersionSet, diags
}

func packNameVersionProject(models []IgnoreFilterNameVersionProjectAPIModel) (basetypes.SetValue, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	nameVersions := lo.Map(
		models,
		func(property IgnoreFilterNameVersionProjectAPIModel, _ int) attr.Value {
			nameVersionMap := map[string]attr.Value{
				"name":    types.StringNull(),
				"version": types.StringNull(),
			}

			if property.Name != "" {
				nameVersionMap["name"] = types.StringValue(property.Name)
			}

			if property.Version != "" {
				nameVersionMap["version"] = types.StringValue(property.Version)
			}

			return types.ObjectValueMust(
				nameVersionResourceModelAttributeTypes,
				nameVersionMap,
			)
		},
	)

	nameVersionSet, d := types.SetValue(
		nameVersionSetResourceModelAttributeTypes,
		nameVersions,
	)
	if d != nil {
		diags.Append(d...)
	}

	return nameVersionSet, diags
}

func packNameVersionPath(models []IgnoreFilterNameVersionPathAPIModel) (basetypes.SetValue, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	nameVersionPaths := lo.Map(
		models,
		func(property IgnoreFilterNameVersionPathAPIModel, _ int) attr.Value {
			nameVersionPathMap := map[string]attr.Value{
				"name":    types.StringNull(),
				"version": types.StringNull(),
				"path":    types.StringNull(),
			}

			if property.Name != "" {
				nameVersionPathMap["name"] = types.StringValue(property.Name)
			}

			if property.Version != "" {
				nameVersionPathMap["version"] = types.StringValue(property.Version)
			}

			if property.Version != "" {
				nameVersionPathMap["path"] = types.StringValue(property.Path)
			}

			return types.ObjectValueMust(
				nameVersionPathResourceModelAttributeTypes,
				nameVersionPathMap,
			)
		},
	)

	nameVersionPathSet, d := types.SetValue(
		nameVersionPathSetResourceModelAttributeTypes,
		nameVersionPaths,
	)
	if d != nil {
		diags.Append(d...)
	}

	return nameVersionPathSet, diags
}

func (m *IgnoreRuleResourceModel) fromAPIModel(ctx context.Context, apiModel IgnoreRuleAPIModel) diag.Diagnostics {
	diags := diag.Diagnostics{}

	m.ID = types.StringValue(apiModel.ID)
	m.Notes = types.StringValue(apiModel.Notes)

	author := types.StringNull()
	if apiModel.Author != "" {
		author = types.StringValue(apiModel.Author)
	}
	m.Author = author

	created := types.StringNull()
	if apiModel.Created != nil {
		created = types.StringValue(apiModel.Created.Format(time.RFC3339))
	}
	m.Created = created

	expiresAt := types.StringNull()
	if apiModel.ExpiresAt != nil {
		expiresAt = types.StringValue(apiModel.ExpiresAt.Local().Format("2006-01-02"))
	}
	m.ExpiredAt = expiresAt

	m.IsExpired = types.BoolValue(apiModel.IsExpired)

	vulnerabilities, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.Vulnerabilities)
	if d != nil {
		diags.Append(d...)
	}
	m.Vulnerabilities = vulnerabilities

	liceneses, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.Licenses)
	if d != nil {
		diags.Append(d...)
	}
	m.Licenses = liceneses

	cves, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.CVEs)
	if d != nil {
		diags.Append(d...)
	}
	m.CVEs = cves

	operationalRisks, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.OperationalRisks)
	if d != nil {
		diags.Append(d...)
	}
	m.OperationalRisks = operationalRisks

	watches, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.Watches)
	if d != nil {
		diags.Append(d...)
	}
	m.Watches = watches

	policies, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.Policies)
	if d != nil {
		diags.Append(d...)
	}
	m.Policies = policies

	dockerLayers, d := types.SetValueFrom(ctx, types.StringType, apiModel.IgnoreFilters.DockerLayers)
	if d != nil {
		diags.Append(d...)
	}
	m.DockerLayers = dockerLayers

	releaseBundles, d := packNameVersion(apiModel.IgnoreFilters.ReleaseBundles)
	if d != nil {
		diags.Append(d...)
	}
	m.ReleaseBundles = releaseBundles

	builds, d := packNameVersionProject(apiModel.IgnoreFilters.Builds)
	if d != nil {
		diags.Append(d...)
	}
	m.Builds = builds

	components, d := packNameVersion(apiModel.IgnoreFilters.Components)
	if d != nil {
		diags.Append(d...)
	}
	m.Components = components

	artifacts, d := packNameVersionPath(apiModel.IgnoreFilters.Artifacts)
	if d != nil {
		diags.Append(d...)
	}
	m.Artifacts = artifacts

	return diags
}

type IgnoreRuleAPIModel struct {
	ID            string                `json:"id,omitempty"`
	Author        string                `json:"author,omitempty"`
	Created       *time.Time            `json:"created,omitempty"`
	IsExpired     bool                  `json:"is_expired,omitempty"`
	Notes         string                `json:"notes"`
	ExpiresAt     *time.Time            `json:"expires_at,omitempty"`
	IgnoreFilters IgnoreFiltersAPIModel `json:"ignore_filters"`
}

type IgnoreFiltersAPIModel struct {
	Vulnerabilities  []string                                 `json:"vulnerabilities,omitempty"`
	Licenses         []string                                 `json:"licenses,omitempty"`
	CVEs             []string                                 `json:"cves,omitempty"`
	Policies         []string                                 `json:"policies,omitempty"`
	Watches          []string                                 `json:"watches,omitempty"`
	DockerLayers     []string                                 `json:"docker-layers,omitempty"`
	OperationalRisks []string                                 `json:"operational_risk,omitempty"`
	ReleaseBundles   []IgnoreFilterNameVersionAPIModel        `json:"release-bundles,omitempty"`
	Builds           []IgnoreFilterNameVersionProjectAPIModel `json:"builds,omitempty"`
	Components       []IgnoreFilterNameVersionAPIModel        `json:"components,omitempty"`
	Artifacts        []IgnoreFilterNameVersionPathAPIModel    `json:"artifacts,omitempty"`
}

type IgnoreFilterNameVersionAPIModel struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type IgnoreFilterNameVersionProjectAPIModel struct {
	IgnoreFilterNameVersionAPIModel
	Project string `json:"project,omitempty"`
}

type IgnoreFilterNameVersionPathAPIModel struct {
	IgnoreFilterNameVersionAPIModel
	Path string `json:"path,omitempty"`
}

func (r *IgnoreRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the ignore rule",
			},
			"project_key": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validatorfw_string.ProjectKey(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters.",
			},
			"notes": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Notes of the ignore rule",
			},
			"expiration_date": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[0-1])$`),
						"Date must be in YYYY-MM-DD format",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The Ignore Rule will be active until the expiration date. At that date it will automatically get deleted. The rule with the expiration date less than current day, will error out. Vaule assumes to be in local timezone. Ensure client and server time zones match.",
			},
			"author": schema.StringAttribute{
				Computed: true,
			},
			"created": schema.StringAttribute{
				Computed: true,
			},
			"is_expired": schema.BoolAttribute{
				Computed: true,
			},
			"vulnerabilities": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(
						path.MatchRoot("licenses"),
						path.MatchRoot("operational_risk"),
					),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific vulnerabilities to ignore. Omit to apply to all.",
			},
			"cves": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(
						path.MatchRoot("licenses"),
						path.MatchRoot("operational_risk"),
					),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific CVEs to ignore. Omit to apply to all. Should set to 'any' when 'vulnerabilities' is set to 'any'.",
			},
			"licenses": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific licenses to ignore. Omit to apply to all.",
			},
			"operational_risk": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ConflictsWith(
						path.MatchRoot("licenses"),
						path.MatchRoot("vulnerabilities"),
						path.MatchRoot("cves"),
					),
					setvalidator.ValueStringsAre(
						stringvalidator.OneOf("any"),
					),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "Operational risk to ignore. Only accept 'any'",
			},
			"policies": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific policies to ignore. Omit to apply to all.",
			},
			"watches": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific watches to ignore. Omit to apply to all.",
			},
			"docker_layers": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(regexp.MustCompile(`^[0-9a-z]{64}$`), "Must be SHA256 hash"),
					),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of Docker layer SHA256 hashes to ignore. Omit to apply to all.",
			},
		},
		Blocks: map[string]schema.Block{
			"release_bundle": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Name of the release bundle",
						},
						"version": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Version of the release bundle",
						},
					},
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific release bundles to ignore. Omit to apply to all.",
			},
			"build": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Name of the build",
						},
						"version": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Version of the build",
						},
					},
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific builds to ignore. Omit to apply to all.",
			},
			"component": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Name of the component",
						},
						"version": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Version of the component",
						},
					},
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific components to ignore. Omit to apply to all.",
			},
			"artifact": schema.SetNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Name of the artifact. Wildcards are not supported.",
						},
						"version": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Version of the artifact",
						},
						"path": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
								stringvalidator.RegexMatches(regexp.MustCompile(`^.+\/$`), "Must end with a '/'"),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							Description: "Path of the artifact. Must end with a '/'",
						},
					},
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				Description: "List of specific artifacts to ignore. Omit to apply to all.",
			},
		},
		Description: "Provides an Xray ignore rule resource. See [Xray Ignore Rules](https://www.jfrog.com/confluence/display/JFROG/Ignore+Rules) and [REST API](https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-IGNORERULES) for more details. Notice: at least one of the 'vulnerabilities/cves/liceneses', 'component', and 'docker_layers/artifact/build/release_bundle' should not be empty. When selecting the ignore criteria, take note of the combinations you choose. Some combinations such as omitting everything is not allowed as it will ignore all future violations (in the watch or in the system).",
	}
}

func (r *IgnoreRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (r *IgnoreRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan IgnoreRuleResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request, err := getRestyRequest(r.ProviderData.Client, plan.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	type IgnoreRuleCreateResult struct {
		Info string `json:"info"`
	}

	var ignoreRule IgnoreRuleAPIModel
	resp.Diagnostics.Append(plan.toAPIModel(ctx, &ignoreRule)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result IgnoreRuleCreateResult
	response, err := request.
		SetBody(ignoreRule).
		SetResult(&result).
		Post(IgnoreRulesEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}
	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	// response is in this json structure:
	// {
	//   info": "Successfully added Ignore rule with id: c0e5b540-1988-42b2-6a86-b444cda1c521"
	// }
	// use regex to match the group for the ID
	re := regexp.MustCompile(`(?m)^Successfully added Ignore rule with id: (.+)$`)
	matches := re.FindStringSubmatch(result.Info)
	if len(matches) > 1 {
		plan.ID = types.StringValue(matches[1])
	}

	// Fetch the ignore rule to fill out computed fields
	response, err = request.
		SetPathParam("id", plan.ID.ValueString()).
		SetResult(&ignoreRule).
		Get(IgnoreRuleEndpoint)
	if err != nil {
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToCreateResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(plan.fromAPIModel(ctx, ignoreRule)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *IgnoreRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state IgnoreRuleResourceModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request, err := getRestyRequest(r.ProviderData.Client, state.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	var ignoreRule IgnoreRuleAPIModel

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		SetResult(&ignoreRule).
		Get(IgnoreRuleEndpoint)
	if err != nil {
		utilfw.UnableToRefreshResourceError(resp, err.Error())
		return
	}

	if response.StatusCode() == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	if response.IsError() {
		utilfw.UnableToRefreshResourceError(resp, response.String())
		return
	}

	resp.Diagnostics.Append(state.fromAPIModel(ctx, ignoreRule)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *IgnoreRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// noop
}

func (r *IgnoreRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state IgnoreRuleResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	request, err := getRestyRequest(r.ProviderData.Client, state.ProjectKey.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"failed to get Resty client",
			err.Error(),
		)
		return
	}

	response, err := request.
		SetPathParam("id", state.ID.ValueString()).
		Delete(IgnoreRuleEndpoint)

	if err != nil {
		utilfw.UnableToDeleteResourceError(resp, err.Error())
		return
	}

	if response.IsError() {
		utilfw.UnableToDeleteResourceError(resp, response.String())
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState imports the resource into the Terraform state.
func (r *IgnoreRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
