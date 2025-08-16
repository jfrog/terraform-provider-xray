package xray

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
)

var _ resource.Resource = &CatalogLabelsResource{}

func NewCatalogLabelsResource() resource.Resource {
	return &CatalogLabelsResource{
		JFrogResource: util.JFrogResource{
			TypeName:              "xray_catalog_labels",
			CatalogHealthRequired: true,
		},
	}
}

type CatalogLabelsResource struct {
	util.JFrogResource
}

func (r *CatalogLabelsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "xray_catalog_labels"
	r.TypeName = resp.TypeName
}

func (r CatalogLabelsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Labels.IsNull() || data.Labels.IsUnknown() {
		return
	}

	seen := make(map[string]struct{})
	for _, labelVal := range data.Labels.Elements() {
		attrs := labelVal.(types.Object).Attributes()
		nameVal := attrs["name"].(types.String)
		if nameVal.IsNull() || nameVal.IsUnknown() {
			continue
		}
		name := nameVal.ValueString()
		if _, exists := seen[name]; exists {
			resp.Diagnostics.AddAttributeError(
				path.Root("labels").AtSetValue(labelVal).AtName("name"),
				"Duplicate label name",
				fmt.Sprintf("Label name '%s' is duplicated in the labels block. Label names must be unique.", name),
			)
			// continue to report all duplicates
			continue
		}
		seen[name] = struct{}{}
	}
}

type CatalogLabelsResourceModel struct {
	Labels             types.Set `tfsdk:"labels"`
	PackageAssignments types.Set `tfsdk:"package_assignments"`
	VersionAssignments types.Set `tfsdk:"version_assignments"`
}

type LabelModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

type PackageAssignmentModel struct {
	LabelName   types.String `tfsdk:"label_name"`
	PackageName types.String `tfsdk:"package_name"`
	PackageType types.String `tfsdk:"package_type"`
}

type VersionAssignmentModel struct {
	LabelName   types.String `tfsdk:"label_name"`
	PackageName types.String `tfsdk:"package_name"`
	PackageType types.String `tfsdk:"package_type"`
	Versions    types.Set    `tfsdk:"versions"`
}

// Internal helper for expanded version assignments
type versionAssignmentExpanded struct {
	labelName   string
	packageName string
	packageType string
	version     string
}

func (r *CatalogLabelsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	r.JFrogResource.Configure(ctx, req, resp)

	// Perform catalog health check if this resource requires it
	if r.CatalogHealthRequired {
		providerData := r.JFrogResource.ProviderData
		err := r.JFrogResource.ValidateCatalogHealth(providerData)
		if err != nil {
			resp.Diagnostics.AddError(
				"Catalog Health Check Failed",
				fmt.Sprintf("Resource requires catalog functionality but catalog health check failed: %s", err.Error()),
			)
			return
		}
	}
}

// getExistingLabels checks if specific labels exist in the catalog.
// - For a single label, it uses getLabel for precision.
// - For multiple labels, it uses searchLabels and filters client-side.
func (r *CatalogLabelsResource) getExistingLabels(ctx context.Context, labelNames []string) (map[string]string, error) {
	existingLabels := make(map[string]string)
	if len(labelNames) == 0 {
		return existingLabels, nil
	}

	if len(labelNames) == 1 {
		// Single label -> use getLabel
		single := labelNames[0]
		query := getLabelQuery(single)

		var graphqlResp GetSingleLabelResponse
		resp, err := r.JFrogResource.ProviderData.Client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]interface{}{"query": query}).
			SetResult(&graphqlResp).
			Post(CatalogGraphQLEndpoint)
		if err != nil {
			log.Printf("[DEBUG] GraphQL getLabel query failed for label %s: %s", single, err.Error())
			return existingLabels, nil
		}
		if resp.StatusCode() == 200 && graphqlResp.Data.CustomCatalogLabel.GetLabel.Name != "" {
			existingLabels[graphqlResp.Data.CustomCatalogLabel.GetLabel.Name] = graphqlResp.Data.CustomCatalogLabel.GetLabel.Description
		}
		return existingLabels, nil
	}

	// Multiple labels -> use searchLabels and filter locally
	query := searchLabelsQuery()

	var searchResp GetMultipleLabelsResponse
	resp, err := r.JFrogResource.ProviderData.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"query": query}).
		SetResult(&searchResp).
		Post(CatalogGraphQLEndpoint)
	if err != nil {
		log.Printf("[DEBUG] GraphQL searchLabels query failed: %s", err.Error())
		return existingLabels, nil
	}
	if resp.StatusCode() != 200 {
		log.Printf("[DEBUG] searchLabels returned non-200 status: %d", resp.StatusCode())
		return existingLabels, nil
	}

	wanted := make(map[string]struct{}, len(labelNames))
	for _, n := range labelNames {
		wanted[n] = struct{}{}
	}
	for _, edge := range searchResp.Data.CustomCatalogLabel.SearchLabels.Edges {
		name := edge.Node.Name
		if _, ok := wanted[name]; ok {
			existingLabels[name] = edge.Node.Description
		}
	}

	log.Printf("[DEBUG] getExistingLabels(search): found %d/%d labels", len(existingLabels), len(labelNames))
	return existingLabels, nil
}

// validateLabelsExistenceUnified validates that all provided labels exist in either the plan/state labels or in the catalog.
// - If state is nil, only the plan is considered for local existence checks.
// - If resp is provided (plan-time validation), errors/warnings are reported via resp; otherwise errors are returned.
func (r *CatalogLabelsResource) validateLabelsExistenceUnified(ctx context.Context, labelNames []string, plan *CatalogLabelsResourceModel, state *CatalogLabelsResourceModel, resp *resource.ModifyPlanResponse, contextHint string) ([]string, error) {

	if len(labelNames) == 0 {
		return nil, nil
	}

	// Build local label set from plan and state when available
	localLabels := make(map[string]struct{})
	if plan != nil && !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		var planLabels []LabelModel
		if diags := plan.Labels.ElementsAs(ctx, &planLabels, false); !diags.HasError() {
			for _, l := range planLabels {
				if !l.Name.IsUnknown() && !l.Name.IsNull() {
					localLabels[l.Name.ValueString()] = struct{}{}
				}
			}
		}
	}
	if state != nil && !state.Labels.IsNull() && !state.Labels.IsUnknown() {
		var stateLabels []LabelModel
		if diags := state.Labels.ElementsAs(ctx, &stateLabels, false); !diags.HasError() {
			for _, l := range stateLabels {
				if !l.Name.IsUnknown() && !l.Name.IsNull() {
					localLabels[l.Name.ValueString()] = struct{}{}
				}
			}
		}
	}

	// Determine which labels require catalog validation
	var toCheck []string
	for _, name := range uniqueStrings(labelNames) {
		if _, ok := localLabels[name]; !ok {
			toCheck = append(toCheck, name)
		}
	}
	if len(toCheck) == 0 {
		return nil, nil
	}

	existingInCatalog, err := r.getExistingLabels(ctx, toCheck)
	if err != nil {
		if resp != nil {
			resp.Diagnostics.AddWarning(
				"Unable to validate label existence",
				fmt.Sprintf("Could not check if %s labels exist in catalog: %s. The operation will be validated during apply.", contextHint, err.Error()),
			)
		}
		return nil, fmt.Errorf("failed to check label existence in catalog: %w", err)
	}

	var missing []string
	for _, name := range toCheck {
		if _, exists := existingInCatalog[name]; !exists {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

// getAssignedLabelsForPackage returns the set of label names currently assigned to a package
func (r *CatalogLabelsResource) getAssignedLabelsForPackage(ctx context.Context, packageName, packageType string) (map[string]struct{}, error) {
	assigned := make(map[string]struct{})

	query := getPackageLabelsQuery(packageName, packageType)

	var graphqlResp GetPackageLabelResponse
	resp, err := r.JFrogResource.ProviderData.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"query": query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)

	if err != nil {
		log.Printf("[DEBUG] GraphQL getPackage query failed for %s:%s: %s", packageType, packageName, err.Error())
		return assigned, nil
	}

	if resp.StatusCode() == 200 && graphqlResp.Data.PublicPackage.GetPackage.Name != "" {
		for _, edge := range graphqlResp.Data.PublicPackage.GetPackage.CustomCatalogLabelsConnection.Edges {
			assigned[edge.Node.Name] = struct{}{}
		}
		log.Printf("[DEBUG] Found %d assigned labels for %s:%s", len(assigned), packageType, packageName)
	} else {
		log.Printf("[DEBUG] No assigned labels found for %s:%s (status: %d)", packageType, packageName, resp.StatusCode())
	}

	return assigned, nil
}

// validatePackageAssignmentRedundancyInPlan warns if a planned package assignment already exists in catalog
func (r *CatalogLabelsResource) validatePackageAssignmentRedundancyInPlan(ctx context.Context, plan *CatalogLabelsResourceModel, state *CatalogLabelsResourceModel, resp *resource.ModifyPlanResponse) {
	if plan.PackageAssignments.IsNull() || plan.PackageAssignments.IsUnknown() {
		return
	}

	var assignments []PackageAssignmentModel
	resp.Diagnostics.Append(plan.PackageAssignments.ElementsAs(ctx, &assignments, false)...)
	if resp.Diagnostics.HasError() || len(assignments) == 0 {
		return
	}

	type pkgKey struct{ name, ptype string }
	cache := make(map[pkgKey]map[string]struct{})

	// Build state map of existing package->label assignments (if state provided)
	stateAssigned := make(map[pkgKey]map[string]struct{})
	if state != nil && !state.PackageAssignments.IsNull() && !state.PackageAssignments.IsUnknown() {
		var sassign []PackageAssignmentModel
		if diags := state.PackageAssignments.ElementsAs(ctx, &sassign, false); !diags.HasError() {
			for _, a := range sassign {
				k := pkgKey{a.PackageName.ValueString(), a.PackageType.ValueString()}
				if _, ok := stateAssigned[k]; !ok {
					stateAssigned[k] = make(map[string]struct{})
				}
				if !a.LabelName.IsNull() && !a.LabelName.IsUnknown() {
					stateAssigned[k][a.LabelName.ValueString()] = struct{}{}
				}
			}
		}
	}

	for _, a := range assignments {
		if a.LabelName.IsNull() || a.LabelName.IsUnknown() || a.PackageName.IsNull() || a.PackageType.IsNull() {
			continue
		}
		key := pkgKey{a.PackageName.ValueString(), a.PackageType.ValueString()}
		if _, ok := cache[key]; !ok {
			assigned, err := r.getAssignedLabelsForPackage(ctx, key.name, key.ptype)
			if err != nil {
				continue
			}
			cache[key] = assigned
		}
		if _, already := cache[key][a.LabelName.ValueString()]; already {
			// Only warn if this package-label is NOT already present in state
			if _, presentInState := stateAssigned[key][a.LabelName.ValueString()]; presentInState {
				continue
			}
			resp.Diagnostics.AddWarning(
				"Package already has this label assigned",
				fmt.Sprintf("Package %s:%s already has label '%s' assigned. This assignment will be skipped during apply.", key.ptype, key.name, a.LabelName.ValueString()),
			)
		}
	}
}

// getAssignedLabelsForPackageVersion returns the set of label names currently assigned to a package version
func (r *CatalogLabelsResource) getAssignedLabelsForPackageVersion(ctx context.Context, packageName, packageType, version string) (map[string]struct{}, error) {
	assigned := make(map[string]struct{})

	query := getPackageVersionLabelsQuery(packageName, packageType, version)

	var graphqlResp GetPackageVersionLabelsResponse
	resp, err := r.JFrogResource.ProviderData.Client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]interface{}{"query": query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)

	if err != nil {
		log.Printf("[DEBUG] GraphQL getPackageVersion query failed for %s:%s@%s: %s", packageType, packageName, version, err.Error())
		return assigned, nil
	}

	if resp.StatusCode() == 200 {
		for _, edge := range graphqlResp.Data.PublicPackageVersion.GetVersion.CustomCatalogLabelsConnection.Edges {
			assigned[edge.Node.Name] = struct{}{}
		}
		log.Printf("[DEBUG] Found %d assigned labels for %s:%s@%s", len(assigned), packageType, packageName, version)
	} else {
		log.Printf("[DEBUG] No assigned labels found for %s:%s@%s (status: %d)", packageType, packageName, version, resp.StatusCode())
	}

	return assigned, nil
}

// validatePackageVersionAssignmentRedundancyInPlan errors if any targeted package version already has a label
// Skips the error when the specific package:version is already tracked in state for this resource
func (r *CatalogLabelsResource) validatePackageVersionAssignmentRedundancyInPlan(ctx context.Context, plan *CatalogLabelsResourceModel, state *CatalogLabelsResourceModel, resp *resource.ModifyPlanResponse) {
	if plan.VersionAssignments.IsNull() || plan.VersionAssignments.IsUnknown() {
		return
	}

	var assignments []VersionAssignmentModel
	resp.Diagnostics.Append(plan.VersionAssignments.ElementsAs(ctx, &assignments, false)...)
	if resp.Diagnostics.HasError() || len(assignments) == 0 {
		return
	}

	// Build set of versions present in state (if provided)
	stateKeys := make(map[string]struct{})
	if state != nil && !state.VersionAssignments.IsNull() && !state.VersionAssignments.IsUnknown() {
		var sassign []VersionAssignmentModel
		if diags := state.VersionAssignments.ElementsAs(ctx, &sassign, false); !diags.HasError() {
			for _, a := range sassign {
				var vs []string
				if !a.Versions.IsNull() && !a.Versions.IsUnknown() && len(a.Versions.Elements()) > 0 {
					if d2 := a.Versions.ElementsAs(ctx, &vs, false); !d2.HasError() {
						for _, v := range vs {
							key := fmt.Sprintf("%s:%s:%s", a.PackageName.ValueString(), a.PackageType.ValueString(), v)
							stateKeys[key] = struct{}{}
						}
					}
				}
			}
		}
	}

	// Expand versions sets
	for _, a := range assignments {
		if a.Versions.IsNull() || a.Versions.IsUnknown() || len(a.Versions.Elements()) == 0 {
			continue
		}
		var vs []string
		resp.Diagnostics.Append(a.Versions.ElementsAs(ctx, &vs, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, v := range vs {
			assigned, err := r.getAssignedLabelsForPackageVersion(ctx, a.PackageName.ValueString(), a.PackageType.ValueString(), v)
			if err != nil {
				// non-fatal
				continue
			}
			if len(assigned) > 0 {
				// Skip error if this exact package:version is already tracked in state
				key := fmt.Sprintf("%s:%s:%s", a.PackageName.ValueString(), a.PackageType.ValueString(), v)
				if _, ok := stateKeys[key]; ok {
					continue
				}
				// collect existing assigned label names
				var existing []string
				for lbl := range assigned {
					existing = append(existing, lbl)
				}
				existingText := strings.Join(existing, ", ")
				if existingText == "" {
					existingText = "<unknown>"
				}
				resp.Diagnostics.AddWarning(
					"Package version already has a label assigned",
					fmt.Sprintf("Package version already has label '%s' assigned: %s:%s@%s. This assignment will be skipped during apply.", existingText, a.PackageType.ValueString(), a.PackageName.ValueString(), v),
				)
				// Continue checking remaining versions
				continue
			}
		}
	}
}

func (r *CatalogLabelsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// On destroy, plan is null. Skip validations to avoid decoding null into a non-nullable model.
	if req.Plan.Raw.IsNull() {
		log.Printf("[DEBUG] ModifyPlan: plan is null (destroy), skipping validations")
		return
	}

	var plan CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current state to support validation against existing labels
	var state CatalogLabelsResourceModel
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Check for existing labels in catalog during plan phase (CREATE operations only)
	if req.State.Raw.IsNull() && !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		var planLabels []LabelModel
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &planLabels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Extract label names to check
		var labelNames []string
		for _, planLabel := range planLabels {
			if !planLabel.Name.IsUnknown() && !planLabel.Name.IsNull() {
				labelNames = append(labelNames, planLabel.Name.ValueString())
			}
		}

		if len(labelNames) > 0 {
			// Check if any planned labels already exist in the catalog
			existingLabels, err := r.getExistingLabels(ctx, labelNames)
			if err != nil {
				// If we can't check existing labels, add a warning but don't fail the plan
				resp.Diagnostics.AddWarning(
					"Unable to validate label existence",
					fmt.Sprintf("Could not check if labels already exist in catalog: %s. The operation will be validated during apply.", err.Error()),
				)
				return
			}

			var conflictingLabels []string
			for _, labelName := range labelNames {
				if _, exists := existingLabels[labelName]; exists {
					conflictingLabels = append(conflictingLabels, labelName)
				}
			}

			if len(conflictingLabels) > 0 {
				resp.Diagnostics.AddWarning(
					"Labels already exist in catalog",
					fmt.Sprintf("The following labels already exist in the catalog and will be skipped during creation: %s", strings.Join(conflictingLabels, ", ")),
				)
			} else {
				log.Printf("[DEBUG] Plan validation: All %d labels are available for creation", len(labelNames))
			}
		}
	}

	// Validate package assignments against state and catalog (both CREATE and UPDATE)
	if !plan.PackageAssignments.IsNull() && !plan.PackageAssignments.IsUnknown() {
		operationType := "CREATE"
		if !req.State.Raw.IsNull() {
			operationType = "UPDATE"
		}
		log.Printf("[DEBUG] Plan validation (%s): Validating package assignment labels against state and catalog", operationType)
		// Build label list from package assignments and validate
		if !plan.PackageAssignments.IsNull() && !plan.PackageAssignments.IsUnknown() {
			var assignments []PackageAssignmentModel
			resp.Diagnostics.Append(plan.PackageAssignments.ElementsAs(ctx, &assignments, false)...)
			if !resp.Diagnostics.HasError() && len(assignments) > 0 {
				var names []string
				for _, a := range assignments {
					if !a.LabelName.IsNull() && !a.LabelName.IsUnknown() {
						names = append(names, a.LabelName.ValueString())
					}
				}
				_, _ = r.validateLabelsExistenceUnified(ctx, names, &plan, func() *CatalogLabelsResourceModel {
					if req.State.Raw.IsNull() {
						return nil
					}
					return &state
				}(), nil, "package assignments")
			}
		}

		// Warn if assignment already exists in catalog to prevent redundant operations (only when not in state)
		r.validatePackageAssignmentRedundancyInPlan(ctx, &plan, func() *CatalogLabelsResourceModel {
			if req.State.Raw.IsNull() {
				return nil
			}
			return &state
		}(), resp)
	}

	// Validate version assignments against state and catalog (both CREATE and UPDATE)
	if !plan.VersionAssignments.IsNull() && !plan.VersionAssignments.IsUnknown() {
		operationType := "CREATE"
		if !req.State.Raw.IsNull() {
			operationType = "UPDATE"
		}
		log.Printf("[DEBUG] Plan validation (%s): Validating version assignment labels against state and catalog", operationType)
		// Build label list from version assignments and validate
		if !plan.VersionAssignments.IsNull() && !plan.VersionAssignments.IsUnknown() {
			var assignments []VersionAssignmentModel
			resp.Diagnostics.Append(plan.VersionAssignments.ElementsAs(ctx, &assignments, false)...)
			if !resp.Diagnostics.HasError() && len(assignments) > 0 {
				var names []string
				for _, a := range assignments {
					if !a.LabelName.IsNull() && !a.LabelName.IsUnknown() {
						names = append(names, a.LabelName.ValueString())
					}
				}
				_, _ = r.validateLabelsExistenceUnified(ctx, names, &plan, func() *CatalogLabelsResourceModel {
					if req.State.Raw.IsNull() {
						return nil
					}
					return &state
				}(), nil, "version assignments")
			}
		}

		// Error if any targeted package version already has a label, unless already in state
		r.validatePackageVersionAssignmentRedundancyInPlan(ctx, &plan, func() *CatalogLabelsResourceModel {
			if req.State.Raw.IsNull() {
				return nil
			}
			return &state
		}(), resp)
	}
}

func (r *CatalogLabelsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages JFrog Catalog labels and their assignments using the correct GraphQL API mutations. \n\n" +
			"~> Requires JFrog Catalog service to be available.",
		Attributes: map[string]schema.Attribute{
			"labels": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: fmt.Sprintf("Set of catalog labels to manage. At least one label is required. Maximum of %d labels can be created in a single operation.", MaxLabelsPerOperation),
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthAtMost(MaxLabelNameLength),
								stringvalidator.LengthAtLeast(2),
							},
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.RequiresReplace(),
							},
							MarkdownDescription: fmt.Sprintf("The name of the catalog label. Must be unique and have at most %d characters.", MaxLabelNameLength),
						},
						"description": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthAtMost(MaxLabelDescriptionLength),
								stringvalidator.LengthAtLeast(1),
							},
							MarkdownDescription: fmt.Sprintf("Description of the catalog label. Must have at most %d characters.", MaxLabelDescriptionLength),
						},
					},
				},
			},
			"package_assignments": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Set of package assignments. Assigns labels to packages. Note: Only one label per package is supported by the API.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"label_name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Label name to assign to the package. API supports only 1 label per assignment.",
						},
						"package_name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Name of the package to assign labels to.",
						},
						"package_type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Type of the package (e.g., npm, maven, docker, etc.).",
						},
					},
				},
			},
			"version_assignments": schema.SetNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Set of package version assignments. Assigns labels to specific package versions. Note: Only one label per package version is supported by the API.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"label_name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Label name to assign to the package version. API supports only 1 label per assignment.",
						},
						"package_name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Name of the package.",
						},
						"package_type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Type of the package (e.g., npm, maven, docker, etc.).",
						},
						"versions": schema.SetAttribute{
							Required:    true,
							ElementType: types.StringType,
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
								setvalidator.ValueStringsAre(
									stringvalidator.LengthAtLeast(1),
								),
							},
							MarkdownDescription: "List of versions for bulk assignment with the same label. Must contain at least one non-empty version.",
						},
					},
				},
			},
		},
	}
}

func (r *CatalogLabelsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	log.Printf("[DEBUG] ========== CATALOG LABELS CREATE OPERATION STARTED ==========")

	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.JFrogResource.TypeName)

	var plan CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		log.Printf("[ERROR] Failed to read plan during create operation")
		return
	}

	// Check for existing labels before creating new ones
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		var planLabels []LabelModel
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &planLabels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Extract label names to check
		var labelNames []string
		for _, planLabel := range planLabels {
			labelNames = append(labelNames, planLabel.Name.ValueString())
		}

		// Check if any planned labels already exist
		existingLabels, err := r.getExistingLabels(ctx, labelNames)
		if err != nil {
			log.Printf("[ERROR] Failed to get existing labels: %s", err.Error())
			utilfw.UnableToCreateResourceError(resp, err.Error())
			return
		}

		var conflictingLabels []string
		for _, planLabel := range planLabels {
			labelName := planLabel.Name.ValueString()
			if _, exists := existingLabels[labelName]; exists {
				conflictingLabels = append(conflictingLabels, labelName)
			}
		}

		if len(conflictingLabels) > 0 {
			log.Printf("[DEBUG] %d labels already exist and will be skipped: %s", len(conflictingLabels), strings.Join(conflictingLabels, ", "))
		}

		// Filter out labels that already exist; create only new ones
		var labelsToCreate []LabelModel
		for _, planLabel := range planLabels {
			labelName := planLabel.Name.ValueString()
			if _, exists := existingLabels[labelName]; !exists {
				labelsToCreate = append(labelsToCreate, planLabel)
			} else {
				log.Printf("[DEBUG] Label '%s' already exists; skipping creation", labelName)
			}
		}

		if len(labelsToCreate) > 0 {
			log.Printf("[DEBUG] Creating %d new labels; %d already exist", len(labelsToCreate), len(planLabels)-len(labelsToCreate))
			err = r.createLabels(ctx, labelsToCreate, resp)
			if err != nil {
				utilfw.UnableToCreateResourceError(resp, err.Error())
				return
			}
		} else {
			log.Printf("[DEBUG] All %d labels already exist; skipping label creation", len(planLabels))
		}
	}

	// Then create package assignments
	log.Printf("[DEBUG] Checking package assignments: IsNull=%t, IsUnknown=%t", plan.PackageAssignments.IsNull(), plan.PackageAssignments.IsUnknown())
	if !plan.PackageAssignments.IsNull() && !plan.PackageAssignments.IsUnknown() {
		log.Printf("[DEBUG] Calling assignPackageLabels")
		err := r.assignPackageLabels(ctx, &plan, resp)
		if err != nil {
			log.Printf("[ERROR] Failed to assign package labels: %s", err.Error())
			return
		}
	} else {
		log.Printf("[DEBUG] Skipping package assignments")
	}

	// Finally create version assignments
	if !plan.VersionAssignments.IsNull() && !plan.VersionAssignments.IsUnknown() {
		err := r.assignPackageVersionLabels(ctx, &plan, resp)
		if err != nil {
			log.Printf("[ERROR] Failed to assign version labels: %s", err.Error())
			utilfw.UnableToCreateResourceError(resp, err.Error())
			return
		}
	} else {
		log.Printf("[DEBUG] Skipping package version assignments")
	}

	// Save data into Terraform state
	log.Printf("[DEBUG] Saving catalog labels resource to Terraform state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		log.Printf("[ERROR] Failed to save catalog labels resource to state")
		return
	}
	log.Printf("[DEBUG] Successfully saved catalog labels resource to state")
	log.Printf("[DEBUG] ========== CATALOG LABELS CREATE OPERATION COMPLETED ==========")
}

func (r *CatalogLabelsResource) createLabels(ctx context.Context, labels []LabelModel, resp *resource.CreateResponse) error {
	if len(labels) == 0 {
		return nil
	}

	if len(labels) == 1 {
		return r.createSingleLabel(ctx, labels[0], resp)
	}

	return r.createMultipleLabels(ctx, labels, resp)
}

func (r *CatalogLabelsResource) createSingleLabel(ctx context.Context, label LabelModel, resp *resource.CreateResponse) error {
	query := createSingleLabelMutation(label.Name.ValueString(), label.Description.ValueString())
	var graphqlResp CreateLabelResponse
	response, err := r.ProviderData.Client.R().
		SetBody(GraphQLRequest{Query: query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)
	if err != nil {
		log.Printf("[ERROR] Failed to create catalog label: %s", err.Error())
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return err
	}
	if response.IsError() {
		log.Printf("[ERROR] GraphQL error creating label: %s", response.String())
		errorMsg := r.parseGraphQLError(response.String())
		utilfw.UnableToCreateResourceError(resp, errorMsg)
		return fmt.Errorf("GraphQL error: %s", errorMsg)
	}
	log.Printf("[DEBUG] Successfully created label: %s", label.Name.ValueString())
	return nil
}

func (r *CatalogLabelsResource) createMultipleLabels(ctx context.Context, labels []LabelModel, resp *resource.CreateResponse) error {
	// Build labels array for GraphQL mutation
	var labelsJson []string
	for _, label := range labels {
		labelsJson = append(labelsJson, fmt.Sprintf(`{name: "%s", description: "%s"}`,
			label.Name.ValueString(), label.Description.ValueString()))
	}
	query := createMultipleLabelsMutation(strings.Join(labelsJson, ", "))
	log.Printf("[DEBUG] GraphQL create multiple labels query: %s", query)

	var graphqlResp CreateMultipleLabelsResponse
	response, err := r.ProviderData.Client.R().
		SetBody(GraphQLRequest{Query: query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)

	if err != nil {
		log.Printf("[ERROR] Failed to create catalog labels: %s", err.Error())
		utilfw.UnableToCreateResourceError(resp, err.Error())
		return err
	}

	log.Printf("[DEBUG] Create labels response: %s", response.String())

	if response.IsError() {
		log.Printf("[ERROR] GraphQL error creating labels: %s", response.String())
		errorMsg := r.parseGraphQLError(response.String())
		utilfw.UnableToCreateResourceError(resp, errorMsg)
		return fmt.Errorf("GraphQL error: %s", errorMsg)
	}

	log.Printf("[DEBUG] Successfully created %d catalog labels", len(graphqlResp.Data.CustomCatalogLabel.CreateCustomCatalogLabels))
	return nil
}

func (r *CatalogLabelsResource) assignPackageLabels(ctx context.Context, plan *CatalogLabelsResourceModel, resp interface{}) error {
	log.Printf("[DEBUG] assignPackageLabels function called")
	var assignments []PackageAssignmentModel
	{
		// Append diags to response when possible
		switch h := resp.(type) {
		case *resource.CreateResponse:
			h.Diagnostics.Append(plan.PackageAssignments.ElementsAs(ctx, &assignments, false)...)
			if h.Diagnostics.HasError() {
				return fmt.Errorf("failed to extract package assignments")
			}
		case *resource.UpdateResponse:
			h.Diagnostics.Append(plan.PackageAssignments.ElementsAs(ctx, &assignments, false)...)
			if h.Diagnostics.HasError() {
				return fmt.Errorf("failed to extract package assignments")
			}
		default:
			diags := plan.PackageAssignments.ElementsAs(ctx, &assignments, false)
			if diags.HasError() {
				return fmt.Errorf("failed to extract package assignments")
			}
		}
	}
	log.Printf("[DEBUG] Found %d package assignments", len(assignments))

	// Validate required fields before any existence checks
	for _, assignment := range assignments {
		if assignment.LabelName.IsNull() || assignment.LabelName.IsUnknown() || assignment.LabelName.ValueString() == "" {
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, "Label must be specified for the assignment. Package assignments must include a label name.")
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, "Label must be specified for the assignment. Package assignments must include a label name.")
			}
			return fmt.Errorf("label must be specified for package assignment")
		}
	}

	// Collect all label names to validate their existence
	var allLabelNames []string
	for _, assignment := range assignments {
		labelName := assignment.LabelName.ValueString()
		allLabelNames = append(allLabelNames, labelName)
	}

	// Validate all referenced labels exist in either local state or catalog
	if len(allLabelNames) > 0 {
		log.Printf("[DEBUG] Validating existence of %d labels for package assignments", len(allLabelNames))
		missingLabels, err := r.validateLabelsExistenceUnified(ctx, allLabelNames, plan, nil, nil, "package")
		if err != nil {
			log.Printf("[ERROR] Failed to validate label existence: %s", err.Error())
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, fmt.Sprintf("Failed to validate label existence: %s", err.Error()))
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, fmt.Sprintf("Failed to validate label existence: %s", err.Error()))
			}
			return err
		}

		if len(missingLabels) > 0 {
			errorMsg := fmt.Sprintf("The following labels do not exist in local state or catalog: %s. Please create these labels first or define them in the labels block.", strings.Join(missingLabels, ", "))
			log.Printf("[ERROR] %s", errorMsg)
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, errorMsg)
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, errorMsg)
			}
			return fmt.Errorf("referenced labels do not exist: %s", strings.Join(missingLabels, ", "))
		}
		log.Printf("[DEBUG] All %d referenced labels exist in state or catalog", len(allLabelNames))
	}

	// Group assignments by label name for bulk operations
	labelToPackages := make(map[string][]PackageAssignmentModel)

	for _, assignment := range assignments {
		labelName := assignment.LabelName.ValueString()
		labelToPackages[labelName] = append(labelToPackages[labelName], assignment)
	}

	// Process each label group - assign to all packages for that label
	for labelName, packageAssignments := range labelToPackages {
		log.Printf("[DEBUG] Assigning label '%s' to %d packages", labelName, len(packageAssignments))

		// Skip if label is already assigned to this package
		assigned, err := r.getAssignedLabelsForPackage(ctx, packageAssignments[0].PackageName.ValueString(), packageAssignments[0].PackageType.ValueString())
		if err == nil {
			if _, exists := assigned[labelName]; exists {
				log.Printf("[DEBUG] Package %s:%s already has label '%s' assigned. Skipping.", packageAssignments[0].PackageType.ValueString(), packageAssignments[0].PackageName.ValueString(), labelName)
				continue
			}
		}

		// Assign the same label to multiple packages (individual assignments since no bulk API exists)
		for _, assignment := range packageAssignments {
			query := assignPackageLabelMutation(
				assignment.PackageName.ValueString(),
				assignment.PackageType.ValueString(),
				labelName,
			)

			log.Printf("[DEBUG] GraphQL assign single package label query: %s", query)

			var graphqlResp AssignPackagelabelResponse
			response, err := r.ProviderData.Client.R().
				SetBody(GraphQLRequest{Query: query}).
				SetResult(&graphqlResp).
				Post(CatalogGraphQLEndpoint)

			if err != nil {
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, err.Error())
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, err.Error())
				}
				return err
			}

			if response.IsError() {
				log.Printf("[ERROR] GraphQL error assigning package label: %s", response.String())
				errorMsg := r.parseGraphQLError(response.String())
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, errorMsg)
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, errorMsg)
				}
				return fmt.Errorf("GraphQL error: %s", errorMsg)
			}
		}

		log.Printf("[DEBUG] Successfully assigned label '%s' to %d packages", labelName, len(packageAssignments))
	}

	return nil
}

func (r *CatalogLabelsResource) assignPackageVersionLabels(ctx context.Context, plan *CatalogLabelsResourceModel, resp interface{}) error {
	var assignments []VersionAssignmentModel
	{
		switch h := resp.(type) {
		case *resource.CreateResponse:
			h.Diagnostics.Append(plan.VersionAssignments.ElementsAs(ctx, &assignments, false)...)
			if h.Diagnostics.HasError() {
				return fmt.Errorf("failed to extract version assignments")
			}
		case *resource.UpdateResponse:
			h.Diagnostics.Append(plan.VersionAssignments.ElementsAs(ctx, &assignments, false)...)
			if h.Diagnostics.HasError() {
				return fmt.Errorf("failed to extract version assignments")
			}
		default:
			diags := plan.VersionAssignments.ElementsAs(ctx, &assignments, false)
			if diags.HasError() {
				return fmt.Errorf("failed to extract version assignments")
			}
		}
	}

	// Expand versions list into individual assignments
	var expanded []versionAssignmentExpanded
	for _, a := range assignments {
		// Validate required label name before proceeding
		if a.LabelName.IsNull() || a.LabelName.IsUnknown() || a.LabelName.ValueString() == "" {
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, "Label must be specified for the assignment. Version assignments must include a label name.")
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, "Label must be specified for the assignment. Version assignments must include a label name.")
			}
			return fmt.Errorf("label must be specified for version assignment")
		}
		if !a.Versions.IsNull() && !a.Versions.IsUnknown() && len(a.Versions.Elements()) > 0 {
			var vs []string
			// Use a generic path without appending to resp
			if diags := a.Versions.ElementsAs(ctx, &vs, false); diags.HasError() {
				return fmt.Errorf("failed to extract versions list")
			}
			for _, v := range vs {
				expanded = append(expanded, versionAssignmentExpanded{
					labelName:   a.LabelName.ValueString(),
					packageName: a.PackageName.ValueString(),
					packageType: a.PackageType.ValueString(),
					version:     v,
				})
			}
		} else {
			// versions is required
			return fmt.Errorf("versions list is required for version assignments")
		}
	}

	// Collect all label names to validate their existence
	var allLabelNames []string
	for _, assignment := range expanded {
		labelName := assignment.labelName
		allLabelNames = append(allLabelNames, labelName)
	}

	// Validate all referenced labels exist in either local state or catalog
	if len(allLabelNames) > 0 {
		log.Printf("[DEBUG] Validating existence of %d labels for version assignments", len(allLabelNames))
		missingLabels, err := r.validateLabelsExistenceUnified(ctx, allLabelNames, plan, nil, nil, "version")
		if err != nil {
			log.Printf("[ERROR] Failed to validate label existence for version assignments: %s", err.Error())
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, fmt.Sprintf("Failed to validate label existence: %s", err.Error()))
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, fmt.Sprintf("Failed to validate label existence: %s", err.Error()))
			}
			return err
		}

		if len(missingLabels) > 0 {
			errorMsg := fmt.Sprintf("The following labels do not exist in local state or catalog: %s. Please create these labels first or define them in the labels block.", strings.Join(missingLabels, ", "))
			log.Printf("[ERROR] %s", errorMsg)
			switch h := resp.(type) {
			case *resource.CreateResponse:
				utilfw.UnableToCreateResourceError(h, errorMsg)
			case *resource.UpdateResponse:
				utilfw.UnableToUpdateResourceError(h, errorMsg)
			}
			return fmt.Errorf("referenced labels do not exist: %s", strings.Join(missingLabels, ", "))
		}
		log.Printf("[DEBUG] All %d referenced labels exist in state or catalog for version assignments", len(allLabelNames))
	}

	// Group assignments by label name
	labelToVersions := make(map[string][]versionAssignmentExpanded)
	for _, a := range expanded {
		label := a.labelName
		labelToVersions[label] = append(labelToVersions[label], a)
	}

	// For each label, decide between single-version API or bulk API
	for labelName, vers := range labelToVersions {
		if len(vers) == 1 {
			// single
			query := assignSinglePackageVersionLabelMutation(vers[0].packageName, vers[0].packageType, vers[0].version, labelName)
			log.Printf("[DEBUG] GraphQL assign single version label query: %s", query)

			var graphqlResp AssignSinglePackageVersionLabelResponse
			response, err := r.ProviderData.Client.R().
				SetBody(GraphQLRequest{Query: query}).
				SetResult(&graphqlResp).
				Post(CatalogGraphQLEndpoint)
			if err != nil {
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, err.Error())
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, err.Error())
				}
				return err
			}
			if response.IsError() {
				log.Printf("[ERROR] GraphQL error assigning single version label: %s", response.String())
				errorMsg := r.parseGraphQLError(response.String())
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, errorMsg)
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, errorMsg)
				}
				return fmt.Errorf("GraphQL error: %s", errorMsg)
			}
			log.Printf("[DEBUG] Assigned label '%s' to single package version %s@%s via single API", labelName, vers[0].packageName, vers[0].version)
			continue
		}

		// multiple versions -> bulk per label
		var pv []string
		for _, a := range vers {
			pv = append(pv, fmt.Sprintf(`{publicPackage: {name: "%s", type: "%s"}, version: "%s"}`,
				a.packageName, a.packageType, a.version))
		}
		for i := 0; i < len(pv); i += MaxLabelsPerOperation {
			end := i + MaxLabelsPerOperation
			if end > len(pv) {
				end = len(pv)
			}
			query := assignMultiplePackageVersionsLabelsMutation(strings.Join(pv[i:end], ", "), labelName)
			log.Printf("[DEBUG] GraphQL assign bulk version labels query: %s", query)

			var graphqlResp AssignMultiplePackageVersionsLabelsResponse
			response, err := r.ProviderData.Client.R().
				SetBody(GraphQLRequest{Query: query}).
				SetResult(&graphqlResp).
				Post(CatalogGraphQLEndpoint)
			if err != nil {
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, err.Error())
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, err.Error())
				}
				return err
			}
			if response.IsError() {
				log.Printf("[ERROR] GraphQL error assigning bulk version labels: %s", response.String())
				errorMsg := r.parseGraphQLError(response.String())
				switch h := resp.(type) {
				case *resource.CreateResponse:
					utilfw.UnableToCreateResourceError(h, errorMsg)
				case *resource.UpdateResponse:
					utilfw.UnableToUpdateResourceError(h, errorMsg)
				}
				return fmt.Errorf("GraphQL error: %s", errorMsg)
			}
			log.Printf("[DEBUG] Successfully assigned label '%s' to %d package versions", labelName, end-i)
		}
	}

	return nil
}

func (r *CatalogLabelsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	log.Printf("[DEBUG] ========== CATALOG LABELS UPDATE OPERATION STARTED ==========")

	var plan, state CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 1) Labels: create new, update changed descriptions, delete removed
	// Extract lists
	var planLabels, stateLabels []LabelModel
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &planLabels, false)...)
	}
	if !state.Labels.IsNull() {
		resp.Diagnostics.Append(state.Labels.ElementsAs(ctx, &stateLabels, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Index by name
	planByName := map[string]LabelModel{}
	for _, l := range planLabels {
		planByName[l.Name.ValueString()] = l
	}
	stateByName := map[string]LabelModel{}
	for _, l := range stateLabels {
		stateByName[l.Name.ValueString()] = l
	}

	// Create or update
	for name, pl := range planByName {
		if sl, ok := stateByName[name]; ok {
			if pl.Description.ValueString() != sl.Description.ValueString() {
				// update
				query := updateLabelMutation(sl.Name.ValueString(), pl.Name.ValueString(), pl.Description.ValueString())
				var graphqlResp UpdateLabelResponse
				response, err := r.ProviderData.Client.R().
					SetBody(GraphQLRequest{Query: query}).
					SetResult(&graphqlResp).
					Post(CatalogGraphQLEndpoint)
				if err != nil {
					utilfw.UnableToUpdateResourceError(resp, err.Error())
					return
				}
				if response.IsError() {
					errorMsg := r.parseGraphQLError(response.String())
					utilfw.UnableToUpdateResourceError(resp, errorMsg)
					return
				}
			}
		} else {
			// create
			query := createSingleLabelMutation(pl.Name.ValueString(), pl.Description.ValueString())
			var graphqlResp CreateLabelResponse
			response, err := r.ProviderData.Client.R().
				SetBody(GraphQLRequest{Query: query}).
				SetResult(&graphqlResp).
				Post(CatalogGraphQLEndpoint)
			if err != nil {
				utilfw.UnableToUpdateResourceError(resp, err.Error())
				return
			}
			if response.IsError() {
				errorMsg := r.parseGraphQLError(response.String())
				utilfw.UnableToUpdateResourceError(resp, errorMsg)
				return
			}
		}
	}

	// Delete labels removed from plan
	for name, sl := range stateByName {
		if _, ok := planByName[name]; !ok {
			if err := r.deleteSingleLabel(ctx, sl); err != nil {
				utilfw.UnableToUpdateResourceError(resp, err.Error())
				return
			}
		}
	}

	// 2) Package assignments: remove those in state not in plan; assign those new/changed in plan
	// Extract assignments
	var planPkgs, statePkgs []PackageAssignmentModel
	if !plan.PackageAssignments.IsNull() && !plan.PackageAssignments.IsUnknown() {
		resp.Diagnostics.Append(plan.PackageAssignments.ElementsAs(ctx, &planPkgs, false)...)
	}
	if !state.PackageAssignments.IsNull() {
		resp.Diagnostics.Append(state.PackageAssignments.ElementsAs(ctx, &statePkgs, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Key by package (name:type)
	type pkgKey struct{ name, ptype string }
	planPkgMap := map[pkgKey]PackageAssignmentModel{}
	for _, a := range planPkgs {
		planPkgMap[pkgKey{a.PackageName.ValueString(), a.PackageType.ValueString()}] = a
	}
	statePkgMap := map[pkgKey]PackageAssignmentModel{}
	for _, a := range statePkgs {
		statePkgMap[pkgKey{a.PackageName.ValueString(), a.PackageType.ValueString()}] = a
	}

	// Remove assignments not in plan using helper
	if len(statePkgs) > 0 {
		var toRemove []PackageAssignmentModel
		for k, a := range statePkgMap {
			if _, ok := planPkgMap[k]; !ok {
				toRemove = append(toRemove, a)
			}
		}
		if len(toRemove) > 0 {
			// build a temporary model to reuse helper
			tmp := CatalogLabelsResourceModel{}
			set, _ := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{"label_name": types.StringType, "package_name": types.StringType, "package_type": types.StringType}}, toRemove)
			tmp.PackageAssignments = set
			if err := r.removePackageLabels(ctx, &tmp); err != nil {
				utilfw.UnableToUpdateResourceError(resp, err.Error())
				return
			}
		}
	}

	// Add or change assignments in plan via helper
	if len(planPkgs) > 0 {
		var toAdd []PackageAssignmentModel
		for k, a := range planPkgMap {
			if sa, ok := statePkgMap[k]; !ok || sa.LabelName.ValueString() != a.LabelName.ValueString() {
				toAdd = append(toAdd, a)
			}
		}
		if len(toAdd) > 0 {
			tmp := CatalogLabelsResourceModel{}
			set, _ := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{"label_name": types.StringType, "package_name": types.StringType, "package_type": types.StringType}}, toAdd)
			tmp.PackageAssignments = set
			if err := r.assignPackageLabels(ctx, &tmp, resp); err != nil {
				return
			}
		}
	}

	// 3) Version assignments: compute diff per (name:type:version) and remove/add
	var planVers, stateVers []VersionAssignmentModel
	if !plan.VersionAssignments.IsNull() && !plan.VersionAssignments.IsUnknown() {
		resp.Diagnostics.Append(plan.VersionAssignments.ElementsAs(ctx, &planVers, false)...)
	}
	if !state.VersionAssignments.IsNull() {
		resp.Diagnostics.Append(state.VersionAssignments.ElementsAs(ctx, &stateVers, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Expand to per-version mapping
	planVerMap := map[string]string{} // key -> label
	for _, a := range planVers {
		var vs []string
		if !a.Versions.IsNull() && !a.Versions.IsUnknown() && len(a.Versions.Elements()) > 0 {
			if diags := a.Versions.ElementsAs(ctx, &vs, false); !diags.HasError() {
				for _, v := range vs {
					key := fmt.Sprintf("%s:%s:%s", a.PackageName.ValueString(), a.PackageType.ValueString(), v)
					planVerMap[key] = a.LabelName.ValueString()
				}
			}
		}
	}
	stateVerMap := map[string]string{}
	for _, a := range stateVers {
		var vs []string
		if !a.Versions.IsNull() && !a.Versions.IsUnknown() && len(a.Versions.Elements()) > 0 {
			if diags := a.Versions.ElementsAs(ctx, &vs, false); !diags.HasError() {
				for _, v := range vs {
					key := fmt.Sprintf("%s:%s:%s", a.PackageName.ValueString(), a.PackageType.ValueString(), v)
					stateVerMap[key] = a.LabelName.ValueString()
				}
			}
		}
	}

	// Remove those not in plan via helper
	if len(stateVerMap) > 0 {
		// We need original models to feed helper; rebuild a list of VersionAssignmentModel with single version entries
		var toRemove []VersionAssignmentModel
		for key, stateLabel := range stateVerMap {
			if _, ok := planVerMap[key]; !ok {
				parts := strings.SplitN(key, ":", 3)
				pkgName, pkgType, version := parts[0], parts[1], parts[2]
				vm := VersionAssignmentModel{
					LabelName:   types.StringValue(stateLabel),
					PackageName: types.StringValue(pkgName),
					PackageType: types.StringValue(pkgType),
				}
				versSet, _ := types.SetValueFrom(ctx, types.StringType, []string{version})
				vm.Versions = versSet
				toRemove = append(toRemove, vm)
			}
		}
		if len(toRemove) > 0 {
			tmp := CatalogLabelsResourceModel{}
			set, _ := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{"label_name": types.StringType, "package_name": types.StringType, "package_type": types.StringType, "versions": types.SetType{ElemType: types.StringType}}}, toRemove)
			tmp.VersionAssignments = set
			if err := r.removePackageVersionLabels(ctx, &tmp); err != nil {
				utilfw.UnableToUpdateResourceError(resp, err.Error())
				return
			}
		}
	}

	// Add or change via helper
	if len(planVerMap) > 0 {
		var toAdd []VersionAssignmentModel
		for key, planLabel := range planVerMap {
			stateLabel, ok := stateVerMap[key]
			parts := strings.SplitN(key, ":", 3)
			pkgName, pkgType, version := parts[0], parts[1], parts[2]
			if !ok || stateLabel != planLabel {
				vm := VersionAssignmentModel{
					LabelName:   types.StringValue(planLabel),
					PackageName: types.StringValue(pkgName),
					PackageType: types.StringValue(pkgType),
				}
				versSet, _ := types.SetValueFrom(ctx, types.StringType, []string{version})
				vm.Versions = versSet
				toAdd = append(toAdd, vm)
			}
		}
		if len(toAdd) > 0 {
			tmp := CatalogLabelsResourceModel{}
			set, _ := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: map[string]attr.Type{"label_name": types.StringType, "package_name": types.StringType, "package_type": types.StringType, "versions": types.SetType{ElemType: types.StringType}}}, toAdd)
			tmp.VersionAssignments = set
			if err := r.assignPackageVersionLabels(ctx, &tmp, resp); err != nil {
				return
			}
		}
	}

	// Persist plan to state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	log.Printf("[DEBUG] ========== CATALOG LABELS UPDATE OPERATION COMPLETED ==========")
}

func (r *CatalogLabelsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Keep current state as-is (non-destructive Read to avoid flapping due to eventual consistency)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CatalogLabelsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	log.Printf("[DEBUG] ========== CATALOG LABELS DELETE OPERATION STARTED ==========")

	var state CatalogLabelsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		log.Printf("[ERROR] Failed to read state during delete operation")
		return
	}

	err := r.deleteAll(ctx, &state)
	if err != nil {
		resp.Diagnostics.AddError("Deletion failed", err.Error())
		return
	}

	log.Printf("[DEBUG] ========== CATALOG LABELS DELETE OPERATION COMPLETED ==========")
}

func (r *CatalogLabelsResource) deleteAll(ctx context.Context, state *CatalogLabelsResourceModel) error {
	// Delete in reverse order: assignments first, then labels

	// Remove version assignments
	if !state.VersionAssignments.IsNull() && !state.VersionAssignments.IsUnknown() && len(state.VersionAssignments.Elements()) > 0 {
		err := r.removePackageVersionLabels(ctx, state)
		if err != nil {
			log.Printf("[WARNING] Failed to remove version assignments: %s", err.Error())
		}
	}

	// Remove package assignments
	if !state.PackageAssignments.IsNull() && !state.PackageAssignments.IsUnknown() && len(state.PackageAssignments.Elements()) > 0 {
		err := r.removePackageLabels(ctx, state)
		if err != nil {
			log.Printf("[WARNING] Failed to remove package assignments: %s", err.Error())
		}
	}

	// Delete labels
	if !state.Labels.IsNull() && !state.Labels.IsUnknown() && len(state.Labels.Elements()) > 0 {
		return r.deleteLabels(ctx, state)
	}

	return nil
}

func (r *CatalogLabelsResource) removePackageVersionLabels(ctx context.Context, state *CatalogLabelsResourceModel) error {
	var assignments []VersionAssignmentModel
	diags := state.VersionAssignments.ElementsAs(ctx, &assignments, false)
	if diags.HasError() {
		return fmt.Errorf("failed to extract version assignments")
	}

	// Count total label assignments being removed
	totalAssignments := 0
	for range assignments {
		totalAssignments += 1
	}

	// Validate total assignments don't exceed API limits
	if totalAssignments > MaxLabelsPerOperation {
		return fmt.Errorf("removing more than %d labels assignments in a single operation is not supported. Cannot remove more than %d label assignments from package versions. Got %d assignments", MaxLabelsPerOperation, MaxLabelsPerOperation, totalAssignments)
	}

	// Collect all label names to validate their existence before removal
	var allLabelNames []string
	for _, assignment := range assignments {
		labelName := assignment.LabelName.ValueString()
		allLabelNames = append(allLabelNames, labelName)
	}

	// Validate all labels exist before attempting removal
	if len(allLabelNames) > 0 {
		log.Printf("[DEBUG] Validating existence of %d labels before version removal", len(allLabelNames))
		missingLabels, err := r.validateLabelsExistenceUnified(ctx, allLabelNames, state, nil, nil, "version")
		if err != nil {
			log.Printf("[WARNING] Failed to validate label existence before removal: %s", err.Error())
			// Don't fail removal if validation fails - labels might have been removed externally
		} else if len(missingLabels) > 0 {
			log.Printf("[WARNING] Some labels to be removed do not exist: %s", strings.Join(missingLabels, ", "))
			// Continue with removal - this is expected during cleanup
		} else {
			log.Printf("[DEBUG] All %d labels exist and can be removed from package versions", len(allLabelNames))
		}
	}

	for _, assignment := range assignments {
		// Extract versions and label
		var versions []string
		if diags := assignment.Versions.ElementsAs(ctx, &versions, false); diags.HasError() {
			return fmt.Errorf("failed to extract versions for removal")
		}
		labelName := assignment.LabelName.ValueString()
		if labelName == "" || len(versions) == 0 {
			continue
		}

		if len(versions) == 1 {
			// single version
			query := removeSinglePackageVersionLabelMutation(assignment.PackageName.ValueString(), assignment.PackageType.ValueString(), versions[0], fmt.Sprintf(`"%s"`, labelName))
			log.Printf("[DEBUG] GraphQL single remove version label query: %s", query)

			var graphqlResp RemoveSinglePackageVersionLabelResponse
			response, err := r.ProviderData.Client.R().
				SetBody(GraphQLRequest{Query: query}).
				SetResult(&graphqlResp).
				Post(CatalogGraphQLEndpoint)

			if err != nil {
				return fmt.Errorf("failed to remove version label: %w", err)
			}
			if response.IsError() {
				log.Printf("[WARNING] GraphQL error removing version label: %s", response.String())
			}
			continue
		}

		// multiple versions
		labelNamesJson := fmt.Sprintf(`"%s"`, labelName)
		var pv []string
		for _, v := range versions {
			pv = append(pv, fmt.Sprintf(`{publicPackage: {name: "%s", type: "%s"}, version: "%s"}`,
				assignment.PackageName.ValueString(), assignment.PackageType.ValueString(), v))
		}
		query := removeMultiplePackageVersionsLabelsMutation(strings.Join(pv, ", "), labelNamesJson)
		log.Printf("[DEBUG] GraphQL remove bulk version labels query: %s", query)

		var graphqlResp RemoveMultiplePackageVersionsLabelsResponse
		response, err := r.ProviderData.Client.R().
			SetBody(GraphQLRequest{Query: query}).
			SetResult(&graphqlResp).
			Post(CatalogGraphQLEndpoint)

		if err != nil {
			return fmt.Errorf("failed to remove version labels in bulk: %w", err)
		}
		if response.IsError() {
			log.Printf("[WARNING] GraphQL error removing bulk version labels: %s", response.String())
		}
	}

	return nil
}

func (r *CatalogLabelsResource) removePackageLabels(ctx context.Context, state *CatalogLabelsResourceModel) error {
	var assignments []PackageAssignmentModel
	diags := state.PackageAssignments.ElementsAs(ctx, &assignments, false)
	if diags.HasError() {
		return fmt.Errorf("failed to extract package assignments")
	}

	// Count total label assignments being removed
	totalAssignments := 0
	for range assignments {
		totalAssignments += 1
	}

	// Validate total assignments don't exceed API limits
	if totalAssignments > MaxLabelsPerOperation {
		return fmt.Errorf("removing more than %d labels assignments in a single operation is not supported. Cannot remove more than %d label assignments. Got %d assignments", MaxLabelsPerOperation, MaxLabelsPerOperation, totalAssignments)
	}

	// Collect all label names to validate their existence before removal
	var allLabelNames []string
	for _, assignment := range assignments {
		labelName := assignment.LabelName.ValueString()
		allLabelNames = append(allLabelNames, labelName)
	}

	// Validate all labels exist before attempting removal
	if len(allLabelNames) > 0 {
		log.Printf("[DEBUG] Validating existence of %d labels before package removal", len(allLabelNames))
		missingLabels, err := r.validateLabelsExistenceUnified(ctx, allLabelNames, state, nil, nil, "package")
		if err != nil {
			log.Printf("[WARNING] Failed to validate label existence before removal: %s", err.Error())
			// Don't fail removal if validation fails - labels might have been removed externally
		} else if len(missingLabels) > 0 {
			log.Printf("[WARNING] Some labels to be removed do not exist: %s", strings.Join(missingLabels, ", "))
			// Continue with removal - this is expected during cleanup
		} else {
			log.Printf("[DEBUG] All %d labels exist and can be removed from packages", len(allLabelNames))
		}
	}

	for _, assignment := range assignments {
		labelNames := []string{assignment.LabelName.ValueString()}

		labelNamesJson := make([]string, len(labelNames))
		for i, name := range labelNames {
			labelNamesJson[i] = fmt.Sprintf(`"%s"`, name)
		}

		query := removePackageLabelMutation(strings.Join(labelNamesJson, ", "), assignment.PackageName.ValueString(), assignment.PackageType.ValueString())

		log.Printf("[DEBUG] GraphQL remove package labels query: %s", query)

		response, err := r.ProviderData.Client.R().
			SetBody(GraphQLRequest{Query: query}).
			Post(CatalogGraphQLEndpoint)

		if err != nil {
			return fmt.Errorf("failed to remove package labels: %w", err)
		}

		if response.IsError() {
			log.Printf("[WARNING] GraphQL error removing package labels: %s", response.String())
		}
	}

	return nil
}

func (r *CatalogLabelsResource) deleteLabels(ctx context.Context, state *CatalogLabelsResourceModel) error {
	var labels []LabelModel
	diags := state.Labels.ElementsAs(ctx, &labels, false)
	if diags.HasError() {
		return fmt.Errorf("failed to extract labels")
	}

	if len(labels) == 0 {
		return nil
	}

	// Validate label count doesn't exceed API limits for deletion
	if len(labels) > MaxLabelsPerOperation {
		return fmt.Errorf("deleting more than %d labels is not supported. Cannot delete more than %d labels in a single operation. Got %d labels", MaxLabelsPerOperation, MaxLabelsPerOperation, len(labels))
	}

	log.Printf("[DEBUG] Deleting %d catalog labels", len(labels))

	if len(labels) == 1 {
		return r.deleteSingleLabel(ctx, labels[0])
	} else {
		return r.deleteMultipleLabels(ctx, labels)
	}
}

func (r *CatalogLabelsResource) deleteSingleLabel(ctx context.Context, label LabelModel) error {
	query := deleteSingleLabelMutation(label.Name.ValueString())
	log.Printf("[DEBUG] GraphQL delete single label query: %s", query)

	var graphqlResp DeleteSingleLabelResponse
	response, err := r.ProviderData.Client.R().
		SetBody(GraphQLRequest{Query: query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)

	if err != nil {
		return fmt.Errorf("failed to delete label '%s': %w", label.Name.ValueString(), err)
	}

	log.Printf("[DEBUG] Delete label response: %s", response.String())

	if response.IsError() {
		if response.StatusCode() == 404 {
			log.Printf("[DEBUG] Label '%s' doesn't exist (404), considering it deleted", label.Name.ValueString())
			return nil
		}
		return fmt.Errorf("GraphQL error deleting label '%s': %s", label.Name.ValueString(), response.String())
	}

	log.Printf("[DEBUG] Successfully deleted label: %s", label.Name.ValueString())
	return nil
}

func (r *CatalogLabelsResource) deleteMultipleLabels(ctx context.Context, labels []LabelModel) error {
	var labelsJson []string
	for _, label := range labels {
		labelsJson = append(labelsJson, fmt.Sprintf(`{name:"%s"}`, label.Name.ValueString()))
	}

	query := deleteMultipleLabelsMutation(strings.Join(labelsJson, ", "))
	log.Printf("[DEBUG] GraphQL delete multiple labels query: %s", query)

	var graphqlResp DeleteMultipleLabelsResponse
	response, err := r.ProviderData.Client.R().
		SetBody(GraphQLRequest{Query: query}).
		SetResult(&graphqlResp).
		Post(CatalogGraphQLEndpoint)

	if err != nil {
		return fmt.Errorf("failed to delete labels: %w", err)
	}

	log.Printf("[DEBUG] Delete labels response: %s", response.String())
	log.Printf("[DEBUG] Parsed response value: %v", graphqlResp.Data.CustomCatalogLabel.DeleteCustomCatalogLabels)

	if response.IsError() {
		return fmt.Errorf("GraphQL error deleting labels: %s", response.String())
	}

	if !graphqlResp.Data.CustomCatalogLabel.DeleteCustomCatalogLabels {
		log.Printf("[WARNING] Delete labels returned false - some labels may not have been deleted")
		// Try individual deletion as fallback
		for _, label := range labels {
			err := r.deleteSingleLabel(ctx, label)
			if err != nil {
				log.Printf("[ERROR] Failed to delete label individually: %s", err.Error())
			}
		}
	} else {
		log.Printf("[DEBUG] Bulk deletion successful - all %d labels deleted", len(labels))
	}

	log.Printf("[DEBUG] Successfully deleted %d catalog labels", len(labels))
	return nil
}

func (r *CatalogLabelsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// For import, we expect a comma-separated list of label names
	labelNames := strings.Split(req.ID, ",")

	var labels []LabelModel
	for _, name := range labelNames {
		labels = append(labels, LabelModel{
			Name:        types.StringValue(strings.TrimSpace(name)),
			Description: types.StringValue(""), // Description will be populated during Read
		})
	}

	labelsSet, diags := types.SetValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"name":        types.StringType,
			"description": types.StringType,
		},
	}, labels)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Ensure typed null sets for assignments to satisfy framework type checks
	pkgAssignType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"label_name":   types.StringType,
		"package_name": types.StringType,
		"package_type": types.StringType,
	}}
	verAssignType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"label_name":   types.StringType,
		"package_name": types.StringType,
		"package_type": types.StringType,
		"versions":     types.SetType{ElemType: types.StringType},
	}}

	state := CatalogLabelsResourceModel{
		Labels:             labelsSet,
		PackageAssignments: types.SetNull(pkgAssignType),
		VersionAssignments: types.SetNull(verAssignType),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
