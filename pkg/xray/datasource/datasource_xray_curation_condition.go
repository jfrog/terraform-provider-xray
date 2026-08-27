package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

const (
	CurationConditionsEndpoint = "xray/api/v1/curation/conditions"

	// CurationConditionsPageSize is sent as `num_of_rows` to raise the API default
	// of 15, so the common case of a few dozen conditions is read in one request.
	CurationConditionsPageSize = 100

	// CurationConditionsMaxPages bounds the pagination walk. A deployment which
	// ignores `page_num` returns a full page forever, so the walk has to stop even
	// when the API reports more rows than it serves.
	CurationConditionsMaxPages = 100
)

// curationConditionIDPattern matches the numeric condition IDs accepted by
// `xray_curation_policy.condition_id`.
var curationConditionIDPattern = regexp.MustCompile(`^\d+$`)

var _ datasource.DataSource = &CurationConditionDataSource{}
var _ datasource.DataSourceWithConfigure = &CurationConditionDataSource{}

func NewCurationConditionDataSource() datasource.DataSource {
	return &CurationConditionDataSource{}
}

type CurationConditionDataSource struct {
	ProviderData util.ProviderMetadata
}

type CurationConditionDataSourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	ConditionTemplateID types.String `tfsdk:"condition_template_id"`
	IsCustom            types.Bool   `tfsdk:"is_custom"`
	RiskType            types.String `tfsdk:"risk_type"`
	SupportedPkgTypes   types.Set    `tfsdk:"supported_pkg_types"`
	ParamValues         types.String `tfsdk:"param_values"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedBy           types.String `tfsdk:"updated_by"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
}

// CurationConditionAPIModel is a single condition returned by the list Curation
// conditions API. `id` is kept raw because the API is documented to return a
// string but is normalized so a numeric value is also accepted.
type CurationConditionAPIModel struct {
	ID                  json.RawMessage `json:"id"`
	Name                string          `json:"name"`
	ConditionTemplateID string          `json:"condition_template_id"`
	IsCustom            bool            `json:"is_custom"`
	RiskType            string          `json:"risk_type"`
	SupportedPkgTypes   []string        `json:"supported_pkg_types"`
	ParamValues         json.RawMessage `json:"param_values"`
	CreatedBy           string          `json:"created_by"`
	CreatedAt           string          `json:"created_at"`
	UpdatedBy           string          `json:"updated_by"`
	UpdatedAt           string          `json:"updated_at"`
}

// CurationConditionsMetaAPIModel is the pagination envelope of the list Curation
// conditions API. It is absent from responses which are not paginated, which
// Present distinguishes from an envelope reporting zero counts.
type CurationConditionsMetaAPIModel struct {
	TotalCount  int64  `json:"total_count"`
	ResultCount int64  `json:"result_count"`
	NumOfRows   int64  `json:"num_of_rows"`
	PageNum     *int64 `json:"page_num"`

	// Present reports whether the response carried a `meta` object. It is set by
	// ParseCurationConditions rather than decoded, so a response without
	// pagination metadata can be treated as a complete listing.
	Present bool `json:"-"`
}

// ParseCurationConditions parses one page of the list Curation conditions API.
// Xray returns a paginated object keyed by `data`, while other deployments have
// been observed returning an object keyed by `conditions` or a bare array, so
// all three shapes are supported. A successful response in any other shape is an
// error rather than an empty list, otherwise a lookup failure would be
// indistinguishable from a missing condition.
func ParseCurationConditions(body []byte) ([]CurationConditionAPIModel, CurationConditionsMetaAPIModel, error) {
	var meta CurationConditionsMetaAPIModel

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, meta, fmt.Errorf("response body is empty")
	}

	if strings.HasPrefix(trimmed, "[") {
		var conditions []CurationConditionAPIModel
		if err := json.Unmarshal(body, &conditions); err != nil {
			return nil, meta, fmt.Errorf("unable to parse condition array: %w", err)
		}
		return conditions, meta, nil
	}

	if !strings.HasPrefix(trimmed, "{") {
		return nil, meta, fmt.Errorf("expected a JSON object or array, got: %s", truncateBody(trimmed))
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, meta, fmt.Errorf("unable to parse response object: %w", err)
	}

	if rawMeta, ok := envelope["meta"]; ok {
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			return nil, meta, fmt.Errorf("unable to parse `meta`: %w", err)
		}
		meta.Present = true
	}

	rawConditions, ok := envelope["data"]
	if !ok {
		rawConditions, ok = envelope["conditions"]
	}
	if !ok {
		return nil, meta, fmt.Errorf("response object contains neither a `data` nor a `conditions` field: %s", truncateBody(trimmed))
	}

	if strings.TrimSpace(string(rawConditions)) == "null" {
		return nil, meta, nil
	}

	var conditions []CurationConditionAPIModel
	if err := json.Unmarshal(rawConditions, &conditions); err != nil {
		return nil, meta, fmt.Errorf("unable to parse condition array: %w", err)
	}

	return conditions, meta, nil
}

// CurationConditionsWalk reports how much of the Curation conditions listing was
// read. Complete is false when the walk ended before the API had returned every
// row it reported, so a caller must not treat an absent condition as proof that
// the condition does not exist.
type CurationConditionsWalk struct {
	Scanned    int64
	TotalCount int64
	Complete   bool
}

// WalkCurationConditions reads every page of the list Curation conditions API,
// passing each condition to visit. Pages are requested with the documented
// 1-based `page_num` and `num_of_rows` parameters, and query is merged in to
// allow additional server-side filters.
//
// The walk stops on the first page which is not full, once the reported
// `total_count` of distinct rows has been read, or at CurationConditionsMaxPages.
// A response without pagination metadata is a complete listing on its own.
// Inconsistent pagination — including a server which ignores `page_num` and
// repeats the first page — ends the walk instead of looping, and is reported
// through Complete rather than being mistaken for the end of the listing.
func WalkCurationConditions(ctx context.Context, client *resty.Client, query map[string]string, visit func(CurationConditionAPIModel)) (CurationConditionsWalk, error) {
	walk := CurationConditionsWalk{Complete: true}
	seen := map[string]struct{}{}

	for page := 1; page <= CurationConditionsMaxPages; page++ {
		params := map[string]string{
			"page_num":    strconv.Itoa(page),
			"num_of_rows": strconv.Itoa(CurationConditionsPageSize),
		}
		for key, value := range query {
			params[key] = value
		}

		response, err := client.R().
			SetContext(ctx).
			SetQueryParams(params).
			Get(CurationConditionsEndpoint)
		if err != nil {
			return walk, fmt.Errorf("request for page %d failed: %w", page, err)
		}
		if response.IsError() {
			return walk, fmt.Errorf("request for page %d returned status %d, body: %s",
				page, response.StatusCode(), truncateBody(response.String()))
		}

		conditions, meta, err := ParseCurationConditions(response.Body())
		if err != nil {
			return walk, fmt.Errorf("page %d could not be parsed: %w", page, err)
		}

		walk.TotalCount = meta.TotalCount

		// Without pagination metadata there is nothing to page through.
		if !meta.Present {
			for _, condition := range conditions {
				visit(condition)
			}
			walk.Scanned = int64(len(conditions))
			return walk, nil
		}

		// An echoed page_num which does not match the page that was requested means
		// the server is not advancing. Stop before treating those rows as new.
		if page > 1 && meta.PageNum != nil && *meta.PageNum != int64(page) {
			walk.Complete = false
			return walk, nil
		}

		newOnPage := 0
		for _, condition := range conditions {
			key := curationConditionIdentity(condition.ID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			newOnPage++
			walk.Scanned++
			visit(condition)
		}

		// Every reported row has been read.
		if meta.TotalCount > 0 && walk.Scanned >= meta.TotalCount {
			return walk, nil
		}

		// An empty page yields no progress, so continuing would loop forever.
		if len(conditions) == 0 {
			walk.Complete = meta.TotalCount <= 0
			return walk, nil
		}

		// A later page with no new condition IDs is the first page served again.
		if page > 1 && newOnPage == 0 {
			walk.Complete = false
			return walk, nil
		}

		// A page the API did not fill is the last one. `num_of_rows` is echoed
		// back, so a deployment which caps the page size is respected.
		pageSize := int64(CurationConditionsPageSize)
		if meta.NumOfRows > 0 {
			pageSize = meta.NumOfRows
		}
		if int64(len(conditions)) < pageSize {
			walk.Complete = meta.TotalCount <= 0
			return walk, nil
		}
	}

	walk.Complete = false
	return walk, nil
}

// curationConditionIdentity is a stable key for a condition ID so a repeated
// page can be distinguished from two legitimate conditions which share a name
// but have different IDs.
func curationConditionIdentity(raw json.RawMessage) string {
	id, err := NormalizeCurationConditionID(raw)
	if err == nil {
		return id
	}
	return strings.TrimSpace(string(raw))
}

// FindCurationConditionsByName returns every Curation condition whose name is
// exactly name. The `name` query parameter is passed to the API, but matching is
// repeated locally across all pages because a deployment may ignore the filter or
// treat it as a partial match.
func FindCurationConditionsByName(ctx context.Context, client *resty.Client, name string) ([]CurationConditionAPIModel, CurationConditionsWalk, error) {
	var matches []CurationConditionAPIModel

	walk, err := WalkCurationConditions(ctx, client, map[string]string{"name": name}, func(condition CurationConditionAPIModel) {
		if condition.Name == name {
			matches = append(matches, condition)
		}
	})
	if err != nil {
		return nil, walk, err
	}

	return matches, walk, nil
}

// DecideCurationConditionLookup reports whether an exact-name lookup can be
// resolved. A unique match is only proven when the listing is complete; an
// unread later page may hold another condition with the same name. Returns an
// empty summary on success.
func DecideCurationConditionLookup(name string, matchCount int, walk CurationConditionsWalk) (summary, detail string) {
	if !walk.Complete && matchCount <= 1 {
		listed := fmt.Sprintf("only %d conditions were listed", walk.Scanned)
		if walk.TotalCount > 0 {
			listed = fmt.Sprintf("only %d of %d conditions were listed", walk.Scanned, walk.TotalCount)
		}
		return "Incomplete Curation conditions listing",
			fmt.Sprintf("The lookup of %q cannot be resolved because %s. "+
				"A later page may contain a condition with that name, or another condition with the same name, so uniqueness is not proven. Retry the operation.",
				name, listed)
	}

	switch {
	case matchCount == 0:
		return "Curation condition not found",
			fmt.Sprintf("No Curation condition with name %q was found. Verify the name matches exactly (case-sensitive) as shown in the Curation UI.", name)
	case matchCount > 1:
		return "Multiple Curation conditions found",
			fmt.Sprintf("Found %d Curation conditions with name %q; expected exactly one.", matchCount, name)
	}

	return "", ""
}

// CurationConditionParamValues converts the raw `param_values` of a condition to
// its state value. An absent or null field becomes null rather than an empty
// string, so "the API did not return parameter values" stays distinguishable from
// a condition which genuinely has none.
func CurationConditionParamValues(raw json.RawMessage) types.String {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return types.StringNull()
	}

	return types.StringValue(trimmed)
}

// NormalizeCurationConditionID converts the `id` of a condition to the numeric
// string expected by `xray_curation_policy.condition_id`. Only a JSON string or
// a JSON integer is accepted; anything else is an error so a malformed ID is
// reported instead of being written to state.
func NormalizeCurationConditionID(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", fmt.Errorf("condition has no `id` field")
	}

	var id string
	if strings.HasPrefix(trimmed, `"`) {
		if err := json.Unmarshal([]byte(trimmed), &id); err != nil {
			return "", fmt.Errorf("condition `id` %s is not a valid JSON string: %w", trimmed, err)
		}
	} else {
		var number json.Number
		if err := json.Unmarshal([]byte(trimmed), &number); err != nil {
			return "", fmt.Errorf("condition `id` %s is neither a JSON string nor a JSON number", truncateBody(trimmed))
		}
		id = number.String()
	}

	if !curationConditionIDPattern.MatchString(id) {
		return "", fmt.Errorf("condition `id` %q is not a numeric string", id)
	}

	return id, nil
}

func truncateBody(body string) string {
	const maxLen = 256
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "..."
}

func (d *CurationConditionDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_curation_condition"
}

func (d *CurationConditionDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The numeric ID of the Curation condition, as a string. Use this value for `condition_id` in `xray_curation_policy`.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The exact name of the Curation condition to look up (case-sensitive), as shown in the Curation UI.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"condition_template_id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the condition template the condition is based on, e.g. `CVECVSSRange` or `isImmature`.",
			},
			"is_custom": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the condition is user-defined (`true`) or built-in (`false`).",
			},
			"risk_type": schema.StringAttribute{
				Computed:    true,
				Description: "The type of risk the condition detects, e.g. `security`, `legal`, or `operational`.",
			},
			"supported_pkg_types": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "The package types the condition can be applied to.",
			},
			"param_values": schema.StringAttribute{
				Computed:    true,
				Description: "The parameter values of the condition, serialized as a JSON string. Null when the API does not return parameter values for the condition.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The user who created the condition.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp of the creation of the condition.",
			},
			"updated_by": schema.StringAttribute{
				Computed:    true,
				Description: "The user who last updated the condition.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp of the last update of the condition.",
			},
		},
		MarkdownDescription: "Looks up a Curation condition by its exact name and returns its numeric ID and metadata. Use it to reference built-in or custom Curation conditions from `xray_curation_policy` without hard-coding numeric IDs. See JFrog [List Conditions API documentation](https://docs.jfrog.com/security/reference/listconditions) for more details.",
	}
}

func (d *CurationConditionDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	d.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

func (d *CurationConditionDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data CurationConditionDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := data.Name.ValueString()

	matches, walk, err := FindCurationConditionsByName(ctx, d.ProviderData.Client, name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to read data source",
			fmt.Sprintf("An unexpected error occurred while attempting to read the Curation conditions from %s. "+
				"Please retry the operation or report this issue to the provider developers.\n\nError: %s",
				CurationConditionsEndpoint, err.Error()),
		)
		return
	}

	if summary, detail := DecideCurationConditionLookup(name, len(matches), walk); summary != "" {
		resp.Diagnostics.AddError(summary, detail)
		return
	}

	condition := matches[0]

	id, err := NormalizeCurationConditionID(condition.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Curation condition ID",
			fmt.Sprintf("The Curation condition named %q cannot be used because its ID could not be resolved to a numeric string, "+
				"which is required by `condition_id` in `xray_curation_policy`.\n\nError: %s", name, err.Error()),
		)
		return
	}

	supportedPkgTypes, ds := types.SetValueFrom(ctx, types.StringType, condition.SupportedPkgTypes)
	resp.Diagnostics.Append(ds...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.ID = types.StringValue(id)
	data.Name = types.StringValue(condition.Name)
	data.ConditionTemplateID = types.StringValue(condition.ConditionTemplateID)
	data.IsCustom = types.BoolValue(condition.IsCustom)
	data.RiskType = types.StringValue(condition.RiskType)
	data.SupportedPkgTypes = supportedPkgTypes
	data.ParamValues = CurationConditionParamValues(condition.ParamValues)
	data.CreatedBy = types.StringValue(condition.CreatedBy)
	data.CreatedAt = types.StringValue(condition.CreatedAt)
	data.UpdatedBy = types.StringValue(condition.UpdatedBy)
	data.UpdatedAt = types.StringValue(condition.UpdatedAt)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
