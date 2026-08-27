package datasource_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
	xray_datasource "github.com/jfrog/terraform-provider-xray/v3/pkg/xray/datasource"
)

func TestParseCurationConditions(t *testing.T) {
	// Response shape returned by Xray 3.150.x for GET xray/api/v1/curation/conditions.
	const paginatedBody = `{
		"data": [
			{
				"id": "1",
				"name": "Malicious package",
				"condition_template_id": "isMalicious",
				"is_custom": false,
				"risk_type": "security",
				"supported_pkg_types": ["npm", "PyPI"],
				"param_values": [],
				"created_by": "system",
				"created_at": "2026-08-07T09:28:03Z",
				"updated_by": "admin",
				"updated_at": "2026-08-07T09:28:03Z"
			},
			{
				"id": "91",
				"name": "cc-immature-pkgs",
				"condition_template_id": "isImmature",
				"is_custom": true,
				"risk_type": "operational",
				"param_values": [{"param_id": "package_age_days", "value": 14}]
			}
		],
		"meta": {"total_count": 21, "result_count": 2, "num_of_rows": 15}
	}`

	tests := []struct {
		name            string
		body            string
		wantNames       []string
		wantTotalCount  int64
		wantResultCount int64
		wantMetaPresent bool
		wantErr         bool
	}{
		{
			name:            "paginated data object",
			body:            paginatedBody,
			wantNames:       []string{"Malicious package", "cc-immature-pkgs"},
			wantTotalCount:  21,
			wantResultCount: 2,
			wantMetaPresent: true,
		},
		{
			// Without a `meta` object there is nothing to page through, so the
			// response is a complete listing on its own.
			name:      "wrapped conditions object",
			body:      `{"conditions": [{"id": "3", "name": "CVE with CVSS score of 9 or above"}]}`,
			wantNames: []string{"CVE with CVSS score of 9 or above"},
		},
		{
			name:      "bare array",
			body:      `[{"id": 3, "name": "first"}, {"id": "4", "name": "second"}]`,
			wantNames: []string{"first", "second"},
		},
		{
			name:      "empty array",
			body:      `[]`,
			wantNames: []string{},
		},
		{
			name:            "null condition array",
			body:            `{"data": null, "meta": {"total_count": 0, "result_count": 0}}`,
			wantNames:       []string{},
			wantMetaPresent: true,
		},
		{
			name:    "empty body",
			body:    "   ",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			body:    `{"data": [{"id": "1"`,
			wantErr: true,
		},
		{
			name:    "object without condition array",
			body:    `{"meta": {"total_count": 0}}`,
			wantErr: true,
		},
		{
			name:    "condition array is not an array",
			body:    `{"data": {"id": "1"}}`,
			wantErr: true,
		},
		{
			name:    "JSON scalar",
			body:    `"not a condition list"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions, meta, err := xray_datasource.ParseCurationConditions([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCurationConditions() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if len(conditions) != len(tt.wantNames) {
				t.Fatalf("got %d conditions, want %d", len(conditions), len(tt.wantNames))
			}
			for i, wantName := range tt.wantNames {
				if conditions[i].Name != wantName {
					t.Errorf("condition %d name = %q, want %q", i, conditions[i].Name, wantName)
				}
			}
			if meta.TotalCount != tt.wantTotalCount {
				t.Errorf("meta.TotalCount = %d, want %d", meta.TotalCount, tt.wantTotalCount)
			}
			if meta.ResultCount != tt.wantResultCount {
				t.Errorf("meta.ResultCount = %d, want %d", meta.ResultCount, tt.wantResultCount)
			}
			if meta.Present != tt.wantMetaPresent {
				t.Errorf("meta.Present = %t, want %t", meta.Present, tt.wantMetaPresent)
			}
		})
	}
}

func TestParseCurationConditionsKeepsAPIFields(t *testing.T) {
	body := `{"data": [{
		"id": "91",
		"name": "cc-immature-pkgs",
		"condition_template_id": "isImmature",
		"is_custom": true,
		"risk_type": "operational",
		"supported_pkg_types": ["npm", "Maven"],
		"param_values": [{"param_id": "package_age_days", "value": 14}],
		"created_by": "admin",
		"created_at": "2026-08-07T09:28:03Z",
		"updated_by": "admin",
		"updated_at": "2026-08-08T10:00:00Z"
	}]}`

	conditions, _, err := xray_datasource.ParseCurationConditions([]byte(body))
	if err != nil {
		t.Fatalf("ParseCurationConditions() unexpected error: %v", err)
	}
	if len(conditions) != 1 {
		t.Fatalf("got %d conditions, want 1", len(conditions))
	}

	c := conditions[0]
	if c.ConditionTemplateID != "isImmature" {
		t.Errorf("ConditionTemplateID = %q, want %q", c.ConditionTemplateID, "isImmature")
	}
	if !c.IsCustom {
		t.Error("IsCustom = false, want true")
	}
	if c.RiskType != "operational" {
		t.Errorf("RiskType = %q, want %q", c.RiskType, "operational")
	}
	if len(c.SupportedPkgTypes) != 2 || c.SupportedPkgTypes[0] != "npm" {
		t.Errorf("SupportedPkgTypes = %v, want [npm Maven]", c.SupportedPkgTypes)
	}
	if c.CreatedBy != "admin" || c.CreatedAt != "2026-08-07T09:28:03Z" {
		t.Errorf("CreatedBy/CreatedAt = %q/%q, want admin/2026-08-07T09:28:03Z", c.CreatedBy, c.CreatedAt)
	}
	if c.UpdatedBy != "admin" || c.UpdatedAt != "2026-08-08T10:00:00Z" {
		t.Errorf("UpdatedBy/UpdatedAt = %q/%q, want admin/2026-08-08T10:00:00Z", c.UpdatedBy, c.UpdatedAt)
	}
	if !json.Valid(c.ParamValues) {
		t.Errorf("ParamValues = %q, want valid JSON", string(c.ParamValues))
	}
}

func TestParseCurationConditionsPageNum(t *testing.T) {
	body := `{"data": [{"id": "1", "name": "a"}], "meta": {"total_count": 21, "result_count": 1, "num_of_rows": 15, "page_num": 3}}`
	_, meta, err := xray_datasource.ParseCurationConditions([]byte(body))
	if err != nil {
		t.Fatalf("ParseCurationConditions() unexpected error: %v", err)
	}
	if meta.PageNum == nil || *meta.PageNum != 3 {
		t.Fatalf("meta.PageNum = %v, want 3", meta.PageNum)
	}

	_, meta, err = xray_datasource.ParseCurationConditions([]byte(`{"data": [], "meta": {"total_count": 0}}`))
	if err != nil {
		t.Fatalf("ParseCurationConditions() unexpected error: %v", err)
	}
	if meta.PageNum != nil {
		t.Errorf("meta.PageNum = %v, want nil when omitted", meta.PageNum)
	}
}

func TestNormalizeCurationConditionID(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "string id", raw: `"146"`, want: "146"},
		{name: "number id", raw: `146`, want: "146"},
		{name: "zero id", raw: `"0"`, want: "0"},
		{name: "padded string id", raw: `  "146"  `, want: "146"},
		{name: "missing id", raw: ``, wantErr: true},
		{name: "null id", raw: `null`, wantErr: true},
		{name: "empty string id", raw: `""`, wantErr: true},
		{name: "non-numeric string id", raw: `"abc"`, wantErr: true},
		{name: "float id", raw: `12.5`, wantErr: true},
		{name: "negative id", raw: `-3`, wantErr: true},
		{name: "boolean id", raw: `true`, wantErr: true},
		{name: "object id", raw: `{"value": 1}`, wantErr: true},
		{name: "array id", raw: `[1]`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xray_datasource.NormalizeCurationConditionID(json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeCurationConditionID(%q) error = %v, wantErr = %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr {
				if got != "" {
					t.Errorf("NormalizeCurationConditionID(%q) = %q, want empty string on error", tt.raw, got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeCurationConditionID(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// curationConditionsPage builds one page of the paginated list Curation
// conditions API response.
func curationConditionsPage(conditions string, totalCount, resultCount, numOfRows int) string {
	return fmt.Sprintf(`{"data": [%s], "meta": {"total_count": %d, "result_count": %d, "num_of_rows": %d}}`,
		conditions, totalCount, resultCount, numOfRows)
}

func curationCondition(id, name string) string {
	return fmt.Sprintf(`{"id": %q, "name": %q, "condition_template_id": "isImmature"}`, id, name)
}

// newCurationConditionsServer serves the list Curation conditions API from
// handler, which is passed the requested 1-based page number. It records the
// `page_num` of every request so a test can assert the pages which were walked.
func newCurationConditionsServer(t *testing.T, handler func(pageNum int) (int, string)) (*resty.Client, *[]int) {
	t.Helper()

	var requestedPages []int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/" + xray_datasource.CurationConditionsEndpoint
		if r.URL.Path != wantPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, wantPath)
		}
		if r.URL.Query().Get("num_of_rows") == "" {
			t.Error("request is missing the `num_of_rows` query parameter")
		}

		rawPageNum := r.URL.Query().Get("page_num")
		pageNum, err := strconv.Atoi(rawPageNum)
		if err != nil {
			t.Errorf("request `page_num` = %q, want an integer", rawPageNum)
		}
		requestedPages = append(requestedPages, pageNum)

		status, body := handler(pageNum)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)

	return resty.New().SetBaseURL(server.URL), &requestedPages
}

// TestFindCurationConditionsByNamePaginates covers the pagination walk: every
// page has to be visited and exact name matches accumulated across all of them
// before the caller can decide between zero, one, and multiple matches.
func TestFindCurationConditionsByNamePaginates(t *testing.T) {
	t.Run("target only on a later page", func(t *testing.T) {
		// The API `name` filter is ignored by this deployment, so the target is
		// buried on the last page behind unrelated conditions.
		pages := map[int]string{
			1: curationConditionsPage(curationCondition("1", "first")+","+curationCondition("2", "second"), 5, 2, 2),
			2: curationConditionsPage(curationCondition("3", "third")+","+curationCondition("4", "fourth"), 5, 2, 2),
			3: curationConditionsPage(curationCondition("146", "target"), 5, 1, 2),
		}

		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, pages[pageNum]
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if got := string(matches[0].ID); got != `"146"` {
			t.Errorf("match ID = %s, want \"146\"", got)
		}
		if !walk.Complete {
			t.Error("walk.Complete = false, want true")
		}
		if walk.Scanned != 5 {
			t.Errorf("walk.Scanned = %d, want 5", walk.Scanned)
		}
		if want := []int{1, 2, 3}; !equalInts(*requestedPages, want) {
			t.Errorf("requested pages = %v, want %v", *requestedPages, want)
		}
	})

	t.Run("duplicate exact name on a later page", func(t *testing.T) {
		pages := map[int]string{
			1: curationConditionsPage(curationCondition("1", "dupe")+","+curationCondition("2", "other"), 4, 2, 2),
			2: curationConditionsPage(curationCondition("3", "dupe")+","+curationCondition("4", "another"), 4, 2, 2),
		}

		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, pages[pageNum]
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "dupe")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		// Both duplicates must be reported, otherwise an ambiguous lookup would
		// silently resolve to whichever page happened to be read first.
		if len(matches) != 2 {
			t.Fatalf("got %d matches, want 2", len(matches))
		}
		if !walk.Complete {
			t.Error("walk.Complete = false, want true")
		}
		if want := []int{1, 2}; !equalInts(*requestedPages, want) {
			t.Errorf("requested pages = %v, want %v", *requestedPages, want)
		}
	})

	t.Run("non-exact API name filter", func(t *testing.T) {
		// A deployment which treats `name` as a partial match returns neighbours
		// of the target; only the exact name may be matched locally.
		page := curationConditionsPage(
			curationCondition("1", "target-suffix")+","+curationCondition("2", "prefix-target"), 3, 2, 2)
		pages := map[int]string{
			1: page,
			2: curationConditionsPage(curationCondition("3", "target"), 3, 1, 2),
		}

		client, _ := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, pages[pageNum]
		})

		matches, _, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if matches[0].Name != "target" {
			t.Errorf("match name = %q, want %q", matches[0].Name, "target")
		}
	})

	t.Run("wrapped conditions object is a complete response", func(t *testing.T) {
		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, `{"conditions": [{"id": "3", "name": "target"}]}`
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if !walk.Complete {
			t.Error("walk.Complete = false, want true")
		}
		// Without pagination metadata the response is complete, so no second
		// page may be requested.
		if want := []int{1}; !equalInts(*requestedPages, want) {
			t.Errorf("requested pages = %v, want %v", *requestedPages, want)
		}
	})

	t.Run("bare array is a complete response", func(t *testing.T) {
		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, `[{"id": 3, "name": "target"}, {"id": "4", "name": "other"}]`
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if !walk.Complete {
			t.Error("walk.Complete = false, want true")
		}
		if want := []int{1}; !equalInts(*requestedPages, want) {
			t.Errorf("requested pages = %v, want %v", *requestedPages, want)
		}
	})

	t.Run("empty later page stops the walk and reports it incomplete", func(t *testing.T) {
		// `total_count` promises far more conditions than the API actually
		// serves. The walk has to stop instead of looping, and must not claim the
		// listing was complete, otherwise a missing condition would be reported
		// as definitively not found.
		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			if pageNum == 1 {
				return http.StatusOK, curationConditionsPage(
					curationCondition("1", "first")+","+curationCondition("2", "second"), 100, 2, 2)
			}
			return http.StatusOK, curationConditionsPage("", 100, 0, 2)
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("got %d matches, want 0", len(matches))
		}
		if walk.Complete {
			t.Error("walk.Complete = true, want false for a truncated listing")
		}
		if len(*requestedPages) != 2 {
			t.Errorf("requested %d pages, want 2", len(*requestedPages))
		}
	})

	t.Run("short later page ends the walk", func(t *testing.T) {
		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			if pageNum == 1 {
				return http.StatusOK, curationConditionsPage(
					curationCondition("1", "first")+","+curationCondition("2", "target"), 3, 2, 2)
			}
			return http.StatusOK, curationConditionsPage(curationCondition("3", "third"), 3, 1, 2)
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("got %d matches, want 1", len(matches))
		}
		if !walk.Complete {
			t.Error("walk.Complete = false, want true")
		}
		if want := []int{1, 2}; !equalInts(*requestedPages, want) {
			t.Errorf("requested pages = %v, want %v", *requestedPages, want)
		}
	})

	t.Run("HTTP error on a later page", func(t *testing.T) {
		client, _ := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			if pageNum == 1 {
				return http.StatusOK, curationConditionsPage(
					curationCondition("1", "first")+","+curationCondition("2", "second"), 10, 2, 2)
			}
			return http.StatusInternalServerError, `{"error": "boom"}`
		})

		_, _, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err == nil {
			t.Fatal("FindCurationConditionsByName() error = nil, want an error for a failed later page")
		}
		// The diagnostic has to name the page which failed.
		if !regexp.MustCompile(`page 2`).MatchString(err.Error()) {
			t.Errorf("error = %q, want it to mention `page 2`", err.Error())
		}
	})

	t.Run("malformed body on a later page", func(t *testing.T) {
		client, _ := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			if pageNum == 1 {
				return http.StatusOK, curationConditionsPage(
					curationCondition("1", "first")+","+curationCondition("2", "second"), 10, 2, 2)
			}
			return http.StatusOK, `{"data": [{"id": "3"`
		})

		_, _, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err == nil {
			t.Fatal("FindCurationConditionsByName() error = nil, want an error for a malformed later page")
		}
		if !regexp.MustCompile(`page 2`).MatchString(err.Error()) {
			t.Errorf("error = %q, want it to mention `page 2`", err.Error())
		}
	})

	t.Run("repeated full page with positive total_count is incomplete", func(t *testing.T) {
		// A server which ignores `page_num` repeats the same full first page while
		// reporting a larger total_count. Counting those rows twice would reach
		// total_count and claim the listing was complete, which would surface as a
		// false not-found or a false duplicate-name match.
		const page = `{"id":"1","name":"first"},{"id":"2","name":"second"}`

		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, curationConditionsPage(page, 4, 2, 2)
		})

		matches, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if len(matches) != 0 {
			t.Fatalf("got %d matches, want 0", len(matches))
		}
		if walk.Complete {
			t.Error("walk.Complete = true, want false when later pages repeat the first page")
		}
		if walk.Scanned != 2 {
			t.Errorf("walk.Scanned = %d, want 2 distinct rows", walk.Scanned)
		}
		if len(*requestedPages) != 2 {
			t.Errorf("requested %d pages, want 2 (stop on the repeated page)", len(*requestedPages))
		}
	})

	t.Run("echoed page_num that does not advance is incomplete", func(t *testing.T) {
		page := func(pageNum int) string {
			return fmt.Sprintf(
				`{"data": [%s,%s], "meta": {"total_count": 4, "result_count": 2, "num_of_rows": 2, "page_num": %d}}`,
				curationCondition("1", "first"), curationCondition("2", "second"), pageNum)
		}

		client, requestedPages := newCurationConditionsServer(t, func(int) (int, string) {
			// The server always echoes page 1, even when page 2 is requested.
			return http.StatusOK, page(1)
		})

		_, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if walk.Complete {
			t.Error("walk.Complete = true, want false when echoed page_num does not advance")
		}
		if walk.Scanned != 2 {
			t.Errorf("walk.Scanned = %d, want 2 distinct rows", walk.Scanned)
		}
		if len(*requestedPages) != 2 {
			t.Errorf("requested %d pages, want 2", len(*requestedPages))
		}
	})

	t.Run("endlessly full pages are bounded", func(t *testing.T) {
		// Distinct new IDs on every page still have to stop at the page cap, even
		// when total_count claims there are more rows.
		client, requestedPages := newCurationConditionsServer(t, func(pageNum int) (int, string) {
			return http.StatusOK, curationConditionsPage(
				curationCondition(strconv.Itoa(pageNum*2-1), "first")+","+curationCondition(strconv.Itoa(pageNum*2), "second"),
				1000000, 2, 2)
		})

		_, walk, err := xray_datasource.FindCurationConditionsByName(context.Background(), client, "target")
		if err != nil {
			t.Fatalf("FindCurationConditionsByName() unexpected error: %v", err)
		}
		if walk.Complete {
			t.Error("walk.Complete = true, want false once the page limit is reached")
		}
		if len(*requestedPages) != xray_datasource.CurationConditionsMaxPages {
			t.Errorf("requested %d pages, want the %d page limit",
				len(*requestedPages), xray_datasource.CurationConditionsMaxPages)
		}
	})
}

func TestCurationConditionParamValues(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNull bool
		want     string
	}{
		{name: "absent", raw: ``, wantNull: true},
		{name: "JSON null", raw: `null`, wantNull: true},
		{name: "blank", raw: `   `, wantNull: true},
		{name: "empty array", raw: `[]`, want: `[]`},
		{name: "populated array", raw: `[{"param_id":"package_age_days","value":14}]`, want: `[{"param_id":"package_age_days","value":14}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := xray_datasource.CurationConditionParamValues(json.RawMessage(tt.raw))
			if got.IsNull() != tt.wantNull {
				t.Fatalf("CurationConditionParamValues(%q).IsNull() = %t, want %t", tt.raw, got.IsNull(), tt.wantNull)
			}
			if tt.wantNull {
				return
			}
			if got.ValueString() != tt.want {
				t.Errorf("CurationConditionParamValues(%q) = %q, want %q", tt.raw, got.ValueString(), tt.want)
			}
		})
	}
}

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestDecideCurationConditionLookup(t *testing.T) {
	const name = "target"
	listed := xray_datasource.CurationConditionsWalk{Scanned: 2, TotalCount: 4, Complete: false}
	complete := xray_datasource.CurationConditionsWalk{Scanned: 4, TotalCount: 4, Complete: true}

	t.Run("incomplete walk with one match is not unique", func(t *testing.T) {
		// An unread later page may hold a second condition with the same exact
		// name, so a single match on a truncated listing cannot be accepted.
		summary, detail := xray_datasource.DecideCurationConditionLookup(name, 1, listed)
		if summary == "" {
			t.Fatal("DecideCurationConditionLookup() succeeded, want an error for an incomplete walk")
		}
		if summary == "Curation condition not found" {
			t.Errorf("summary = %q, want an incomplete-listing diagnostic rather than a definitive not-found", summary)
		}
		if summary == "Multiple Curation conditions found" {
			t.Errorf("summary = %q, want an incomplete-listing diagnostic rather than a definitive duplicate", summary)
		}
		if !regexp.MustCompile(`(?i)incomplete|listed|truncated|page`).MatchString(summary + " " + detail) {
			t.Errorf("diagnostic %q / %q does not describe an incomplete listing", summary, detail)
		}
		if !regexp.MustCompile(`target`).MatchString(detail) {
			t.Errorf("detail = %q, want it to mention the looked-up name", detail)
		}
	})

	t.Run("incomplete walk with zero matches is not a definitive absence", func(t *testing.T) {
		summary, detail := xray_datasource.DecideCurationConditionLookup(name, 0, listed)
		if summary == "" {
			t.Fatal("DecideCurationConditionLookup() succeeded, want an error for an incomplete walk")
		}
		if summary == "Curation condition not found" {
			t.Errorf("summary = %q, want an incomplete-listing diagnostic rather than a definitive not-found", summary)
		}
		if !regexp.MustCompile(`(?i)incomplete|listed|truncated|page`).MatchString(summary + " " + detail) {
			t.Errorf("diagnostic %q / %q does not describe an incomplete listing", summary, detail)
		}
	})

	t.Run("complete walk with zero matches is not found", func(t *testing.T) {
		summary, detail := xray_datasource.DecideCurationConditionLookup(name, 0, complete)
		if summary != "Curation condition not found" {
			t.Fatalf("summary = %q, want %q", summary, "Curation condition not found")
		}
		if !regexp.MustCompile(`target`).MatchString(detail) {
			t.Errorf("detail = %q, want it to mention the looked-up name", detail)
		}
	})

	t.Run("complete walk with multiple matches is ambiguous", func(t *testing.T) {
		summary, detail := xray_datasource.DecideCurationConditionLookup(name, 2, complete)
		if summary != "Multiple Curation conditions found" {
			t.Fatalf("summary = %q, want %q", summary, "Multiple Curation conditions found")
		}
		if !regexp.MustCompile(`2`).MatchString(detail) {
			t.Errorf("detail = %q, want it to mention the match count", detail)
		}
	})

	t.Run("complete walk with one match succeeds", func(t *testing.T) {
		summary, detail := xray_datasource.DecideCurationConditionLookup(name, 1, complete)
		if summary != "" || detail != "" {
			t.Fatalf("DecideCurationConditionLookup() = %q / %q, want success", summary, detail)
		}
	})
}

// TestAccDataSourceCurationCondition_customCondition covers the customer flow: a
// condition is looked up by its exact name and the resulting `id` is fed to
// `xray_curation_policy.condition_id`. A custom condition created by the test is
// used instead of a built-in name so the test does not depend on the conditions
// shipped by a particular Xray version.
func TestAccDataSourceCurationCondition_customCondition(t *testing.T) {
	_, policyFqrn, policyName := testutil.MkNames("test-condition-lookup-policy", "xray_curation_policy")
	conditionName := fmt.Sprintf("test-condition-lookup-%d", testutil.RandomInt())
	repoName := fmt.Sprintf("test-condition-lookup-npm-%d", testutil.RandomInt())
	const dataSourceName = "data.xray_curation_condition.test"

	// A Curation policy is rejected by the API unless at least one curated
	// repository exists, so one is created for the duration of the test.
	config := fmt.Sprintf(`
		resource "artifactory_remote_npm_repository" "test" {
			key             = "%s"
			url             = "https://registry.npmjs.org/"
			repo_layout_ref = "npm-default"
			curated         = true
		}

		resource "xray_custom_curation_condition" "test" {
			name                  = "%s"
			condition_template_id = "isImmature"
			param_values = jsonencode([
				{
					param_id = "package_age_days"
					value    = 1
				},
				{
					param_id = "vulnerability_cvss_score"
					value    = 5.0
				}
			])
		}

		data "xray_curation_condition" "test" {
			name = xray_custom_curation_condition.test.name
		}

		resource "xray_curation_policy" "%s" {
			name                  = "%s"
			condition_id          = data.xray_curation_condition.test.id
			scope                 = "specific_repos"
			repo_include          = [artifactory_remote_npm_repository.test.key]
			policy_action         = "dry_run"
			waiver_request_config = "forbidden"
		}
	`, repoName, conditionName, policyName, policyName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		ExternalProviders: map[string]resource.ExternalProvider{
			"artifactory": {
				Source: "jfrog/artifactory",
			},
		},
		CheckDestroy: acctest.VerifyDeleted(policyFqrn, "", acctest.CheckCurationPolicy),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "name", conditionName),
					resource.TestMatchResourceAttr(dataSourceName, "id", regexp.MustCompile(`^\d+$`)),
					resource.TestCheckResourceAttr(dataSourceName, "condition_template_id", "isImmature"),
					resource.TestCheckResourceAttr(dataSourceName, "is_custom", "true"),
					// The parameter values the condition was created with are read back
					// from the API, so they must be present. `risk_type` and the audit
					// timestamps are assigned by the API and are not asserted, since
					// they are not part of what the lookup is responsible for.
					resource.TestCheckResourceAttrSet(dataSourceName, "param_values"),
					// The condition ID resolved by name must be the one the API assigned.
					resource.TestCheckResourceAttrPair(dataSourceName, "id", "xray_custom_curation_condition.test", "id"),
					// ... and it must be usable as condition_id of a Curation policy.
					resource.TestCheckResourceAttrPair(policyFqrn, "condition_id", dataSourceName, "id"),
				),
			},
		},
	})
}

// TestAccDataSourceCurationCondition_builtIn verifies a built-in condition can be
// resolved by name. The name is read from the API at test time rather than being
// hardcoded, so the test does not break when the built-in set changes.
func TestAccDataSourceCurationCondition_builtIn(t *testing.T) {
	const dataSourceName = "data.xray_curation_condition.built_in"

	// The condition name is looked up before the test case runs, so the test has
	// to be skipped explicitly when acceptance tests are not enabled.
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Acceptance test skipped unless env 'TF_ACC' set")
	}

	conditionName := builtInCurationConditionName(t)

	config := fmt.Sprintf(`
		data "xray_curation_condition" "built_in" {
			name = "%s"
		}
	`, conditionName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "name", conditionName),
					resource.TestMatchResourceAttr(dataSourceName, "id", regexp.MustCompile(`^\d+$`)),
					resource.TestCheckResourceAttrSet(dataSourceName, "condition_template_id"),
					resource.TestCheckResourceAttr(dataSourceName, "is_custom", "false"),
				),
			},
		},
	})
}

// TestAccDataSourceCurationCondition_notFound verifies that an unknown condition
// name produces a clear error instead of empty state.
func TestAccDataSourceCurationCondition_notFound(t *testing.T) {
	config := `
		data "xray_curation_condition" "missing" {
			name = "this-condition-does-not-exist-zzzz-9999"
		}
	`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Curation condition not found`),
			},
		},
	})
}

// builtInCurationConditionName returns the name of a built-in (non-custom)
// Curation condition from the test instance. Every page is walked, so the helper
// still finds one when the first page happens to hold only custom conditions.
// `is_custom` is not passed as a query filter because the API is not verified to
// support it; filtering locally cannot silently return a custom condition.
func builtInCurationConditionName(t *testing.T) string {
	t.Helper()

	var name string

	walk, err := xray_datasource.WalkCurationConditions(
		context.Background(),
		acctest.GetTestResty(t),
		nil,
		func(condition xray_datasource.CurationConditionAPIModel) {
			if name == "" && !condition.IsCustom {
				name = condition.Name
			}
		},
	)
	if err != nil {
		t.Fatalf("failed to list Curation conditions: %v", err)
	}

	if name == "" {
		t.Fatalf("no built-in Curation condition found on the test instance (%d of %d conditions listed, complete: %t)",
			walk.Scanned, walk.TotalCount, walk.Complete)
	}

	return name
}
