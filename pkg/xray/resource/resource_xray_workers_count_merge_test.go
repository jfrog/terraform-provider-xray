package xray

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
)

const currentWorkersCount = `{
	"index": {"new_content": 16, "existing_content": 4},
	"impact_analysis": {"new_content": 8},
	"postscan": {"new_content": 8, "existing_content": 4},
	"sbomcleanup": {"new_content": 2, "existing_content": 0},
	"some_future_type": {"new_content": 3, "existing_content": 1}
}`

func nullWorkersCountModel() WorkersCountResourceModelV1 {
	var m WorkersCountResourceModelV1
	for _, b := range workersCountBlocks {
		attrTypes := newExistingResourceModelAttributeTypes
		if b.newOnly {
			attrTypes = newResourceModelAttributeTypes
		}
		*b.field(&m) = types.SetNull(types.ObjectType{AttrTypes: attrTypes})
	}
	return m
}

func mustNewExistingSet(t *testing.T, n, e int64) types.Set {
	t.Helper()
	set, ds := newExistingModelToResourceSet(WorkersCountNewExistingContentAPIModel{
		WorkersCountNewContentAPIModel: WorkersCountNewContentAPIModel{New: n},
		Existing:                       e,
	})
	if ds.HasError() {
		t.Fatalf("newExistingModelToResourceSet: %v", ds)
	}
	return set
}

func TestWorkersCountPutPreservesUnconfiguredTypes(t *testing.T) {
	var putBody map[string]json.RawMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(currentWorkersCount))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &putBody); err != nil {
				t.Errorf("invalid PUT body %q: %v", b, err)
			}
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	r := &WorkersCountResource{
		ProviderData: util.ProviderMetadata{Client: resty.New().SetBaseURL(server.URL)},
	}

	plan := nullWorkersCountModel()
	plan.Index = mustNewExistingSet(t, 8, 2)
	plan.SBOMCleanup = mustNewExistingSet(t, 1, 1)

	if _, err := r.putWorkersCount(&plan); err != nil {
		t.Fatalf("putWorkersCount: %v", err)
	}

	want := map[string]string{
		"index":            `{"new_content":8,"existing_content":2}`,
		"sbomcleanup":      `{"new_content":1,"existing_content":1}`,
		"impact_analysis":  `{"new_content":8}`,
		"postscan":         `{"new_content":8,"existing_content":4}`,
		"some_future_type": `{"new_content":3,"existing_content":1}`,
	}
	if len(putBody) != len(want) {
		t.Fatalf("PUT body has %d keys, want %d: %v", len(putBody), len(want), putBody)
	}
	for k, v := range want {
		var got, exp any
		_ = json.Unmarshal(putBody[k], &got)
		_ = json.Unmarshal([]byte(v), &exp)
		gotJSON, _ := json.Marshal(got)
		expJSON, _ := json.Marshal(exp)
		if string(gotJSON) != string(expJSON) {
			t.Errorf("PUT %s = %s, want %s", k, gotJSON, expJSON)
		}
	}
}

func TestWorkersCountToState(t *testing.T) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(currentWorkersCount), &body); err != nil {
		t.Fatal(err)
	}

	t.Run("refreshes only blocks in state", func(t *testing.T) {
		state := nullWorkersCountModel()
		state.Index = mustNewExistingSet(t, 1, 1)

		if ds := state.toState(body); ds.HasError() {
			t.Fatalf("toState: %v", ds)
		}
		if !state.Index.Equal(mustNewExistingSet(t, 16, 4)) {
			t.Errorf("index = %v, want 16/4", state.Index)
		}
		if !state.PostScan.IsNull() {
			t.Errorf("post_scan = %v, want null", state.PostScan)
		}
	})

	t.Run("import populates all returned blocks", func(t *testing.T) {
		state := nullWorkersCountModel()

		if ds := state.toState(body); ds.HasError() {
			t.Fatalf("toState: %v", ds)
		}
		if !state.PostScan.Equal(mustNewExistingSet(t, 8, 4)) {
			t.Errorf("post_scan = %v, want 8/4", state.PostScan)
		}
		if !state.SBOMCleanup.Equal(mustNewExistingSet(t, 2, 0)) {
			t.Errorf("sbom_cleanup = %v, want 2/0", state.SBOMCleanup)
		}
		if len(state.ImpactAnalysis.Elements()) != 1 {
			t.Errorf("impact_analysis = %v, want one element", state.ImpactAnalysis)
		}
		if !state.Persist.IsNull() {
			t.Errorf("persist = %v, want null (not returned by API)", state.Persist)
		}
	})
}

func TestWorkersCountSchemaBlocksOptional(t *testing.T) {
	if ds := workersCountSchemaV1.ValidateImplementation(context.Background()); ds.HasError() {
		t.Fatalf("schema: %v", ds)
	}
	for name, block := range workersCountSchemaV1.Blocks {
		for _, v := range block.(schema.SetNestedBlock).Validators {
			if v.Description(context.Background()) == setvalidator.IsRequired().Description(context.Background()) {
				t.Errorf("block %s is required; omitted blocks must mean unchanged", name)
			}
		}
	}
	if len(workersCountSchemaV1.Blocks) != len(workersCountBlocks) {
		t.Errorf("schema has %d blocks, workersCountBlocks has %d", len(workersCountSchemaV1.Blocks), len(workersCountBlocks))
	}
}
