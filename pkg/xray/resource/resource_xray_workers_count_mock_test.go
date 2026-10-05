package xray_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

// mockWorkersCount serves GET/PUT on the workers count endpoint and accepts anything else.
func mockWorkersCount(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	current := map[string]json.RawMessage{}
	_ = json.Unmarshal([]byte(`{
		"index": {"new_content": 16, "existing_content": 4},
		"persist": {"new_content": 8, "existing_content": 4},
		"impact_analysis": {"new_content": 8},
		"postscan": {"new_content": 8, "existing_content": 4},
		"sbomcleanup": {"new_content": 2, "existing_content": 0}
	}`), &current)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.HasSuffix(r.URL.Path, "/configuration/workersCount") {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(current)
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			next := map[string]json.RawMessage{}
			if err := json.Unmarshal(b, &next); err != nil {
				t.Errorf("invalid PUT body %q: %v", b, err)
			}
			current = next
			_, _ = w.Write([]byte(`{"info":"ok"}`))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func mockProviderEnv(t *testing.T, url string) {
	t.Setenv("JFROG_URL", url)
	t.Setenv("JFROG_ACCESS_TOKEN", "test")
	t.Setenv("SKIP_XRAY_VERSION_CHECK", "true")
}

const workersCountNoBlocks = `resource "xray_workers_count" "this" {}`

// Refreshes never add blocks the config omits, even when it omits all of them.
func TestWorkersCount_mockNoBlocksStaysEmpty(t *testing.T) {
	mockProviderEnv(t, mockWorkersCount(t).URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: workersCountNoBlocks,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("xray_workers_count.this", "index.#", "0"),
					resource.TestCheckResourceAttr("xray_workers_count.this", "post_scan.#", "0"),
				),
			},
			{Config: workersCountNoBlocks, PlanOnly: true},
		},
	})
}

// Import shows every block Xray returns; the import flag is cleared, so after
// applying a config without blocks, refreshes stop adding them.
func TestWorkersCount_mockImportThenConverge(t *testing.T) {
	mockProviderEnv(t, mockWorkersCount(t).URL)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        workersCountNoBlocks,
				ResourceName:  "xray_workers_count.this",
				ImportState:   true,
				ImportStateId: "workers",
				// Keep the imported state, so the next steps run against it.
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					want := map[string]string{"index.#": "1", "index.0.new_content": "16", "post_scan.#": "1", "sbom_cleanup.0.new_content": "2", "impact_analysis.#": "1"}
					for k, v := range want {
						if got := states[0].Attributes[k]; got != v {
							return fmt.Errorf("imported %s = %q, want %q", k, got, v)
						}
					}
					return nil
				},
			},
			// Drops the imported blocks; with the flag cleared, the post-apply refresh keeps them out.
			{Config: workersCountNoBlocks},
			{Config: workersCountNoBlocks, PlanOnly: true},
		},
	})
}
