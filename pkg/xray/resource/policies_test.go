package xray

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestPolicyReadBackRequestOmitsContentType(t *testing.T) {
	for _, caller := range []string{"Create", "Update"} {
		t.Run(caller, func(t *testing.T) {
			var sawRequest bool
			var gotContentType string

			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawRequest = true
				gotContentType = r.Header.Get("Content-Type")
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(`{}`)); err != nil {
					t.Errorf("failed to write response: %v", err)
				}
			}))
			defer proxy.Close()

			client := resty.New().
				SetBaseURL(proxy.URL).
				SetHeader("content-type", "application/json")

			request, err := policyReadBackRequest(client, "")
			if err != nil {
				t.Fatalf("policyReadBackRequest() unexpected error: %v", err)
			}

			response, err := request.SetPathParam("name", "test-policy").Get(PolicyEndpoint)
			if err != nil {
				t.Fatalf("GET failed: %v", err)
			}
			if response.IsError() {
				t.Fatalf("GET returned error status: %d", response.StatusCode())
			}
			if !sawRequest {
				t.Fatal("proxy did not receive the GET request")
			}
			if gotContentType != "" {
				t.Errorf("GET request Content-Type = %q, want empty", gotContentType)
			}
		})
	}
}
