package provider_test

import (
	"testing"

	"github.com/jfrog/terraform-provider-xray/pkg/xray/provider"
)

func TestProvider(t *testing.T) {
	if err := provider.SdkV2().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}
