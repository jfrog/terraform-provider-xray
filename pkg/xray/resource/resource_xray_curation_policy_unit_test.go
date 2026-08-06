package xray

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCurationPolicyAPIRequestShareWithFederationSerialization(t *testing.T) {
	testCases := []struct {
		name                string
		configValue         types.Bool
		resolvedValue       types.Bool
		wantField           bool
		wantFederationValue bool
	}{
		{
			name:          "omits field when absent from configuration",
			configValue:   types.BoolNull(),
			resolvedValue: types.BoolValue(false),
			wantField:     false,
		},
		{
			name:                "includes explicit false",
			configValue:         types.BoolValue(false),
			resolvedValue:       types.BoolValue(false),
			wantField:           true,
			wantFederationValue: false,
		},
		{
			name:                "includes explicit true",
			configValue:         types.BoolValue(true),
			resolvedValue:       types.BoolValue(true),
			wantField:           true,
			wantFederationValue: true,
		},
		{
			name:                "includes value resolved from unknown configuration",
			configValue:         types.BoolUnknown(),
			resolvedValue:       types.BoolValue(true),
			wantField:           true,
			wantFederationValue: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			plan := minimalCurationPolicyModel("all_repos", testCase.resolvedValue)

			request, diags := (&CurationPolicyResource{}).toAPIRequest(context.Background(), plan, testCase.configValue)
			if diags.HasError() {
				t.Fatalf("toAPIRequest() returned diagnostics: %v", diags)
			}

			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var fields map[string]json.RawMessage
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}

			rawValue, found := fields["share_with_federation"]
			if found != testCase.wantField {
				t.Fatalf("share_with_federation presence = %t, want %t; payload: %s", found, testCase.wantField, payload)
			}
			if !found {
				return
			}

			var got bool
			if err := json.Unmarshal(rawValue, &got); err != nil {
				t.Fatalf("unmarshal share_with_federation: %v", err)
			}
			if got != testCase.wantFederationValue {
				t.Errorf("share_with_federation = %t, want %t", got, testCase.wantFederationValue)
			}
		})
	}
}

func TestCurationPolicyAPIResponseOmittedFederationHydratesFalse(t *testing.T) {
	var policy CurationPolicyAPIModel
	if err := json.Unmarshal([]byte(`{
		"id": "policy-id",
		"name": "policy",
		"condition_id": "3",
		"scope": "all_repos",
		"policy_action": "block",
		"block_from_cache": false
	}`), &policy); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	var state CurationPolicyResourceModel
	diags := (&CurationPolicyResource{}).fromAPIModel(context.Background(), policy, &state)
	if diags.HasError() {
		t.Fatalf("fromAPIModel() returned diagnostics: %v", diags)
	}
	if state.ShareWithFederation.IsNull() || state.ShareWithFederation.IsUnknown() {
		t.Fatalf("share_with_federation = %v, want known false", state.ShareWithFederation)
	}
	if state.ShareWithFederation.ValueBool() {
		t.Error("share_with_federation = true, want false")
	}
}

func TestCurationPolicyAPIRequestRejectsResolvedFederationForSpecificRepos(t *testing.T) {
	plan := minimalCurationPolicyModel("specific_repos", types.BoolValue(true))

	_, diags := (&CurationPolicyResource{}).toAPIRequest(
		context.Background(),
		plan,
		types.BoolUnknown(),
	)

	if !diags.HasError() {
		t.Fatal("toAPIRequest() returned no error, want share_with_federation scope diagnostic")
	}
	if !strings.Contains(diags.Errors()[0].Summary(), "Federation sharing not allowed") {
		t.Fatalf("diagnostic summary = %q, want federation sharing error", diags.Errors()[0].Summary())
	}
}

func minimalCurationPolicyModel(scope string, shareWithFederation types.Bool) CurationPolicyResourceModel {
	return CurationPolicyResourceModel{
		Name:                types.StringValue("policy"),
		ConditionID:         types.StringValue("3"),
		Scope:               types.StringValue(scope),
		PolicyAction:        types.StringValue("block"),
		RepoExclude:         types.SetNull(types.StringType),
		RepoInclude:         types.SetNull(types.StringType),
		PkgTypesInclude:     types.SetNull(types.StringType),
		Waivers:             types.SetNull(types.ObjectType{}),
		LabelWaivers:        types.SetNull(types.ObjectType{}),
		NotifyEmails:        types.SetNull(types.StringType),
		WaiverRequestConfig: types.StringNull(),
		DecisionOwners:      types.SetNull(types.StringType),
		BlockFromCache:      types.BoolValue(false),
		ShareWithFederation: shareWithFederation,
	}
}
