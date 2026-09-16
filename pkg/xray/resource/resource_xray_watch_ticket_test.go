package xray

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestWatch_fromAPIModelByVersionUsesFalseNotNull(t *testing.T) {
	enabled := true
	m := WatchResourceModel{}
	api := WatchAPIModel{
		GeneralData: WatchGeneralDataAPIModel{
			Name:   "watch",
			Active: true,
		},
		CreateTicketEnabled: &enabled,
		TicketProfile:       "my-jira-profile",
		TicketGeneration: &TicketGenerationAPIModel{
			CreateDuplicateTickets: &DuplicateTicketCreationAPIModel{
				ByVersion: VersionTicketSettingsAPIModel{
					Build: true,
				},
			},
		},
	}

	diags := m.fromAPIModel(context.Background(), api)
	if diags.HasError() {
		t.Fatalf("fromAPIModel diagnostics: %v", diags)
	}

	cdt := m.TicketGeneration.Attributes()["create_duplicate_tickets"].(types.Object)
	if cdt.IsNull() {
		t.Fatal("create_duplicate_tickets should be set when build is true")
	}

	bv := cdt.Attributes()["by_version"].(types.Object).Attributes()
	if bv["build"].IsNull() || !bv["build"].(types.Bool).ValueBool() {
		t.Fatal("build should be true")
	}
	if bv["package"].IsNull() {
		t.Fatal("omitted package must be false, not null, so it matches schema defaults")
	}
	if bv["package"].(types.Bool).ValueBool() {
		t.Fatal("omitted package should be false")
	}
	if bv["release_bundle"].IsNull() {
		t.Fatal("omitted release_bundle must be false, not null, so it matches schema defaults")
	}
	if bv["release_bundle"].(types.Bool).ValueBool() {
		t.Fatal("omitted release_bundle should be false")
	}

	ignored := m.TicketGeneration.Attributes()["create_tickets_for_ignored_violation"].(types.Bool)
	if ignored.IsNull() || ignored.ValueBool() {
		t.Fatal("omitted create_tickets_for_ignored_violation must be false, not null")
	}
}

func TestWatch_fromAPIModelOmitsAllFalseByVersion(t *testing.T) {
	enabled := true
	m := WatchResourceModel{}
	api := WatchAPIModel{
		GeneralData: WatchGeneralDataAPIModel{
			Name:   "watch",
			Active: true,
		},
		CreateTicketEnabled: &enabled,
		TicketProfile:       "my-jira-profile",
		TicketGeneration: &TicketGenerationAPIModel{
			CreateDuplicateTickets: &DuplicateTicketCreationAPIModel{
				ByVersion: VersionTicketSettingsAPIModel{},
			},
		},
	}

	diags := m.fromAPIModel(context.Background(), api)
	if diags.HasError() {
		t.Fatalf("fromAPIModel diagnostics: %v", diags)
	}

	cdt := m.TicketGeneration.Attributes()["create_duplicate_tickets"].(types.Object)
	if !cdt.IsNull() {
		t.Fatal("all-false by_version should be omitted from state to avoid drift")
	}
}
