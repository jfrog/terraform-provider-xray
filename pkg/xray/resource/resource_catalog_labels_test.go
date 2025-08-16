package xray_test

import (
	"regexp"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/jfrog/terraform-provider-shared/testutil"
	"github.com/jfrog/terraform-provider-shared/util"
	"github.com/jfrog/terraform-provider-xray/v3/pkg/acctest"
)

func TestAccCatalogLabels_BasicCRUD(t *testing.T) {
	_, fqrn, resName := testutil.MkNames("catalog-labels-", "xray_catalog_labels")

	cfg := util.ExecuteTemplate("TestAccCatalogLabels_BasicCRUD", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [
    { name = "tacc1", description = "d1" },
    { name = "tacc2", description = "d2" }
  ]
}
`, map[string]string{"name": resName})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{Config: cfg,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(fqrn, "labels.#", "2"),
				resource.TestCheckResourceAttr(fqrn, "labels.0.name", "tacc1"),
			),
		}},
	})
}

func TestAccCatalogLabels_Assignments(t *testing.T) {
	_, fqrn, resName := testutil.MkNames("catalog-labels-assign-", "xray_catalog_labels")

	cfg := util.ExecuteTemplate("TestAccCatalogLabels_Assignments", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "tass1", description = "d1" } ]
  package_assignments = [
    { label_name = "tass1", package_name = "express", package_type = "npm" }
  ]
  version_assignments = [
    { label_name = "tass1", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}
`, map[string]string{"name": resName})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{Config: cfg,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(fqrn, "labels.#", "1"),
				resource.TestCheckResourceAttr(fqrn, "package_assignments.#", "1"),
				resource.TestCheckResourceAttr(fqrn, "version_assignments.#", "1"),
			),
		}},
	})
}

func TestAccCatalogLabels_UpdateAssignments(t *testing.T) {
	_, fqrn, resName := testutil.MkNames("catalog-labels-update-", "xray_catalog_labels")

	cfg1 := util.ExecuteTemplate("TestAccCatalogLabels_UpdateAssignments_1", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "tupd1", description = "d1" } ]
  package_assignments = [
    { label_name = "tupd1", package_name = "express", package_type = "npm" }
  ]
  version_assignments = [
    { label_name = "tupd1", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}
`, map[string]string{"name": resName})

	cfg2 := util.ExecuteTemplate("TestAccCatalogLabels_UpdateAssignments_2", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "tupd1", description = "d1-updated" } ]
  package_assignments = [
    { label_name = "tupd1", package_name = "lodash", package_type = "npm" }
  ]
  version_assignments = [
    { label_name = "tupd1", package_name = "express", package_type = "npm", versions = ["4.18.2"] }
  ]
}
`, map[string]string{"name": resName})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg1},
			{Config: cfg2, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(fqrn, "labels.#", "1"),
			)},
		},
	})
}

func TestAccCatalogLabels_LabelNameValidation(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-nameval-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_LabelNameValidation", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "this-name-is-way-too-long", description = "d1" } ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(length|too long|at most)`),
		}},
	})
}

func TestAccCatalogLabels_LabelDescriptionValidation(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-descval-", "xray_catalog_labels")
	// description > 300
	d := make([]byte, 0, 310)
	for i := 0; i < 310; i++ {
		d = append(d, 'a')
	}
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_LabelDescriptionValidation", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "okname", description = "{{ .desc }}" } ]
}
`, map[string]string{"name": resName, "desc": string(d)})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(length|too long|at most)`),
		}},
	})
}

func TestAccCatalogLabels_AssignmentMissingLabel(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-misslbl-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_AssignmentMissingLabel", `
resource "xray_catalog_labels" "{{ .name }}" {
  package_assignments = [
    { label_name = "missing-12345", package_name = "express", package_type = "npm" }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(do not exist|must be specified|missing)`),
		}},
	})
}

func TestAccCatalogLabels_VersionsValidation_Empty(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-versempty-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_VersionsValidation_Empty", `
resource "xray_catalog_labels" "{{ .name }}" {
  version_assignments = [
    { label_name = "lbl1", package_name = "lodash", package_type = "npm", versions = [] }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(at least 1|required|must contain)`),
		}},
	})
}

func TestAccCatalogLabels_PlanWarnings(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-planwarn-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_PlanWarnings", `
resource "xray_catalog_labels" "{{ .name }}" {
  package_assignments = [
    { label_name = "beta-foo", package_name = "express", package_type = "npm" }
  ]
  version_assignments = [
    { label_name = "beta-foo", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}
`, map[string]string{"name": resName})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{Config: cfg,
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
		}},
	})
}

func TestAccCatalogLabels_ReadReconcile(t *testing.T) {
	_, fqrn, resName := testutil.MkNames("catalog-labels-read-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_ReadReconcile", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "tread1", description = "d1" } ]
  package_assignments = [
    { label_name = "tread1", package_name = "express", package_type = "npm" }
  ]
  version_assignments = [
    { label_name = "tread1", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}
`, map[string]string{"name": resName})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg},
			{PlanOnly: true, Config: cfg, ExpectNonEmptyPlan: false},
			{Config: cfg, Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr(fqrn, "labels.#", "1"),
			)},
		},
	})
}

func TestAccCatalogLabels_DeleteExplicit(t *testing.T) {
	acctest.PreCheck(t)
	_, fqrn, resName := testutil.MkNames("catalog-labels-del-", "xray_catalog_labels")

	cfg := util.ExecuteTemplate("TestAccCatalogLabels_DeleteExplicit", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [{ name = "tdel1", description = "d" }]
}
`, map[string]string{"name": resName})

	empty := `# removed`

	checkDeleted := acctest.VerifyDeleted(fqrn, "id", func(id string, req *resty.Request) (*resty.Response, error) {
		q := `query { customCatalogLabel { getLabel(name: "tdel1") { name } } }`
		base := testutil.GetEnvVarWithFallback(t, "XRAY_URL", "JFROG_URL")
		endpoint := base + "/catalog/api/v1/custom/graphql"
		return req.SetBody(map[string]any{"query": q}).Post(endpoint)
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		CheckDestroy:             checkDeleted,
		Steps: []resource.TestStep{
			{Config: cfg},
			{Config: empty},
		},
	})
}

func TestAccCatalogLabels_LabelNameTooShort(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-nameshort-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_LabelNameTooShort", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "a", description = "d1" } ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(length|at least|too short)`),
		}},
	})
}

func TestAccCatalogLabels_LabelDescriptionEmpty(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-descempty-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_LabelDescriptionEmpty", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [ { name = "okname", description = "" } ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(length|at least|required|non-empty)`),
		}},
	})
}

func TestAccCatalogLabels_PackageAssignmentMissingLabelName(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-pkg-misslabel-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_PackageAssignmentMissingLabelName", `
resource "xray_catalog_labels" "{{ .name }}" {
  package_assignments = [
    { label_name = "", package_name = "express", package_type = "npm" }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(must be specified|label must be specified|required)`),
		}},
	})
}

func TestAccCatalogLabels_VersionAssignmentMissingLabelName(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-ver-misslabel-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_VersionAssignmentMissingLabelName", `
resource "xray_catalog_labels" "{{ .name }}" {
  version_assignments = [
    { label_name = "", package_name = "lodash", package_type = "npm", versions = ["4.17.21"] }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(must be specified|label must be specified|required)`),
		}},
	})
}

func TestAccCatalogLabels_VersionsValidation_ContainsEmpty(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-verscontainsempty-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_VersionsValidation_ContainsEmpty", `
resource "xray_catalog_labels" "{{ .name }}" {
  version_assignments = [
    { label_name = "lbl1", package_name = "lodash", package_type = "npm", versions = [""] }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(non-empty|at least|required)`),
		}},
	})
}

func TestAccCatalogLabels_ImportState(t *testing.T) {
	_, fqrn, resName := testutil.MkNames("catalog-labels-import-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_ImportState", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = [
    { name = "imp1", description = "d1" },
    { name = "imp2", description = "d2" }
  ]
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				ResourceName:  fqrn,
				ImportState:   true,
				ImportStateId: "imp1,imp2",
				// Descriptions are not populated on import; just ensure it imports without error
				ImportStateVerify: false,
			},
		},
	})
}

func TestAccCatalogLabels_LabelsEmptySet(t *testing.T) {
	_, _, resName := testutil.MkNames("catalog-labels-emptylabels-", "xray_catalog_labels")
	cfg := util.ExecuteTemplate("TestAccCatalogLabels_LabelsEmptySet", `
resource "xray_catalog_labels" "{{ .name }}" {
  labels = []
}
`, map[string]string{"name": resName})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexp.MustCompile(`(?i)(at least 1|must contain|non-empty)`),
		}},
	})
}
