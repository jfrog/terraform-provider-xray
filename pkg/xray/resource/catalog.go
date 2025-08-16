package xray

import (
	"fmt"
	"strings"
)

const (
	CatalogGraphQLEndpoint    = "catalog/api/v1/custom/graphql"
	MaxLabelsPerOperation     = 500
	MaxLabelNameLength        = 15  // User requirement: max 15 characters
	MaxLabelDescriptionLength = 300 // User requirement: max 300 characters
)

// parseGraphQLError extracts meaningful error messages from GraphQL responses
func (r *CatalogLabelsResource) parseGraphQLError(responseBody string) string {
	apiErrors := []string{
		fmt.Sprintf("Creating more than %d labels is not supported", MaxLabelsPerOperation),
		"Some of the labels already exist",
		"Assigning more than 1 label is not supported",
		fmt.Sprintf("Deleting more than %d labels is not supported", MaxLabelsPerOperation),
		fmt.Sprintf("Removing more than %d labels assignments in a single operation is not supported", MaxLabelsPerOperation),
		fmt.Sprintf("Assigning a label to more than %d package versions in a single operation is not supported", MaxLabelsPerOperation),
		"A label name cannot be empty",
		"Labels must be specified for the assignment",
		"A requested package version already has a label assigned. More than one label per package version is not supported yet",
		"A requested package already has a label assigned. More than one label per package is not supported yet",
		"Label name is too long",
		"Label description is too long",
		"does not exist",
		"already exists",
		"were not found",
	}
	for _, apiError := range apiErrors {
		if strings.Contains(responseBody, apiError) {
			return apiError
		}
	}
	return responseBody
}

// Utility helpers
func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// GraphQL Request/Response structures
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type GraphQLResponse struct {
	Data   interface{} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

type GetSingleLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			GetLabel struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"getLabel"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type GetMultipleLabelsResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			SearchLabels struct {
				Edges []struct {
					Node struct {
						Name        string `json:"name"`
						Description string `json:"description"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"searchLabels"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type CreateLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			CreateCustomCatalogLabel struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"createCustomCatalogLabel"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type CreateMultipleLabelsResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			CreateCustomCatalogLabels []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"createCustomCatalogLabels"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type DeleteSingleLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			DeleteCustomCatalogLabel bool `json:"deleteCustomCatalogLabel"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type DeleteMultipleLabelsResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			DeleteCustomCatalogLabels bool `json:"deleteCustomCatalogLabels"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type UpdateLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			UpdateCustomCatalogLabel struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"updateCustomCatalogLabel"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

// Response structure for getting package assigned labels
type GetPackageLabelResponse struct {
	Data struct {
		PublicPackage struct {
			GetPackage struct {
				Name                          string `json:"name"`
				Type                          string `json:"type"`
				CustomCatalogLabelsConnection struct {
					Edges []struct {
						Node struct {
							Name string `json:"name"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"customCatalogLabelsConnection"`
			} `json:"getPackage"`
		} `json:"publicPackage"`
	} `json:"data"`
}

type AssignPackagelabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			AssignCustomCatalogLabelsToPublicPackage bool `json:"assignCustomCatalogLabelsToPublicPackage"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type RemovePackageLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			RemoveCustomCatalogLabelsFromPublicPackage bool `json:"removeCustomCatalogLabelsFromPublicPackage"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

// Response structure for getting package version assigned labels
type GetPackageVersionLabelsResponse struct {
	Data struct {
		PublicPackageVersion struct {
			GetVersion struct {
				CustomCatalogLabelsConnection struct {
					Edges []struct {
						Node struct {
							Name string `json:"name"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"customCatalogLabelsConnection"`
			} `json:"getVersion"`
		} `json:"publicPackageVersion"`
	} `json:"data"`
}

type AssignSinglePackageVersionLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			AssignCustomCatalogLabelsToPublicPackageVersion bool `json:"assignCustomCatalogLabelsToPublicPackageVersion"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type AssignMultiplePackageVersionsLabelsResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			AssignCustomCatalogLabelToPublicPackageVersions bool `json:"assignCustomCatalogLabelToPublicPackageVersions"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type RemoveSinglePackageVersionLabelResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			RemoveCustomCatalogLabelsFromPublicPackageVersion bool `json:"removeCustomCatalogLabelsFromPublicPackageVersion"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

type RemoveMultiplePackageVersionsLabelsResponse struct {
	Data struct {
		CustomCatalogLabel struct {
			RemoveCustomCatalogLabelFromPublicPackageVersions bool `json:"removeCustomCatalogLabelFromPublicPackageVersions"`
		} `json:"customCatalogLabel"`
	} `json:"data"`
}

// Query string helpers
func getLabelQuery(name string) string {
	return fmt.Sprintf(`
		query {
			customCatalogLabel {
				getLabel(name: "%s") {
					name
					description
				}
			}
		}
	`, name)
}

func searchLabelsQuery() string {
	return `
	query {
		customCatalogLabel {
			searchLabels {
				edges { node { name description } }
			}
		}
	}
	`
}

// Query builder: get assigned labels for a package
func getPackageLabelsQuery(packageName, packageType string) string {
	return fmt.Sprintf(`
	query {
		publicPackage {
			getPackage(name: "%s" type: "%s") {
				name
				type
				customCatalogLabelsConnection(first: 100) {
					edges { node { name } }
				}
			}
		}
	}
	`, packageName, packageType)
}

// Query builder: get assigned labels for a package version
func getPackageVersionLabelsQuery(packageName, packageType, version string) string {
	return fmt.Sprintf(`
	query {
		publicPackageVersion {
			getVersion(name: "%s", type: "%s", version: "%s") {
				customCatalogLabelsConnection(first: 100) {
					edges { node { name } }
				}
			}
		}
	}
	`, packageName, packageType, version)
}

// Mutation string helpers (string builders only)
func createSingleLabelMutation(name, description string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			createCustomCatalogLabel(label: {name: "%s", description: "%s"}) {
				name
				description
			}
		}
	}
	`, name, description)
}

func createMultipleLabelsMutation(labelsJson string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel{
			createCustomCatalogLabels(labels: [%s]) {
				name
				description
			}
		}
	}
	`, labelsJson)
}

func deleteSingleLabelMutation(name string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			deleteCustomCatalogLabel(label:{name:"%s"})
		}
	}
	`, name)
}

func deleteMultipleLabelsMutation(labelsJson string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			deleteCustomCatalogLabels(labels:[%s])
		}
	}
	`, labelsJson)
}

func updateLabelMutation(currentName, updatedName, updatedDescription string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			updateCustomCatalogLabel(
				label: {name: "%s", updatedName: "%s", updatedDescription: "%s"}
			) {
				name
				description
			}
		}
	}
	`, currentName, updatedName, updatedDescription)
}

func assignPackageLabelMutation(pkgName, pkgType, labelName string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			assignCustomCatalogLabelsToPublicPackage(
				publicPackageLabels: {
					publicPackage: {name:"%s", type:"%s"}
					labelNames:["%s"]
				}
			)
		}
	}
	`, pkgName, pkgType, labelName)
}

func removePackageLabelMutation(labelNamesJson, pkgName, pkgType string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			removeCustomCatalogLabelsFromPublicPackage(
				publicPackageLabels:{
					labelNames:[%s]
					publicPackage:{name:"%s", type:"%s"}
				}
			)
		}
	}
	`, labelNamesJson, pkgName, pkgType)
}

func assignSinglePackageVersionLabelMutation(pkgName, pkgType, versions, labelName string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			assignCustomCatalogLabelsToPublicPackageVersion(
				publicPackageVersionLabels: {
					publicPackageVersion: {publicPackage: {name: "%s", type: "%s"}, version: "%s"}
					labelNames: ["%s"]
				}
			)
		}
	}
	`, pkgName, pkgType, versions, labelName)
}

func assignMultiplePackageVersionsLabelsMutation(pvJson, labelName string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			assignCustomCatalogLabelToPublicPackageVersions(
				publicPackageVersionsLabel: {
					publicPackageVersions: [%s],
					labelName: "%s"
				}
			)
		}
	}
	`, pvJson, labelName)
}

func removeSinglePackageVersionLabelMutation(pkgName, pkgType, version, labelNamesJson string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			removeCustomCatalogLabelsFromPublicPackageVersion(
				publicPackageVersionLabels: {
					publicPackageVersion: {
						publicPackage: {name:"%s", type:"%s"}
						version:"%s"
					}
					labelNames:[%s]
				}
			)
		}
	}
	`, pkgName, pkgType, version, labelNamesJson)
}

func removeMultiplePackageVersionsLabelsMutation(pvJson, labelNamesJson string) string {
	return fmt.Sprintf(`
	mutation {
		customCatalogLabel {
			removeCustomCatalogLabelFromPublicPackageVersions(
				publicPackageVersionsLabel: {
					publicPackageVersions: [%s]
					labelName: "%s"
				}
			)
		}
	}
	`, pvJson, labelNamesJson)
}
