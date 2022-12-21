package xray

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jfrog/terraform-provider-shared/validator"
)

func getRestyRequest(client *resty.Client, projectKey string) (*resty.Request, error) {
	if client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	req := client.R()
	if len(projectKey) > 0 {
		req = req.SetQueryParam("projectKey", projectKey)
	}

	return req, nil
}

var getProjectKeySchema = func(isForceNew bool, additionalDescription string) map[string]*schema.Schema {
	description := fmt.Sprintf("Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters. %s", additionalDescription)

	return map[string]*schema.Schema{
		"project_key": {
			Type:             schema.TypeString,
			Optional:         true,
			ForceNew:         isForceNew,
			ValidateDiagFunc: validator.ProjectKey,
			Description:      description,
		},
	}
}
