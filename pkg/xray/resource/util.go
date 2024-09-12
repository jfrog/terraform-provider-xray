package xray

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	sdkv2_schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	sdkv2_validator "github.com/jfrog/terraform-provider-shared/validator"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
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

var getProjectKeySchema = func(isForceNew bool, additionalDescription string) map[string]*sdkv2_schema.Schema {
	description := fmt.Sprintf("Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters. %s", additionalDescription)

	return map[string]*sdkv2_schema.Schema{
		"project_key": {
			Type:             sdkv2_schema.TypeString,
			Optional:         true,
			ForceNew:         isForceNew,
			ValidateDiagFunc: sdkv2_validator.ProjectKey,
			Description:      description,
		},
	}
}

var projectKeySchemaAttrs = func(isForceNew bool, additionalDescription string) map[string]schema.Attribute {
	description := fmt.Sprintf("Project key for assigning this resource to. Must be 2 - 10 lowercase alphanumeric and hyphen characters. %s", additionalDescription)
	planModifiers := []planmodifier.String{}

	if isForceNew {
		planModifiers = append(planModifiers, stringplanmodifier.RequiresReplace())
	}

	return map[string]schema.Attribute{
		"project_key": schema.StringAttribute{
			Optional: true,
			Validators: []validator.String{
				validatorfw_string.ProjectKey(),
			},
			PlanModifiers: planModifiers,
			Description:   description,
		},
	}
}

type IsRFC3339TimeValidator struct{}

// Description returns a plain text description of the validator's behavior, suitable for a practitioner to understand its impact.
func (v IsRFC3339TimeValidator) Description(ctx context.Context) string {
	return "string must be a valid RFC3339 date"
}

// MarkdownDescription returns a markdown formatted description of the validator's behavior, suitable for a practitioner to understand its impact.
func (v IsRFC3339TimeValidator) MarkdownDescription(ctx context.Context) string {
	return "string must be a valid RFC3339 date"
}

// Validate runs the main validation logic of the validator, reading configuration data out of `req` and updating `resp` with diagnostics.
func (v IsRFC3339TimeValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// If the value is unknown or null, there is nothing to validate.
	if req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}

	timeString := req.ConfigValue.ValueString()

	if _, err := time.Parse(time.RFC3339, timeString); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Time Format",
			fmt.Sprintf("Value must be a valid RFC3339 date, got: %s: %+v", timeString, err),
		)
		return
	}
}

func IsRFC3339Time() IsRFC3339TimeValidator {
	return IsRFC3339TimeValidator{}
}
