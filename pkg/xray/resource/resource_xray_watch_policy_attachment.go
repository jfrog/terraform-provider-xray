package xray

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jfrog/terraform-provider-shared/util"
	utilfw "github.com/jfrog/terraform-provider-shared/util/fw"
	validatorfw_string "github.com/jfrog/terraform-provider-shared/validator/fw/string"
	"github.com/samber/lo"
)

// watchMutexes serializes concurrent read-modify-write operations against the
// same watch. Because a policy assignment lives inside the watch object (Xray
// has no dedicated attachment endpoint), each attachment must GET the watch,
// modify its assigned_policies list, and PUT it back. Two attachments targeting
// the same watch in a single apply would otherwise race and clobber each other.
var watchMutexes sync.Map

func lockWatch(name string) func() {
	mu, _ := watchMutexes.LoadOrStore(name, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

var _ resource.Resource = &WatchPolicyAttachmentResource{}

func NewWatchPolicyAttachmentResource() resource.Resource {
	return &WatchPolicyAttachmentResource{
		TypeName: "xray_watch_policy_attachment",
	}
}

type WatchPolicyAttachmentResource struct {
	ProviderData util.ProviderMetadata
	TypeName     string
}

type WatchPolicyAttachmentResourceModel struct {
	WatchName  types.String `tfsdk:"watch_name"`
	PolicyName types.String `tfsdk:"policy_name"`
	PolicyType types.String `tfsdk:"policy_type"`
	ProjectKey types.String `tfsdk:"project_key"`
}

func (r *WatchPolicyAttachmentResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.TypeName
}

func (r *WatchPolicyAttachmentResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Attaches a single policy to a watch as a standalone resource. This decouples the " +
			"policy-to-watch relationship from both the `xray_security_policy` (or license/operational risk) " +
			"and `xray_watch` resources so that a policy can be detached and deleted without destroying the " +
			"watch. Manage a watch's policies either with this resource or with the `assigned_policy` block " +
			"on `xray_watch` - not both.",
		Attributes: map[string]schema.Attribute{
			"watch_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the watch to attach the policy to.",
			},
			"policy_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the policy to attach.",
			},
			"policy_type": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("security", "license", "operational_risk"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The type of the policy - `security`, `license` or `operational_risk`.",
			},
			"project_key": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					validatorfw_string.ProjectKey(),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Project key of the watch. Must be 2 - 10 lowercase alphanumeric and hyphen characters.",
			},
		},
	}
}

func (r *WatchPolicyAttachmentResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
	r.ProviderData = req.ProviderData.(util.ProviderMetadata)
}

// getWatch fetches the watch by name. The returned bool is false when the watch
// does not exist (HTTP 404).
func (r *WatchPolicyAttachmentResource) getWatch(projectKey, watchName string, watch *WatchAPIModel) (found bool, errMsg string) {
	request, err := getRestyRequest(r.ProviderData.Client, projectKey)
	if err != nil {
		return false, err.Error()
	}

	response, err := request.
		SetPathParam("name", watchName).
		SetResult(watch).
		Get(WatchEndpoint)
	if err != nil {
		return false, err.Error()
	}
	if response.StatusCode() == http.StatusNotFound {
		return false, ""
	}
	if response.IsError() {
		return false, response.String()
	}

	return true, ""
}

// putWatch writes the watch back after its assigned_policies list has been modified.
func (r *WatchPolicyAttachmentResource) putWatch(projectKey, watchName string, watch WatchAPIModel) (errMsg string) {
	request, err := getRestyRequest(r.ProviderData.Client, projectKey)
	if err != nil {
		return err.Error()
	}

	response, err := request.
		SetPathParam("name", watchName).
		SetBody(watch).
		Put(WatchEndpoint)
	if err != nil {
		return err.Error()
	}
	if response.IsError() {
		return response.String()
	}

	return ""
}

func (r *WatchPolicyAttachmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	go util.SendUsageResourceCreate(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var plan WatchPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectKey := plan.ProjectKey.ValueString()
	watchName := plan.WatchName.ValueString()
	policyName := plan.PolicyName.ValueString()
	policyType := plan.PolicyType.ValueString()

	unlock := lockWatch(watchName)
	defer unlock()

	var watch WatchAPIModel
	found, errMsg := r.getWatch(projectKey, watchName, &watch)
	if errMsg != "" {
		utilfw.UnableToCreateResourceError(resp, errMsg)
		return
	}
	if !found {
		resp.Diagnostics.AddError(
			"Watch not found",
			fmt.Sprintf("Watch '%s' does not exist. The watch must be created before attaching a policy to it.", watchName),
		)
		return
	}

	alreadyAttached := lo.ContainsBy(watch.AssignedPolicies, func(p WatchAssignedPolicyAPIModel) bool {
		return p.Name == policyName && p.Type == policyType
	})

	if !alreadyAttached {
		watch.AssignedPolicies = append(watch.AssignedPolicies, WatchAssignedPolicyAPIModel{
			Name: policyName,
			Type: policyType,
		})

		if errMsg := r.putWatch(projectKey, watchName, watch); errMsg != "" {
			utilfw.UnableToCreateResourceError(resp, errMsg)
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WatchPolicyAttachmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	go util.SendUsageResourceRead(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WatchPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectKey := state.ProjectKey.ValueString()
	watchName := state.WatchName.ValueString()
	policyName := state.PolicyName.ValueString()
	policyType := state.PolicyType.ValueString()

	var watch WatchAPIModel
	found, errMsg := r.getWatch(projectKey, watchName, &watch)
	if errMsg != "" {
		utilfw.UnableToRefreshResourceError(resp, errMsg)
		return
	}
	// If the watch is gone, the attachment is gone too.
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	attached := lo.ContainsBy(watch.AssignedPolicies, func(p WatchAssignedPolicyAPIModel) bool {
		return p.Name == policyName && p.Type == policyType
	})
	// The policy was detached out-of-band; drop the attachment from state.
	if !attached {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is never expected to be called because every attribute forces replacement,
// but the interface requires it.
func (r *WatchPolicyAttachmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan WatchPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WatchPolicyAttachmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	go util.SendUsageResourceDelete(ctx, r.ProviderData.Client.R(), r.ProviderData.ProductId, r.TypeName)

	var state WatchPolicyAttachmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectKey := state.ProjectKey.ValueString()
	watchName := state.WatchName.ValueString()
	policyName := state.PolicyName.ValueString()
	policyType := state.PolicyType.ValueString()

	unlock := lockWatch(watchName)
	defer unlock()

	var watch WatchAPIModel
	found, errMsg := r.getWatch(projectKey, watchName, &watch)
	if errMsg != "" {
		utilfw.UnableToDeleteResourceError(resp, errMsg)
		return
	}
	// Watch already gone - nothing to detach.
	if !found {
		return
	}

	filtered := lo.Reject(watch.AssignedPolicies, func(p WatchAssignedPolicyAPIModel, _ int) bool {
		return p.Name == policyName && p.Type == policyType
	})
	// Policy already detached - nothing to do.
	if len(filtered) == len(watch.AssignedPolicies) {
		return
	}
	watch.AssignedPolicies = filtered

	if errMsg := r.putWatch(projectKey, watchName, watch); errMsg != "" {
		utilfw.UnableToDeleteResourceError(resp, errMsg)
		return
	}
}

// ImportState supports importing via "watch_name:policy_name:policy_type" with an
// optional trailing ":project_key".
func (r *WatchPolicyAttachmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, ":")

	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected import identifier with format: watch_name:policy_name:policy_type[:project_key]. Got: %q", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("watch_name"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_name"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_type"), parts[2])...)

	if len(parts) == 4 && parts[3] != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project_key"), parts[3])...)
	}
}
