---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "xray_webhook Resource - terraform-provider-xray"
subcategory: ""
description: |-
  Provides an Xray webhoook resource. See Xray Webhooks https://jfrog.com/help/r/jfrog-security-documentation/configuring-xray?section=UUID-bb7641b3-e469-e0ef-221d-c0ebf660dde1_id_ConfiguringXray-ConfiguringWebhooks and REST API https://jfrog.com/help/r/jfrog-rest-apis/xray-webhooks for more details.
---

# xray_webhook (Resource)

Provides an Xray webhoook resource. See [Xray Webhooks](https://jfrog.com/help/r/jfrog-security-documentation/configuring-xray?section=UUID-bb7641b3-e469-e0ef-221d-c0ebf660dde1_id_ConfiguringXray-ConfiguringWebhooks) and [REST API](https://jfrog.com/help/r/jfrog-rest-apis/xray-webhooks) for more details.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) An identifier for the webhook. This is the name that will be used by any Watches that want to invoke the webhook in case of a violation
- `url` (String) The URL that this webhook invokes. For details of the payload provided by Xray to the webhook, please refer to Webhook Payload.

### Optional

- `description` (String) A free text description.
- `headers` (Map of String) Any custom headers that may need to be added to invoke the webhook.. Name/value pairs.
- `password` (String) A password as required by the webhook.
- `use_proxy` (Boolean) Set the webhook to go through the predefined proxy. For more information, see [Managing Proxies](https://jfrog.com/help/r/jfrog-platform-administration-documentation/managing-proxies).
- `user_name` (String) An username as required by the webhook.

### Read-Only

- `id` (String) The ID of this resource.
