resource "xray_webhook" "my-webhook" {
	name        = "MyWebhook"
	description = "My webhook description"
	url         = "https://tempurl.org"
	use_proxy   = false
	user_name   = "my_user_1"
	password    = "my_user_password"

	headers = {
		header1_name = "header1_value"
		header2_name = "header2_value"
	}
}