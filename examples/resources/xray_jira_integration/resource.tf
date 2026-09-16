# Jira Cloud integration
resource "xray_jira_integration" "cloud" {
  connection_name   = "prod-jira-cloud"
  jira_server_url   = "https://myorg.atlassian.net"
  installation_type = "cloud"
  username          = "security-bot@myorg.com"
  password          = var.jira_api_token
}

# Self-hosted Jira Server integration
resource "xray_jira_integration" "on_prem" {
  connection_name   = "staging-jira-server"
  jira_server_url   = "https://jira.internal.myorg.com"
  installation_type = "server"
  username          = "xray-service"
  password          = var.jira_server_password
  skip_proxy        = true
}
