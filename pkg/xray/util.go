package xray

import (
	"fmt"

	"github.com/go-resty/resty/v2"
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
