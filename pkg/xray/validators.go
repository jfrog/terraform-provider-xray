package xray

import (
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

var matchesHoursMinutesTime = validation.ToDiagFunc(
	validation.StringMatch(regexp.MustCompile(`^([0-1][0-9]|[2][0-3]):([0-5][0-9])$`), "Wrong format input, expected valid hour:minutes (HH:mm) form"),
)
