package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_load_balancer_http_not_enabled[msg] {
	some name
	load_balancer := input.resource.sakuracloud_load_balancer[name]
	load_balancer.vip.port == 80

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_load_balancer/http_not_enabled/"
	msg := sprintf(
		"Port 80 is open on the VIP address of sakuracloud_load_balancer.%s\nMore Info: %s\n",
		[name, url],
	)
}
