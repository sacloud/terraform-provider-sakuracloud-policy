package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_load_balancer_http_not_enabled contains decision if {
	resource := "sakuracloud_load_balancer"
	rule := "sakuracloud_load_balancer_http_not_enabled"

	some name
	load_balancer := input.resource[resource][name]
	load_balancer.vip.port == 80

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_load_balancer/http_not_enabled/"
	decision := {
		"msg": sprintf(
			"%s\nPort 80 is open on the VIP address of %s.%s\nMore Info: %s\n",
			[rule, resource, name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.violation_sakuracloud_load_balancer_http_not_enabled[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.violation_sakuracloud_load_balancer_http_not_enabled[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}
