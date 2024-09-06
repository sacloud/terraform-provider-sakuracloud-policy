package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_server_pw_auth_enabled_with_password contains decision if {
	resource := "sakuracloud_server"
	rule := "sakuracloud_server_pw_auth_enabled_with_password"

	some name
	server := input.resource.sakuracloud_server[name]

	has_field(server.disk_edit_parameter, "password")
	server.disk_edit_parameter.disable_pw_auth == false

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_server/pw_auth_enabled_with_password/"
	decision := {
		"msg": sprintf(
			"Password authentication is enabled with a password set on sakuracloud_server.%s\nMore Info: %s\n",
			[name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.violation_sakuracloud_server_pw_auth_enabled_with_password[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.violation_sakuracloud_server_pw_auth_enabled_with_password[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}
