package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_enhanced_db_unrestricted_source_networks contains decision if {
	resource := "sakuracloud_enhanced_db"
	rule := "sakuracloud_enhanced_db_unrestricted_source_networks"

	some name
	enhanced_db := input.resource[resource][name]

	not has_field(enhanced_db, "allowed_networks")

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_enhanced_db/unrestricted_source_networks/"
	decision := {
		"msg": sprintf(
			"%s\nSource network is not restricted for %s.%s connection\nMore Info: %s\n",
			[rule, resource, name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.violation_sakuracloud_enhanced_db_unrestricted_source_networks[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.violation_sakuracloud_enhanced_db_unrestricted_source_networks[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}
