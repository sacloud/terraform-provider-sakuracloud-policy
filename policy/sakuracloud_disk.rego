package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_disk_not_encrypted contains decision if {
	resource := "sakuracloud_disk"
	rule := "sakuracloud_disk_not_encrypted"

	some name
	disk := input.resource[resource][name]
	not disk.encryption_algorithm == "aes256_xts"

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_disk/not_encrypted/"
	decision := {
		"msg": sprintf(
			"%s\nDisk encryption is not enabled in %s.%s\nMore Info: %s\n",
			[rule, resource, name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.violation_sakuracloud_disk_not_encrypted[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}
