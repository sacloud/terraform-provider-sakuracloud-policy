package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_vpc_router_internet_connection_without_firewall contains decision if {
	resource := "sakuracloud_vpc_router"
	rule := "sakuracloud_vpc_router_internet_connection_without_firewall"

	some name
	vpc_router := input.resource.sakuracloud_vpc_router[name]

	is_internet_connected(vpc_router)
	not used_firewall_global_interface(vpc_router)

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_vpc_router/internet_connection_without_firewall/"
	decision := {
		"msg": sprintf(
			"Internet connection is enabled on sakuracloud_vpc_router.%s, but no firewall is configured on the global interface\nMore Info: %s\n",
			[name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

is_internet_connected(vpc_router) if {
	not has_field(vpc_router, "internet_connection")
}

is_internet_connected(vpc_router) if {
	vpc_router.internet_connection == true
}

used_firewall_global_interface(vpc_router) if {
	vpc_router.firewall.interface_index == 0
}

used_firewall_global_interface(vpc_router) if {
	vpc_router.firewall[_].interface_index == 0
}

exception contains rules if {
	v := data.main.violation_sakuracloud_vpc_router_internet_connection_without_firewall[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.violation_sakuracloud_vpc_router_internet_connection_without_firewall[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}

warn_sakuracloud_vpc_router_unspecified_syslog_host contains decision if {
	resource := "sakuracloud_vpc_router"
	rule := "sakuracloud_vpc_router_unspecified_syslog_host"

	some name

	vpc_router := input.resource.sakuracloud_vpc_router[name]
	not has_field(vpc_router, "syslog_host")

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_vpc_router/unspecified_syslog_host/"

	decision := {
		"msg": sprintf(
			"No syslog server is configured for sakuracloud_vpc_router.%s\nMore Info: %s\n",
			[name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.warn_sakuracloud_vpc_router_unspecified_syslog_host[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.warn_sakuracloud_vpc_router_unspecified_syslog_host[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}
