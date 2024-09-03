package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_vpc_router_internet_connection_without_firewall[msg] {
	some name
	vpc_router := input.resource.sakuracloud_vpc_router[name]

	is_internet_connected(vpc_router)
	not used_firewall_global_interface(vpc_router)

	msg := sprintf("Internet connection is enabled on sakuracloud_vpc_router.%s, but no firewall is configured on the global interface", [name])
}

is_internet_connected(vpc_router) {
	not has_field(vpc_router, "internet_connection")
}

is_internet_connected(vpc_router) {
	vpc_router.internet_connection == true
}

used_firewall_global_interface(vpc_router) {
	vpc_router.firewall.interface_index == 0
}

used_firewall_global_interface(vpc_router) {
	vpc_router.firewall[_].interface_index == 0
}

warn_sakuracloud_vpc_router_unspecified_syslog_host[msg] {
	some name

	vpc_router := input.resource.sakuracloud_vpc_router[name]
	not has_field(vpc_router, "syslog_host")

	msg := sprintf("No syslog server is configured for sakuracloud_vpc_router.%s", [name])
}
