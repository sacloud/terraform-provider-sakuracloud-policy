package main

import data.exception
import data.helpers.has_field
import rego.v1

violation_sakuracloud_proxylb_no_https_redirect contains decision if {
	resource := "sakuracloud_proxylb"
	rule := "sakuracloud_proxylb_no_https_redirect"

	some name
	proxylb := input.resource[resource][name]
	not redirect_https(proxylb)

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/no_https_redirect/"
	decision := {
		"msg": sprintf(
			"%s\nHTTP to HTTPS redirect is not enabled on %s.%s\nMore Info: %s\n",
			[rule, resource, name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

redirect_https(proxylb) if {
	proxylb.bind_port.proxy_mode == "http"
	proxylb.bind_port.redirect_to_https == true
}

redirect_https(proxylb) if {
	bind_port := proxylb.bind_port[_]

	bind_port.proxy_mode == "http"
	bind_port.redirect_to_https == true
}

exception contains rules if {
	v := data.main.violation_sakuracloud_proxylb_no_https_redirect[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.violation_sakuracloud_proxylb_no_https_redirect[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}

warn_sakuracloud_proxylb_unspecified_syslog_host contains decision if {
	resource := "sakuracloud_proxylb"
	rule := "sakuracloud_proxylb_unspecified_syslog_host"

	some name
	proxylb := input.resource[resource][name]
	not has_field(proxylb, "syslog")
	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/unspecified_syslog_host/"

	decision := {
		"msg": sprintf(
			"%s\nNo syslog server is configured for %s.%s\nMore Info: %s\n",
			[rule, resource, name, url],
		),
		"resource": resource,
		"rule": rule,
	}
}

exception contains rules if {
	v := data.main.warn_sakuracloud_proxylb_unspecified_syslog_host[_]

	input.resource[v.resource]
	exception.rule[_] == v.rule
	rules := [v.rule]
}

exception contains rules if {
	v := data.main.warn_sakuracloud_proxylb_unspecified_syslog_host[_]

	some name
	input.resource[v.resource][name]
	name == exception.resource[v.resource][_]
	rules := [v.rule]
}
