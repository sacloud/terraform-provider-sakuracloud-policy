package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_proxylb_no_https_redirect[msg] {
	some name
	proxylb := input.resource.sakuracloud_proxylb[name]
	not redirect_https(proxylb)

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/no_https_redirect/"
	msg := sprintf(
		"HTTP to HTTPS redirect is not enabled on sakuracloud_proxylb.%s\nMore Info: %s\n",
		[name, url],
	)
}

redirect_https(proxylb) {
	proxylb.bind_port.proxy_mode == "http"
	proxylb.bind_port.redirect_to_https == true
}

redirect_https(proxylb) {
	bind_port := proxylb.bind_port[_]

	bind_port.proxy_mode == "http"
	bind_port.redirect_to_https == true
}

warn_sakuracloud_proxylb_unspecified_syslog_host[msg] {
	some name
	proxylb := input.resource.sakuracloud_proxylb[name]
	not has_field(proxylb, "syslog")

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/unspecified_syslog_host/"
	msg := sprintf(
		"No syslog server is configured for sakuracloud_proxylb.%s\nMore Info: %s\n",
		[name, url],
	)
}
