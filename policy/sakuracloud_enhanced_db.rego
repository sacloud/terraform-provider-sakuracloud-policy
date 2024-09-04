package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_enhanced_db_unrestricted_source_networks[msg] {
	some name
	enhanced_db := input.resource.sakuracloud_enhanced_db[name]

	not has_field(enhanced_db, "allowed_networks")

	url := "https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_enhanced_db/unrestricted_source_networks/"
	msg := sprintf(
		"Source network is not restricted for sakuracloud_enhanced_db.%s connection\nMore Info: %s\n",
		[name, url],
	)
}
