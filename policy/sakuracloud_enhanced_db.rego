package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_enhanced_db_unrestricted_source_networks[msg] {
	some name
	enhanced_db := input.resource.sakuracloud_enhanced_db[name]

	not has_field(enhanced_db, "allowed_networks")

	msg := sprintf("Source network is not restricted for sakuracloud_enhanced_db.%s connection", [name])
}
