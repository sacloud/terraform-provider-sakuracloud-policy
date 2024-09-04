package main

import data.test.helpers.no_violations

test_not_specified_allowed_networks {
	cfg := parse_config("hcl2", `
resource "sakuracloud_enhanced_db" "test" {
  name     = "test"
  password = "password"

  database_name = "testdb"
  database_type = "tidb"
  region        = "is1"
}`)

	deny_sakuracloud_enhanced_db_unrestricted_source_networks["Source network is not restricted for sakuracloud_enhanced_db.test connection\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_enhanced_db/unrestricted_source_networks/\n"] with input as cfg
}

test_specified_allowed_networks {
	cfg := parse_config("hcl2", `
resource "sakuracloud_enhanced_db" "test" {
  name     = "test"
  password = "password"

  database_name = "testdb"
  database_type = "tidb"
  region        = "is1"

  allowed_networks = [
    "192.0.2.0/24"
  ]
}`)

	no_violations(deny_sakuracloud_enhanced_db_unrestricted_source_networks) with input as cfg
}
