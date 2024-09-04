package main

import data.test.helpers.no_violations

test_enable_pw_auth_with_password {
	cfg := parse_config("hcl2", `
resource "sakuracloud_server" "test" {
  name   = "test"
  disks  = [sakuracloud_disk.test.id]
  core   = 1
  memory = 1

  disk_edit_parameter {
    hostname        = "test"
    disable_pw_auth = false

    password = "password"
  }
}`)

	deny_sakuracloud_server_pw_auth_enabled_with_password["Password authentication is enabled with a password set on sakuracloud_server.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_server/pw_auth_enabled_with_password/\n"] with input as cfg
}

test_disable_pw_auth_with_ssh_key_ids {
	cfg := parse_config("hcl2", `
resource "sakuracloud_server" "test" {
  name   = "test"
  disks  = [sakuracloud_disk.test.id]
  core   = 1
  memory = 1

  disk_edit_parameter {
    hostname        = "test"
    disable_pw_auth = true

    ssh_key_ids = [resource.sakuracloud_ssh_key.user_key.id]
  }
}`)

	no_violations(deny_sakuracloud_server_pw_auth_enabled_with_password) with input as cfg
}

test_disable_pw_auth_with_password_and_ssh_key_ids {
	cfg := parse_config("hcl2", `
resource "sakuracloud_server" "test" {
  name   = "test"
  disks  = [sakuracloud_disk.test.id]
  core   = 1
  memory = 1

  disk_edit_parameter {
    hostname        = "test"
    disable_pw_auth = true

    password = "password"
    ssh_key_ids = [resource.sakuracloud_ssh_key.user_key.id]
  }
}`)

	no_violations(deny_sakuracloud_server_pw_auth_enabled_with_password) with input as cfg
}

test_not_specified_disk_edit_parameter {
	cfg := parse_config("hcl2", `
resource "sakuracloud_server" "test" {
  name   = "test"
  disks  = [sakuracloud_disk.test.id]
  core   = 1
  memory = 1
}`)

	no_violations(deny_sakuracloud_server_pw_auth_enabled_with_password) with input as cfg
}
