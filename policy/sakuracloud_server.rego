package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_server_pw_auth_enabled_with_password[msg] {
	some name
	server := input.resource.sakuracloud_server[name]

	has_field(server.disk_edit_parameter, "password")
	server.disk_edit_parameter.disable_pw_auth == false

	msg := sprintf("Password authentication is enabled with a password set on sakuracloud_server.%s", [name])
}
