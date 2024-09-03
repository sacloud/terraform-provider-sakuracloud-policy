package main

import data.exception
import data.helpers.has_field

deny_sakuracloud_disk_not_encrypted[msg] {
	some name
	disk := input.resource.sakuracloud_disk[name]
	not disk.encryption_algorithm == "aes256_xts"

	msg := sprintf("Disk encryption is not enabled in sakuracloud_disk.%s", [name])
}
