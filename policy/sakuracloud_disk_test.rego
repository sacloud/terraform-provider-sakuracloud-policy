package main

import data.test.helpers.no_violations

test_not_specified_encryption_algorithm {
	cfg := parse_config("hcl2", `
resource "sakuracloud_disk" "test" {
  name                 = "test"
  size                 = 20
  plan                 = "ssd"
  connector            = "virtio"
  source_archive_id    = data.sakuracloud_archive.ubuntu2204.id
}`)
	violation_sakuracloud_disk_not_encrypted[{
		"msg": "Disk encryption is not enabled in sakuracloud_disk.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_disk/not_encrypted/\n",
		"resource": "sakuracloud_disk",
		"rule": "sakuracloud_disk_not_encrypted",
	}] with input as cfg
}

test_specified_encryption_algorithm_none {
	cfg := parse_config("hcl2", `
resource "sakuracloud_disk" "test" {
  name                 = "test"
  size                 = 20
  plan                 = "ssd"
  connector            = "virtio"
  source_archive_id    = data.sakuracloud_archive.ubuntu2204.id
  encryption_algorithm = "none"
}`)
	violation_sakuracloud_disk_not_encrypted[{
		"msg": "Disk encryption is not enabled in sakuracloud_disk.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_disk/not_encrypted/\n",
		"resource": "sakuracloud_disk",
		"rule": "sakuracloud_disk_not_encrypted",
	}] with input as cfg
}

test_specified_encryption_algorithm_aes256_xts {
	cfg := parse_config("hcl2", `
resource "sakuracloud_disk" "test" {
  name                 = "test"
  size                 = 20
  plan                 = "ssd"
  connector            = "virtio"
  source_archive_id    = data.sakuracloud_archive.ubuntu2204.id
  encryption_algorithm = "aes256_xts"
}`)
	no_violations(violation_sakuracloud_disk_not_encrypted) with input as cfg
}
