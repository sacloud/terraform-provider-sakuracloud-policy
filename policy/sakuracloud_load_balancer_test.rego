package main

import data.test.helpers.no_violations

test_enable_http_port {
	cfg := parse_config("hcl2", `
resource "sakuracloud_load_balancer" "test" {
  name = "test"
  plan = "standard"
  network_interface {
    switch_id    = sakuracloud_switch.fail_switch_1.id
    vrid         = 1
    ip_addresses = ["192.168.0.101"]
    netmask      = 24
    gateway      = "192.168.0.1"
  }
  vip {
    vip  = "192.168.0.201"
    port = 80

    server {
      ip_address = "192.168.0.51"
      protocol   = "http"
      path       = "/health"
      status     = 200
    }

    server {
      ip_address = "192.168.0.52"
      protocol   = "http"
      path       = "/health"
      status     = 200
    }
  }
}`)
	violation_sakuracloud_load_balancer_http_not_enabled[{
		"msg": "sakuracloud_load_balancer_http_not_enabled\nPort 80 is open on the VIP address of sakuracloud_load_balancer.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_load_balancer/http_not_enabled/\n",
		"resource": "sakuracloud_load_balancer",
		"rule": "sakuracloud_load_balancer_http_not_enabled",
	}] with input as cfg
}

test_enable_https_port {
	cfg := parse_config("hcl2", `
resource "sakuracloud_load_balancer" "test" {
  name = "test"
  plan = "standard"
  network_interface {
    switch_id    = sakuracloud_switch.test.id
    vrid         = 1
    ip_addresses = ["192.168.0.101"]
    netmask      = 24
    gateway      = "192.168.0.1"
  }
  vip {
    vip  = "192.168.0.201"
    port = 443

    server {
      ip_address = "192.168.0.51"
      protocol   = "https"
      path       = "/health"
      status     = 200
    }

    server {
      ip_address = "192.168.0.52"
      protocol   = "https"
      path       = "/health"
      status     = 200
    }
  }
}`)
	no_violations(violation_sakuracloud_load_balancer_http_not_enabled) with input as cfg
}

test_not_specified_vip {
	cfg := parse_config("hcl2", `
resource "sakuracloud_load_balancer" "test" {
  name = "test"
  plan = "standard"
  network_interface {
    switch_id    = sakuracloud_switch.fail_switch_1.id
    vrid         = 1
    ip_addresses = ["192.168.0.101"]
    netmask      = 24
    gateway      = "192.168.0.1"
  }
}`)
	no_violations(violation_sakuracloud_load_balancer_http_not_enabled) with input as cfg
}
