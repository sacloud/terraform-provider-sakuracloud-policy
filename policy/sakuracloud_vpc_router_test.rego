package main

import data.test.helpers.no_violations

test_enable_internet_connection {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true
}
    `)
	deny_sakuracloud_vpc_router_internet_connection_without_firewall["Internet connection is enabled on sakuracloud_vpc_router.test, but no firewall is configured on the global interface\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_vpc_router/internet_connection_without_firewall/\n"] with input as cfg
}

test_enable_internet_connection_with_private_interface_firewall {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true

  firewall {
    interface_index = 1
    direction       = "receive"

    expression {
      protocol            = "tcp"
      source_network      = ""
      source_port         = "443"
      destination_network = ""
      destination_port    = ""
      allow               = true
      logging             = true
      description         = "desc"
    }

    expression {
      protocol            = "ip"
      source_network      = ""
      source_port         = ""
      destination_network = ""
      destination_port    = ""
      allow               = false
      logging             = true
      description         = "desc"
    }
  }
}
    `)
	deny_sakuracloud_vpc_router_internet_connection_without_firewall["Internet connection is enabled on sakuracloud_vpc_router.test, but no firewall is configured on the global interface\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_vpc_router/internet_connection_without_firewall/\n"] with input as cfg
}

test_enable_internet_connection_with_global_interface_firewall {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true
  firewall {
    interface_index = 0
    direction       = "receive"

    expression {
      protocol            = "tcp"
      source_network      = ""
      source_port         = "443"
      destination_network = ""
      destination_port    = ""
      allow               = true
      logging             = true
      description         = "desc"
    }

    expression {
      protocol            = "ip"
      source_network      = ""
      source_port         = ""
      destination_network = ""
      destination_port    = ""
      allow               = false
      logging             = true
      description         = "desc"
    }
  }
}
    `)
	no_violations(deny_sakuracloud_vpc_router_internet_connection_without_firewall) with input as cfg
}

test_enable_internet_connection_with_multi_interface_firewall {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true
  firewall {
    interface_index = 0
    direction       = "receive"

    expression {
      protocol            = "tcp"
      source_network      = ""
      source_port         = "443"
      destination_network = ""
      destination_port    = ""
      allow               = true
      logging             = true
      description         = "desc"
    }

    expression {
      protocol            = "ip"
      source_network      = ""
      source_port         = ""
      destination_network = ""
      destination_port    = ""
      allow               = false
      logging             = true
      description         = "desc"
    }
  }

  firewall {
    interface_index = 1
    direction       = "receive"

    expression {
      protocol            = "tcp"
      source_network      = ""
      source_port         = "443"
      destination_network = ""
      destination_port    = ""
      allow               = true
      logging             = true
      description         = "desc"
    }

    expression {
      protocol            = "ip"
      source_network      = ""
      source_port         = ""
      destination_network = ""
      destination_port    = ""
      allow               = false
      logging             = true
      description         = "desc"
    }
  }
}
    `)
	no_violations(deny_sakuracloud_vpc_router_internet_connection_without_firewall) with input as cfg
}

test_disable_internet_connection {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = false
}
    `)
	no_violations(deny_sakuracloud_vpc_router_internet_connection_without_firewall) with input as cfg
}

test_unspecified_syslog_host {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true
}
    `)
	warn_sakuracloud_vpc_router_unspecified_syslog_host["No syslog server is configured for sakuracloud_vpc_router.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_vpc_router/unspecified_syslog_host/\n"] with input as cfg
}

test_specified_syslog_host {
	cfg := parse_config("hcl2", `
resource "sakuracloud_vpc_router" "test" {
  name                = "test"
  internet_connection = true
  syslog_host         = "192.168.0.1"
}
    `)
	no_violations(warn_sakuracloud_vpc_router_unspecified_syslog_host) with input as cfg
}
