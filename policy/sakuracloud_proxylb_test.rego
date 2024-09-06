package main

import data.test.helpers.no_violations

test_not_specified_redirect_to_https {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol    = "http"
    delay_loop  = 10
    host_header = "example.com"
    path        = "/"
  }

  bind_port {
    proxy_mode = "http"
    port       = 80
  }
}`)
	violation_sakuracloud_proxylb_no_https_redirect[{
		"msg": "sakuracloud_proxylb_no_https_redirect\nHTTP to HTTPS redirect is not enabled on sakuracloud_proxylb.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/no_https_redirect/\n",
		"resource": "sakuracloud_proxylb",
		"rule": "sakuracloud_proxylb_no_https_redirect",
	}] with input as cfg
}

test_disable_redirect_to_https {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol    = "http"
    delay_loop  = 10
    host_header = "example.com"
    path        = "/"
  }

  bind_port {
    proxy_mode        = "http"
    port              = 80
    redirect_to_https = false
  }
}`)
	violation_sakuracloud_proxylb_no_https_redirect[{
		"msg": "sakuracloud_proxylb_no_https_redirect\nHTTP to HTTPS redirect is not enabled on sakuracloud_proxylb.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/no_https_redirect/\n",
		"resource": "sakuracloud_proxylb",
		"rule": "sakuracloud_proxylb_no_https_redirect",
	}] with input as cfg
}

test_redirect_to_https {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol   = "http"
    delay_loop = 10
    path       = "/"
  }

  bind_port {
    proxy_mode        = "http"
    port              = 80
    redirect_to_https = true
  }

  bind_port {
    proxy_mode = "https"
    port       = 443
  }
}`)
	no_violations(violation_sakuracloud_proxylb_no_https_redirect) with input as cfg
}

test_redirect_to_https_not_specified_https_bind_port {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol   = "http"
    delay_loop = 10
    path       = "/"
  }

  bind_port {
    proxy_mode        = "http"
    port              = 80
    redirect_to_https = true
  }
}`)
	no_violations(violation_sakuracloud_proxylb_no_https_redirect) with input as cfg
}

test_unspecified_syslog_host {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol   = "http"
    delay_loop = 10
    path       = "/"
  }

  bind_port {
    proxy_mode = "http"
    port       = 80
  }
}`)
	warn_sakuracloud_proxylb_unspecified_syslog_host[{
		"msg": "sakuracloud_proxylb_unspecified_syslog_host\nNo syslog server is configured for sakuracloud_proxylb.test\nMore Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_proxylb/unspecified_syslog_host/\n",
		"resource": "sakuracloud_proxylb",
		"rule": "sakuracloud_proxylb_unspecified_syslog_host",
	}] with input as cfg
}

test_specified_syslog_host {
	cfg := parse_config("hcl2", `
resource "sakuracloud_proxylb" "test" {
  name = "test"
  plan = 100

  health_check {
    protocol   = "http"
    delay_loop = 10
    path       = "/"
  }

  bind_port {
    proxy_mode = "http"
    port       = 80
  }

  syslog {
    server = "192.0.2.1"
    port   = 514
  }
}`)
	no_violations(warn_sakuracloud_proxylb_unspecified_syslog_host) with input as cfg
}
