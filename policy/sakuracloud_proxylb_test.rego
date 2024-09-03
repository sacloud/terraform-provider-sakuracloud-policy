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
	deny_sakuracloud_proxylb_no_https_redirect["HTTP to HTTPS redirect is not enabled on sakuracloud_proxylb.test"] with input as cfg
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
	deny_sakuracloud_proxylb_no_https_redirect["HTTP to HTTPS redirect is not enabled on sakuracloud_proxylb.test"] with input as cfg
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
	no_violations(deny_sakuracloud_proxylb_no_https_redirect) with input as cfg
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
	no_violations(deny_sakuracloud_proxylb_no_https_redirect) with input as cfg
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
	warn_sakuracloud_proxylb_unspecified_syslog_host["No syslog server is configured for sakuracloud_proxylb.test"] with input as cfg
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
