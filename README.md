# terraform-policy

![conftest verify](https://github.com/sacloud/terraform-provider-sakuracloud-policy/actions/workflows/verify.yml/badge.svg)

This repository manages the standard policies for security and governance checks in Terraform code that utilizes the SakuraCloud provider. It leverages OPA (Open Policy Agent) and Conftest to ensure comprehensive policy enforcement.

## Usage Example

This assumes that OPA and Conftest are installed in the execution environment.

- https://www.openpolicyagent.org/docs/latest/#running-opa
- https://www.conftest.dev/install/

### Usage in Local Environment

This is the method for Terraform code implementers to run the policy checks in their local environment.

As mentioned earlier, OPA and Conftest must be installed in the local environment.

```sh
# Run within the Terraform repository that uses the Terraform SakuraCloud provider
$ cd terraform

# Download the policy
$ conftest pull 'git::https://github.com/sacloud/terraform-provider-sakuracloud-policy.git//policy?ref=v1.2.0'

# Run the tests
$ conftest test . --ignore=".git/|.github/|.terraform/"
```

### GitHub Actions

This is the method to perform CI (Continuous Integration) using [GitHub Actions](https://docs.github.com/ja/actions).

```yaml
name: conftest terraform policy check
on:
  pull_request:
env:
  CONFTEST_VERSION: 0.55.0
jobs:
  test:
    name: policy check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Conftest
        run: |
          mkdir -p $HOME/.local/bin
          echo "$HOME/.local/bin" >> $GITHUB_PATH
          wget -O - 'https://github.com/open-policy-agent/conftest/releases/download/v${{ env.CONFTEST_VERSION }}/conftest_${{ env.CONFTEST_VERSION }}_Linux_x86_64.tar.gz' | tar zxvf - -C $HOME/.local/bin

      - name: Conftest version
        run: conftest -v

      - name: download policy
        run: conftest pull 'git::https://github.com/sacloud/terraform-provider-sakuracloud-policy.git//policy?ref=v1.2.0'

      - name: run test
        run: conftest test . --ignore=".git/|.github/|.terraform/" --data="exception.json"
```

## Exception
You can use the Exception feature in Conftest to treat specific rules as exceptions.

In the Conftest execution environment, add a YAML file like the one below. This file should list the names of the rules that you want to treat as exceptions.

```yaml
exception:
  rule:
    - sakuracloud_disk_not_encrypted
```

Then, use the [--data](https://www.conftest.dev/options/#-data) option with the `conftest test` command to load the above file.

This will cause the listed rules to be counted as exceptions, not failures.

```sh
$ conftest test disk.tf --ignore=".git/|.github/|.terraform/" --data="exception.yml"
EXCP - disk.tf - main - data.main.exception[_][_] == "sakuracloud_disk_not_encrypted"

8 tests, 7 passed, 0 warnings, 0 failures, 1 exception
```

## Custom Policies
In addition to the default policies provided, users can add their own custom policies.

For example, by incorporating organization-specific rules, you can ensure that your infrastructure adheres to your organization’s unique policies and guidelines.

### 1. Creating a Custom Policy
Prepare a `.rego` file where you define the custom policy. It is assumed that this file will be managed in the same repository as the Terraform code.

Below is an example of creating a file named `/custom-policy/sakuracloud_disk_too_small.rego`.

This example defines a custom policy that returns an error when the disk size is less than 40GB.

```rego
package main

import data.helpers.has_field
import rego.v1

deny_sakuracloud_disk_too_small contains msg if {
    resource := "sakuracloud_disk"
    rule := "sakuracloud_disk_too_small"

    some name
    disk := input.resource[resource][name]
    disk.size < 40

    msg := sprintf(
        "%s\nDisk is too small %s.%s\n",
        [rule, resource, name],
    )
}
```

### 2. Running Custom Policies with the conftest Command

To apply custom policies in addition to the default policies, use the [--policy](https://www.conftest.dev/options/#-policy) option of the `conftest test` command as shown below.

This command applies both the default policies in the `policy/` directory and the custom policies in the `custom-policy/` directory.

```sh
$ conftest test disk.tf --ignore=".git/|.github/|.terraform/" --policy="policy/" --policy="custom-policy/"
FAIL - disk.tf - main - sakuracloud_disk_too_small
Disk is too small sakuracloud_disk.fail_disk_1

FAIL - disk.tf - main - sakuracloud_disk_not_encrypted
Disk encryption is not enabled in sakuracloud_disk.fail_disk_1
More Info: https://docs.usacloud.jp/terraform-policy/rules/sakuracloud_disk/not_encrypted/


9 tests, 7 passed, 0 warnings, 2 failures, 0 exceptions
```

## Requirements
[Open Policy Agent](https://www.openpolicyagent.org/) v0.68.0+

[Conftest](https://www.conftest.dev/) v0.55.0+

[Terraform provider for SakuraCloud](https://registry.terraform.io/providers/sacloud/sakuracloud/latest) v2.25.4+

## License

`terraform-proivder-sakuracloud-policy` Copyright (C) 2024-2024 terraform-provider-sakuracloud-policy authors.

This project is published under [Apache 2.0 License](LICENSE).
