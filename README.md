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
$ conftest pull 'git::https://github.com/sacloud/terraform-provider-sakuracloud-policy.git//policy?ref=v1.1.0'

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
        run: conftest pull 'git::https://github.com/sacloud/terraform-provider-sakuracloud-policy.git//policy?ref=v1.1.0'

      - name: run test
        run: conftest test . --ignore=".git/|.github/|.terraform/" --data="exception.json"
```

## Requirements
[Open Policy Agent](https://www.openpolicyagent.org/) v0.68.0+

[Conftest](https://www.conftest.dev/) v0.55.0+

[Terraform provider for SakuraCloud](https://registry.terraform.io/providers/sacloud/sakuracloud/latest) v2.25.4+

## License

`terraform-proivder-sakuracloud-policy` Copyright (C) 2024-2024 terraform-provider-sakuracloud-policy authors.

This project is published under [Apache 2.0 License](LICENSE).
