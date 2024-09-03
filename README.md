# terraform-policy

![conftest verify](https://github.com/sacloud/terraform-provider-sakuracloud-policy/actions/workflows/verify.yml/badge.svg)

This repository manages the standard policies for security and governance checks in Terraform code that utilizes the SakuraCloud provider. It leverages OPA (Open Policy Agent) and Conftest to ensure comprehensive policy enforcement.

## Usage Example
```sh
# Run within the Terraform repository that uses the Terraform SakuraCloud provider
$ cd terraform

# Download the policy
$ conftest pull 'git@github.com:sacloud/terraform-provider-sakuracloud-policy.git//policy?ref=v1.0.0'

# Run the tests
$ conftest test . --ignore=".git/|.github/|.terraform/"
```

## Requirements
[Open Policy Agent](https://www.openpolicyagent.org/) v0.68.0+

[Conftest](https://www.conftest.dev/) v0.55.0+

[Terraform provider for SakuraCloud](https://registry.terraform.io/providers/sacloud/sakuracloud/latest) v2.25.4+

## License

`terraform-proivder-sakuracloud-policy` Copyright (C) 2024-2024 terraform-provider-sakuracloud-policy authors.

This project is published under [Apache 2.0 License](LICENSE).
