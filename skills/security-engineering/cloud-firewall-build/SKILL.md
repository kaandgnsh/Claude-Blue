---
name: cloud-firewall-build
description: Build cloud network access controls as code — AWS security groups and NACLs, Azure NSGs, GCP VPC firewall rules — with Terraform using least-privilege ingress/egress, references instead of CIDRs where possible, tags/ownership, plus automated policy checks (terraform validate, Checkov/Trivy, OPA conftest) that block internet-exposed admin ports before apply. Use when creating or refactoring cloud firewall rules, landing-zone network baselines, or replacing click-ops security groups.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# Cloud Firewall Build (Terraform)

Follows `secure-build-workflow`. Not executed in this repository: Terraform and cloud accounts aren't available to the test suite. Validate with the commands in section 3.

## 1. Design rules

- One security group / NSG / firewall rule set **per workload role** (web, app, db), not per instance; reference **groups/tags/service accounts** between tiers instead of CIDRs.
- Internet ingress only on load balancers/WAF (443), never directly to instances. Admin access via SSM Session Manager / Azure Bastion / IAP TCP forwarding, not 22/3389 from the internet.
- Egress: restrict where feasible (proxy/NAT with egress filtering); at minimum block egress for data tiers.
- Every rule has a description naming the purpose and ticket; resources tagged with owner.

## 2. Examples

AWS (provider ≥ 5, separate rule resources):
```hcl
resource "aws_security_group" "app" {
  name        = "app"
  description = "App tier - managed by Terraform"
  vpc_id      = var.vpc_id
  tags        = { Owner = "platform", Purpose = "app-tier" }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  description                  = "ALB to app (CHG-1234)"
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id            = aws_security_group.app.id
  referenced_security_group_id = aws_security_group.db.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "App to PostgreSQL"
}
```
Leaving out an egress rule on a Terraform-managed SG removes AWS's default allow-all egress only if you manage egress explicitly. Verify in the plan.

Azure NSG rule:
```hcl
resource "azurerm_network_security_rule" "https_from_appgw" {
  name                        = "allow-https-from-appgw"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = var.appgw_subnet_cidr
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_range      = "443"
  resource_group_name         = var.rg
  network_security_group_name = azurerm_network_security_group.web.name
}
```
GCP (target by service account, not tags, for stronger binding):
```hcl
resource "google_compute_firewall" "app_from_lb" {
  name                    = "app-from-lb"
  network                 = var.network
  direction               = "INGRESS"
  source_ranges           = ["35.191.0.0/16", "130.211.0.0/22"]   # Google LB / health-check ranges
  target_service_accounts = [google_service_account.app.email]
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}
```

## 3. Validate before apply

```sh
terraform fmt -check && terraform validate
terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
checkov -f plan.json --framework terraform_plan
trivy config .
conftest test plan.json -p policy/
```
Conftest policy (`policy/network.rego`) blocking SSH/RDP from the internet:
```rego
package main

import rego.v1

admin_ports := {22, 3389}

deny contains msg if {
  some rc in input.resource_changes
  rc.type == "aws_vpc_security_group_ingress_rule"
  rc.change.after.cidr_ipv4 == "0.0.0.0/0"
  some p in admin_ports
  rc.change.after.from_port <= p
  rc.change.after.to_port >= p
  msg := sprintf("%s exposes port %d to the internet", [rc.address, p])
}
```

## 4. Roll out and verify

Apply via CI with plan review. Verify with reachability tools (AWS Reachability/Network Access Analyzer, Azure Network Watcher, GCP Connectivity Tests) and flow logs (`netflow-analysis`). Enable flow logs on new subnets, and alert on rule changes made outside Terraform: drift detection, plus CloudTrail `AuthorizeSecurityGroupIngress` by non-pipeline principals.

## Related skills

`secure-build-workflow`, `host-firewall-build`, `iac-scanning`, `cloud-exposure-review`, `firewall-rule-review`

## References

- Terraform AWS `aws_vpc_security_group_ingress_rule`: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule
- Azure NSG overview: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
- GCP VPC firewall rules: https://cloud.google.com/firewall/docs/firewalls
- Conftest: https://www.conftest.dev/
