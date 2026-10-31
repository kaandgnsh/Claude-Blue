---
name: hardening-automation-build
description: Automate server hardening as code with Ansible (or equivalent) — idempotent roles for SSH, firewall, sysctl, auditd, packages and services that validate configs before replacing them, run safely with --check/--diff and canary batches, are tested with Molecule, and report drift. Use when rolling hardening (CIS-style baselines, the ssh/firewall builds from this category) out to many hosts, or converting manual hardening steps into repeatable automation.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# Hardening Automation Build (Ansible)

Follows `secure-build-workflow`. Not executed in this repository: Ansible isn't available to the test suite. The validation steps are in sections 4 and 5.

## 1. Role layout

```
roles/cb_hardening/
  defaults/main.yml        # variables with safe defaults (admin groups, ports)
  tasks/main.yml
  tasks/ssh.yml  tasks/firewall.yml  tasks/sysctl.yml  tasks/auditd.yml
  templates/00-cb-hardening.conf.j2  templates/firewall.nft.j2
  handlers/main.yml
  molecule/default/{molecule.yml,converge.yml,verify.yml}
```

## 2. Validate-before-replace pattern

```yaml
# tasks/ssh.yml
- name: Install hardened sshd drop-in (validated before it replaces the live file)
  ansible.builtin.template:
    src: 00-cb-hardening.conf.j2
    dest: /etc/ssh/sshd_config.d/00-cb-hardening.conf
    owner: root
    group: root
    mode: "0600"
    validate: /usr/sbin/sshd -t -f %s
  notify: Reload sshd

# tasks/firewall.yml
- name: Install nftables ruleset
  ansible.builtin.template:
    src: firewall.nft.j2
    dest: /etc/nftables.d/50-cb-filter.nft
    mode: "0600"
    validate: /usr/sbin/nft -c -f %s
  notify: Apply nftables

# tasks/sysctl.yml
- name: Kernel hardening sysctls
  ansible.posix.sysctl:
    name: "{{ item.key }}"
    value: "{{ item.value }}"
    sysctl_file: /etc/sysctl.d/60-cb-hardening.conf
    reload: true
  loop: "{{ cb_sysctls | dict2items }}"

# handlers/main.yml
- name: Reload sshd
  ansible.builtin.service:
    name: "{{ 'ssh' if ansible_facts.os_family == 'Debian' else 'sshd' }}"
    state: reloaded
- name: Apply nftables
  ansible.builtin.command: /usr/sbin/nft -f /etc/nftables.d/50-cb-filter.nft
  changed_when: true
```
- `validate: sshd -t -f %s` checks the drop-in on its own, using host keys from their default paths. Test the combined config with `sshd -t` afterwards.
- The templates can be produced by `ssh-hardening-build`/`host-firewall-build` generators in CI, or by rendering the same policy data with Jinja2.

## 3. Defaults

```yaml
# defaults/main.yml
cb_ssh_allow_groups: []          # MUST be set per inventory; role asserts non-empty
cb_sysctls:
  kernel.kptr_restrict: 2
  kernel.dmesg_restrict: 1
  kernel.yama.ptrace_scope: 1
  fs.suid_dumpable: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv6.conf.all.accept_redirects: 0
  net.ipv4.conf.all.send_redirects: 0
```
Add an `ansible.builtin.assert` at the top of `tasks/main.yml` that fails when `cb_ssh_allow_groups` is empty (lockout protection).

## 4. Safe execution

```sh
ansible-lint roles/cb_hardening
ansible-playbook site.yml --limit canary --check --diff        # dry run
ansible-playbook site.yml --limit canary                       # one host / small group first
ansible-playbook site.yml --forks 10 -e serial_batch=10%       # with `serial:` in the play and max_fail_percentage: 0
```
Keep an out-of-band access path for the canary. Use `serial` plus `max_fail_percentage: 0` so a bad change stops after the first batch.

## 5. Test with Molecule

```sh
molecule test     # create → converge → idempotence → verify → destroy (Docker/Podman driver)
```
The idempotence step fails if a second run reports changes. `verify.yml` asserts the outcomes, for example `sshd -T | grep 'passwordauthentication no'`, `nft list table inet cb_filter`, and sysctl values.

## 6. Drift

Schedule `--check --diff` runs (or AWX/Ansible Automation Platform jobs) and alert on reported changes. Also compare against CIS scans (`linux-hardening`).

## Related skills

`secure-build-workflow`, `ssh-hardening-build`, `host-firewall-build`, `linux-hardening`, `auditd-rules`

## References

- Ansible template module (`validate`): https://docs.ansible.com/ansible/latest/collections/ansible/builtin/template_module.html
- ansible.posix.sysctl: https://docs.ansible.com/ansible/latest/collections/ansible/posix/sysctl_module.html
- Molecule: https://ansible.readthedocs.io/projects/molecule/
- ansible-lockdown CIS roles: https://github.com/ansible-lockdown
