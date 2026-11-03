# apoena-guard

Fleet-wide monitoring tools, deployed with one small playbook. Today: the reporter behind the
« sécurité » light of tipis-web (`/admin_panel/monitoring_page`). The rules, the panel and the policy
live in tipis-web; this repo only puts the script on the servers. Runbook of the light:
`tipis-web/.claude/skills/deployment-ops/references/observability.md`.

## The reporter
`files/guard_report.py`: Python standard library plus commands already on the box. Every 6 hours and at
boot it reads this server's security facts and POSTs them, signed with the machine's own key. It listens
on nothing, takes no input and reads only the status of its POST. No env value but an image's
`*_VERSION`, no command line, no config dump, no file content.

## Secret
`ansible_secrets.yml`, a vault holding one variable, `guard_report_secret`. The same value sits in
tipis-web's production credentials as `fleet_report_secret`. Each server gets SHA-256(secret + its name),
so a compromised proxy cannot report as tipis-db-1.

    ansible-vault create ansible_secrets.yml     # guard_report_secret: <openssl rand -hex 32>

## Use it
    ansible-playbook reporter.yml --ask-vault-pass --limit venus-2 --check --diff
    ansible-playbook reporter.yml --ask-vault-pass --limit venus-2
    ansible-playbook reporter.yml --ask-vault-pass --limit <host> -e guard_state=absent   # remove

On a server: `sudo systemctl status guard-report`, `sudo journalctl -u guard-report`, and a dry run that
prints the report without sending it: `sudo guard-report`. How strict the unit's sandbox ends up:
`systemd-analyze security guard-report`.

Without touching a server's disk, from here: `ssh <host> 'python3 -' < files/guard_report.py`.

## Add a server
1. A line in `hosts`, and in `Monitoring::Fleet::MACHINES` (tipis-web). Forgetting one shows by itself:
   silent = grey in the panel; unknown = refused when it pushes.
2. Its reviewed firewall rules in tipis-web's `config/security_policy.yml`.
3. Its addresses in `guard_scouts` (`group_vars/all.yml`).
4. Run the playbook with `--limit`.

## Rotate the secret
New value in the vault and in tipis-web's credentials, deploy tipis-web, rerun the playbook on all servers.
Reports are refused in between: the panel goes grey at 24 h, nothing else breaks.

## The OVH token of the light (tipis-web, not here)
Read-only, restricted to erinye-3's IP (`37.187.252.180/32`). If erinye-3 moves, OVH refuses the new address
and the OVH part of the light turns grey after 3 days: update the restriction in the OVH token settings or
create a new token (`/vps`, `/vps/*`, `/dedicated/server`, `/dedicated/server/*`, `/hosting/privateDatabase`,
`/hosting/privateDatabase/*`, GET only).

## The Cloudflare token of the light (tipis-web, not here)
`cloudflare_dns_token` in production credentials: Zone DNS Read on all zones, restricted to erinye-3's
IP. Same rule if erinye-3 moves: the DNS part of the light turns grey after 3 days.

## Netdata and Docker
`netdata_no_docker.yml` takes Netdata out of the `docker` group, which equals root, and restarts it where
the group was removed. No vault. Netdata's installer adds the group back: rerun after any Netdata reinstall.
Container charts are then named after the container's ID and start empty at every deploy, so tipis-web's
monitoring page reads per-process charts (`app.*`), never a `cgroup_*` one.

## Tests
    python3 -m unittest discover tests
