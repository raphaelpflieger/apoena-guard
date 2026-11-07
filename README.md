# apoena-guard

Fleet-wide tools, one small playbook each: the reporter behind the « sécurité » light of tipis-web
(`/admin_panel/monitoring_page`), and the routine patching of every server (`patch.yml`). The rules, the
panel and the policy live in tipis-web; the light says what is owed, this repo does it. Runbook of the
light: `tipis-web/.claude/skills/deployment-ops/references/observability.md`.

## The reporter
`files/guard_report.py`: Python standard library plus commands already on the box. Every 6 hours and at
boot it reads this server's security facts and POSTs them, signed with the machine's own key. It listens
on nothing and reads only the status of its requests. No env value but an image's `*_VERSION`, no command
line, no config dump, no file content. A scout (`guard_scouts`) also knocks on the other servers and sends
what answered with the ports it knocked, so tipis-web can tell a blinded scout from closed doors.
`VERSION` goes up with every change: tipis-web shows a server left on an older one (`REPORTER_VERSION`).

Every 2 minutes `guard-report-asked.timer` makes one signed `GET`: has an admin pressed the refresh button of
tipis-web's status bar since this server last reported? 200 = report now, anything else or no answer = nothing.
That is the one bit a server takes from outside, and the worst a forged yes can do is one more report. Hence no
port, no key on the app's side, no way in. The app needs the `GET` route first; before it, a server just hears 404.

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
5. For `patch.yml`: its place in `hosts` sets its turn; a reboot that takes a service down puts it in
   `[patch_critical]`, a slow boot or a backup timer goes in `host_vars/<it>.yml`.

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

## Patch the fleet
`patch.yml`: apt dist-upgrade, then a reboot where the server asks for one (`/var/run/reboot-required`).
Kernels, openssh and Docker never come through unattended-upgrades (`51-*-overrides`): this is their way in,
when the light shows them. Each server's own repo keeps its `--tags os-upgrade` for building a server. No vault.

    ansible-playbook patch.yml --limit apoena-proxies-14 --check   # what apt would install; nothing changes
    ansible-playbook patch.yml --limit apoena-proxies-14            # one server
    ansible-playbook patch.yml                                      # all but the critical ones, one by one
    ansible-playbook patch.yml --limit tipis-db-1                   # a critical one: alone, its own window

- One server at a time: the proxies, the autocomplete servers, hermes-2, athena-2, neptune-2 (the reverse of
  `hosts`). The first failure stops the run; the servers after it are untouched.
- Before a reboot: `sshd -t` and a new SSH connection (an openssh upgrade locked the fleet out on 2026-05-17),
  no unit newly failed, no backup running (`patch_busy_units`), and the `restart: always` containers stopped
  with their own signal (live-restore skips `docker stop` at shutdown). `unless-stopped` ones are left running:
  stopped by hand, they would not come back.
- After it: the newest kernel runs, the same containers run (none starting or unhealthy), no unit newly
  failed, and a fresh report goes to the light.
- Critical servers (`[patch_critical]` in `hosts`: erinye-3, tipis-db-1, venus-2) run only when alone in the
  run, and ask before rebooting. For erinye-3 and tipis-db-1 (`patch_maintenance`), the play takes tipis-web's
  deploy lock, turns `tipis-maintenance` on (nginx on erinye-3 boots with it), waits for
  `127.0.0.1:8089/health/ready` = 200, turns it off, releases the lock. For tipis-db-1, Sidekiq waits too
  (jobs stay in Redis; many are `retry: 0`), behind a 30-min timer on erinye-3 (`apoena-patch-sidekiq`) that
  starts it again if the run dies: the status sweep is a Sidekiq job, and with it back a maintenance left on
  turns the « rails » light red, which mails.
- The maintenance page covers erinye-3's boot-to-ready minutes, not the minutes its nginx is down
  (Cloudflare's own 52x page then).

## Netdata and Docker
`netdata_no_docker.yml` takes Netdata out of the `docker` group, which equals root, and restarts it where
the group was removed. No vault. Netdata's installer adds the group back: rerun after any Netdata reinstall.
Container charts are then named after the container's ID and start empty at every deploy, so tipis-web's
monitoring page reads per-process charts (`app.*`), never a `cgroup_*` one.

## Tests
    python3 -m unittest discover tests
