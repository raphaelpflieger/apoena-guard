#!/usr/bin/python3
"""Apoena guard reporter: this server's security facts, for the « sécurité » light of tipis-web.

Runs from two systemd timers (see ../templates). Python standard library + commands already on the box.
Tells, never listens. One question, every 2 minutes: did an admin press the status bar's refresh? Of every
answer it reads the status only.
Facts only: never an env value but the *_VERSION of an image, never a command line, a config dump or a
file's content (of a certificate: its name, end date and fingerprint). A section that cannot be read says so in `errors`: unknown never reads as clean.

    guard_report.py           prints the report (a dry run: ssh host 'python3 -' < guard_report.py)
    guard_report.py --if-asked --push    looks first: sends only if an admin pressed the refresh button
    guard_report.py --push    signs and sends it (GUARD_URL, GUARD_HOST, key in $CREDENTIALS_DIRECTORY)
"""
import collections
import concurrent.futures
import glob
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = 2
# a dry run over ssh is the plain user; the timer runs as root
AS_ROOT = [] if os.geteuid() == 0 else ['sudo', '-n']
# what the outside check knocks on: never an SSH port, a dropped connection can count as a failed login
OUTSIDE_PORTS = [21, 23, 25, 53, 80, 110, 111, 143, 179, 443, 445, 465, 587, 993, 995, 1433, 2013, 2049, 2375,
                 2376, 3000, 3128, 3300, 3301, 3306, 3333, 4369, 5000, 5050, 5432, 5601, 5900, 6379, 6380, 6381,
                 6432, 8000, 8065, 8080, 8081, 8085, 8123, 8200, 8220, 8443, 8765, 8888, 9000, 9090, 9100, 9187,
                 9200, 9222, 9300, 11211, 13423, 15672, 16452, 19999, 27017, 31648, 32154]
LOOPBACK = ('127.', '[::1]', '[::ffff:127.')
QUIET_SOCKETS = ('systemd-network', 'chronyd', 'systemd-resolve')
LOGIN_WINDOW = '7 days ago'
ACCEPTED = re.compile(r'^(\S+) .*Accepted (\S+) for (\S+) from (\S+) port \d+ ssh2(?:: \S+ (\S+))?')
FIREWALL_RULE = re.compile(r'^(.+?)\s{2,}(ALLOW|LIMIT)(?: IN| FWD)?\s+(.+?)(?:\s+#.*)?$')
CERT_DIRECTIVE = re.compile(r'^\s*ssl_(certificate|client_certificate|trusted_certificate)\s+"?([^";\s]+)"?\s*;', re.M)
PEM_CERTIFICATE = re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.S)


def run(*cmd, root=False, timeout=60, stdin=None):
    """(exit code, stdout): commands that report by their exit code, or may rightly fail."""
    prefix = AS_ROOT if root else []
    done = subprocess.run(prefix + list(cmd), capture_output=True, text=True, errors='replace', timeout=timeout,
                          input=stdin)
    return done.returncode, done.stdout


def sh(*cmd, **kwargs):
    """stdout, or a raise that turns the section unreadable. Never carries stderr into the report."""
    code, out = run(*cmd, **kwargs)
    if code != 0:
        raise RuntimeError(f'{cmd[0]} exited {code}')
    return out


def read_root(path, limit=200_000):
    """A root-only file's first bytes, None when absent."""
    if os.geteuid() == 0:
        try:
            with open(path, errors='replace') as handle:
                return handle.read(limit)
        except OSError:
            return None
    code, out = run('head', '-c', str(limit), path, root=True)
    return out if code == 0 else None


def age_h(path):
    try:
        return round((time.time() - os.path.getmtime(path)) / 3600, 1)
    except OSError:
        return None


def system():
    with open('/etc/os-release') as handle:
        release = dict(line.strip().split('=', 1) for line in handle if '=' in line)
    with open('/proc/uptime') as handle:
        uptime = float(handle.read().split()[0])
    return {'os': release.get('PRETTY_NAME', '').strip('"'), 'kernel': platform.release(),
            'uptime_h': int(uptime / 3600)}


def apt_state():
    import apt  # python3-apt, a dependency of unattended-upgrades
    security, third_party, others = [], [], 0
    cache = apt.Cache(memonly=True)  # never rewrites apt's binary cache
    for pkg in cache:
        if not (pkg.is_installed and pkg.is_upgradable):
            continue
        newer = [version for version in pkg.versions if version > pkg.installed]
        sites = {origin.site for origin in pkg.candidate.origins if origin.site}
        # any newer version in the security pocket counts, even under a higher candidate from -updates
        if any(origin.archive.endswith('-security') for version in newer for origin in version.origins):
            security.append(pkg.name)
        elif sites and not any(site.endswith('ubuntu.com') for site in sites):
            third_party.append({'pkg': pkg.name, 'installed': pkg.installed.version,
                                'candidate': pkg.candidate.version, 'site': sorted(sites)[0]})
        else:
            others += 1
    return {'security': sorted(security)[:40], 'third_party': third_party[:20], 'other_updates': others,
            'held': sorted(sh('apt-mark', 'showhold').split())[:40], 'sources': apt_sources(),
            'lists_age_h': age_h('/var/lib/apt/periodic/update-success-stamp'),
            'upgrade_age_h': age_h('/var/lib/apt/periodic/upgrade-stamp'),
            'broken': bool(sh('dpkg', '--audit').strip()), 'timers_on': apt_timers_on()}


def apt_sources():
    hosts = set()
    for path in ['/etc/apt/sources.list'] + glob.glob('/etc/apt/sources.list.d/*'):
        try:
            with open(path, errors='replace') as handle:
                for line in handle:
                    if not line.lstrip().startswith('#'):
                        hosts.update(re.findall(r'https?://(?:[^/@\s]+@)?([^/\s]+)', line))
        except OSError:
            pass
    return sorted(hosts)


def apt_timers_on():
    names = ('apt-daily.timer', 'apt-daily-upgrade.timer', 'unattended-upgrades.service')
    return all(run('systemctl', 'is-enabled', name)[0] == 0 for name in names)


def reboot():
    packages = read_root('/var/run/reboot-required.pkgs') or ''
    out = sh('needrestart', '-b', '-r', 'l', root=True) if shutil.which('needrestart') else ''
    return {'age_h': age_h('/var/run/reboot-required'), 'packages': packages.split()[:12],
            'services': re.findall(r'NEEDRESTART-SVC: (\S+)', out)[:30]}


def firewall():
    status = sh('ufw', 'status', 'verbose', root=True).splitlines()
    default = next((line for line in status if line.startswith('Default:')), '')
    allow = [f'{match[1].strip()} <- {match[3].strip()}' for match in map(FIREWALL_RULE.match, status)
             if match and not match[1].startswith('To')]
    # DOCKER-USER is absent on a box without Docker
    filtered = []
    if shutil.which('docker'):
        code, out = run('iptables', '-S', 'DOCKER-USER', root=True)
        if code == 0:
            filtered = sorted(set(re.findall(r'--(?:ctorigdstport|dport|dports) (\S+)', out)))
    return {'active': any(line == 'Status: active' for line in status),
            'deny_incoming': 'deny (incoming)' in default, 'allow': allow, 'docker_filtered_ports': filtered}


def listening():
    sockets = set()
    for line in sh('ss', '-H', '-tulnp', root=True).splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[4].startswith(LOOPBACK):
            continue
        process = re.search(r'\(\("([^"]+)"', line)
        name = process[1] if process else '?'
        if name not in QUIET_SOCKETS:
            sockets.add(f'{fields[0]} {fields[4]} {name}')
    return sorted(sockets)


def homes():
    with open('/etc/passwd') as handle:
        users = [line.split(':') for line in handle]
    return {'root': '/root', **{user[0]: user[5] for user in users if user[5].startswith('/home/')}}


def ssh():
    settings = dict(line.split(' ', 1) for line in sh('sshd', '-T', root=True).splitlines() if ' ' in line)
    keys = {}
    for user, home in homes().items():
        for name in ('authorized_keys', 'authorized_keys2'):
            code, out = run('ssh-keygen', '-lf', f'{home}/.ssh/{name}', root=True)
            if code == 0:
                keys.setdefault(user, []).extend(
                    {'fp': line.split()[1], 'comment': ' '.join(line.split()[2:-1])[:50]} for line in out.splitlines())
    return {'password': settings.get('passwordauthentication') != 'no', 'keys': keys, 'logins': logins()}


def logins():
    """Accepted logins of the window, by account, address and key: no file written, read from the journal."""
    _, out = run('journalctl', '-t', 'sshd', '-t', 'sshd-session', '-S', LOGIN_WINDOW, '-g', 'Accepted',
                 '-o', 'short-iso', '--no-pager', root=True)
    seen = collections.defaultdict(lambda: {'n': 0, 'last': None})
    for line in out.splitlines():
        match = ACCEPTED.match(line)
        if match:
            entry = seen[(match[3], match[4], match[5] or match[2])]
            entry['n'] += 1
            entry['last'] = match[1][:16]
    return [{'user': key[0], 'ip': key[1], 'key': key[2], **value} for key, value in seen.items()][:30]


def accounts():
    with open('/etc/passwd') as handle:
        users = [line.rstrip('\n').split(':') for line in handle if line.count(':') >= 6]
    return {'shell': [user[0] for user in users if not user[6].endswith(('nologin', 'false', 'sync'))],
            'uid0': [user[0] for user in users if user[2] == '0']}


def services():
    failed = sh('systemctl', '--failed', '--no-legend', '--plain', '--no-pager').splitlines()
    return {'failed': [line.split()[0] for line in failed if line.strip()][:20],
            'fail2ban': run('systemctl', 'is-active', 'fail2ban')[0] == 0}


def nginx_files():
    return ['/etc/nginx/nginx.conf'] + glob.glob('/etc/nginx/conf.d/*') + glob.glob('/etc/nginx/sites-enabled/*')


def web():
    """The TLS versions nginx enables, read from its files: nginx -T would run a config test as root."""
    protocols = set()
    for path in nginx_files():
        for value in re.findall(r'^\s*ssl_protocols\s+([^;#]+);', read_root(path) or '', re.M):
            protocols.add(' '.join(value.split()))
    return {'old_tls': sorted(value for value in protocols if re.search(r'TLSv1(\.1)?(\s|$)', value))}


def certificates():
    """What nginx serves (server) or checks clients against (trust), with end dates. Only files it names."""
    uses = {}
    for path in nginx_files():
        for directive, name in CERT_DIRECTIVE.findall(read_root(path) or ''):
            uses.setdefault(name, 'server' if directive == 'certificate' else 'trust')
    return [{'path': name[:120], 'use': use, 'certs': certificates_in(name)} for name, use in sorted(uses.items())][:40]


def certificates_in(path):
    """The file's certificates, in order. A key in the same file stays here: only CERTIFICATE blocks go to openssl."""
    found = []
    for block in PEM_CERTIFICATE.findall(read_root(path) or '')[:8]:
        code, out = run('openssl', 'x509', '-noout', '-enddate', '-subject', '-fingerprint', '-sha256', stdin=block)
        end = re.search(r'^notAfter=(.+)$', out, re.M)
        if code != 0 or not end:
            continue
        name = re.search(r'^subject=.*?CN\s*=\s*([^,/\n]+)', out, re.M)
        digest = re.search(r'^sha256 fingerprint=(\S+)$', out, re.M | re.I)
        found.append({'cn': name[1].strip()[:60] if name else None,
                      'until': time.strftime('%Y-%m-%d', time.gmtime(ssl.cert_time_to_seconds(end[1].strip()))),
                      'sha256': digest[1].replace(':', '').lower() if digest else None})
    return found


def git_tokens():
    """Checkouts whose remote carries a credential: the path, never the value."""
    roots = [path for path in ('/home', '/root', '/opt', '/srv') if os.path.exists(path)]
    found = sh('find', *roots, '-xdev', '-maxdepth', '4', '-path', '*/.git/config', '-type', 'f', root=True, timeout=45)
    return [path for path in found.split()
            if re.search(r'url\s*=\s*https?://[^/\s]+@', read_root(path, 20_000) or '')][:10]


def base_os(pid):
    """From the container's own root, through /proc: starts nothing in it, works on a distroless image."""
    for relative in ('etc/os-release', 'usr/lib/os-release'):
        text = read_root(f'/proc/{pid}/root/{relative}', 2_000)
        if text:
            match = re.search(r'^PRETTY_NAME="?([^"\n]{1,60})', text, re.M)
            if match:
                return match[1]
    return None


def docker():
    """Running containers, whitelisted fields only: `docker inspect` holds their env, it stays in this process."""
    if not shutil.which('docker'):
        return None
    ids = sh('docker', 'ps', '-q', root=True).split()
    version = sh('docker', 'version', '--format', '{{.Server.Version}}', root=True).strip()
    if not ids:
        return {'version': version, 'containers': []}
    containers = json.loads(sh('docker', 'inspect', *ids, root=True))
    images = image_details({container['Image'] for container in containers})
    return {'version': version,
            'containers': [container_facts(container, images.get(container['Image'], {})) for container in containers]}


def image_details(ids):
    """What docker still knows of these images. One can be gone while its container runs: with the
    containerd store, moving a tag deletes the old image at once, and `docker image inspect` then
    exits 1 while still listing the others."""
    _, out = run('docker', 'image', 'inspect', *sorted(ids), root=True)
    return {image['Id']: image for image in json.loads(out or '[]')}


def container_facts(container, image):
    config = image.get('Config') or {}
    env = [line for line in config.get('Env') or [] if re.match(r'^[A-Z0-9_]+_VERSION=', line)]
    public = {binding.get('HostPort')
              for bindings in ((container.get('NetworkSettings') or {}).get('Ports') or {}).values()
              for binding in bindings or [] if binding.get('HostIp') in ('', '0.0.0.0', '::')}
    pid = (container.get('State') or {}).get('Pid')
    return {'name': container['Name'].lstrip('/')[:60], 'image': (container.get('Config') or {}).get('Image', '')[:120],
            'built': (image.get('Created') or '')[:10], 'base': base_os(pid) if pid else None,
            'versions': dict(line[:60].split('=', 1) for line in env),
            'label': ((config.get('Labels') or {}).get('org.opencontainers.image.version') or '')[:40] or None,
            'root_power': bool((container.get('HostConfig') or {}).get('Privileged')) or any(
                'docker.sock' in (mount.get('Source') or '') for mount in container.get('Mounts') or []),
            'public': sorted(port for port in public if port)}


def outside():
    """Every other server, knocked from here (GUARD_SCOUT="name=ip name=ip …"): what the internet can reach."""
    targets = [token.split('=', 1) for token in os.environ.get('GUARD_SCOUT', '').split()]
    if not targets:
        return None

    def knock(job):
        name, address, port = job
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        with socket.socket(family) as probe:
            probe.settimeout(2.5)
            try:
                probe.connect((address, port))
            except OSError:
                return None
        return name, address, port

    found = {}
    jobs = [(name, address, port) for name, address in targets for port in OUTSIDE_PORTS]
    with concurrent.futures.ThreadPoolExecutor(40) as pool:
        for hit in pool.map(knock, jobs):
            if hit:
                found.setdefault(hit[0], {}).setdefault(hit[1], []).append(hit[2])
    return {'at': int(time.time()), 'servers': [name for name, _ in targets], 'open': found}


SECTIONS = {'system': system, 'apt': apt_state, 'reboot': reboot, 'firewall': firewall, 'listening': listening,
            'ssh': ssh, 'accounts': accounts, 'services': services, 'web': web, 'certificates': certificates,
            'git_tokens': git_tokens,
            'docker': docker, 'outside': outside}


def report():
    facts = {'version': VERSION, 'host': os.environ.get('GUARD_HOST') or socket.gethostname(),
             'at': int(time.time()), 'errors': {}}
    for name, section in SECTIONS.items():
        try:
            facts[name] = section()
        except Exception as error:  # the section stays unknown, the others still report
            facts['errors'][name] = type(error).__name__
    return facts


def signature(key, timestamp, body):
    return hmac.new(key.encode(), f'{timestamp}.'.encode() + body, hashlib.sha256).hexdigest()


def machine_key():
    with open(os.path.join(os.environ['CREDENTIALS_DIRECTORY'], 'key')) as handle:
        return handle.read().strip()


def asked():
    """Did an admin press the status bar's refresh since this server last reported? The status is the whole
    answer: 200 yes, anything else or no answer at all means no. The worst a forged yes can do is one report."""
    timestamp = str(int(time.time()))
    host = os.environ.get('GUARD_HOST') or socket.gethostname()
    request = urllib.request.Request(os.environ['GUARD_URL'], method='GET', headers={
        'User-Agent': f'apoena-guard/{VERSION}', 'X-Guard-Host': host, 'X-Guard-Timestamp': timestamp,
        'X-Guard-Signature': signature(machine_key(), timestamp, b'')})
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:
            return answer.status == 200
    except (urllib.error.URLError, OSError):
        return False


def push(facts, attempts=3):
    key = machine_key()
    body = json.dumps(facts, ensure_ascii=False, separators=(',', ':')).encode()
    for attempt in range(attempts):
        timestamp = str(int(time.time()))
        request = urllib.request.Request(os.environ['GUARD_URL'], data=body, method='POST', headers={
            'Content-Type': 'application/octet-stream', 'User-Agent': f'apoena-guard/{VERSION}',
            'X-Guard-Host': facts['host'], 'X-Guard-Timestamp': timestamp,
            'X-Guard-Signature': signature(key, timestamp, body)})
        try:
            with urllib.request.urlopen(request, timeout=20):
                return True  # 2xx: the answer's content is never read
        except (urllib.error.URLError, OSError) as error:
            print(f'push failed: {getattr(error, "code", type(error).__name__)}', file=sys.stderr)
            if attempt + 1 < attempts:
                time.sleep(60)
    return False


def main():
    if '--if-asked' in sys.argv and not asked():
        return 0
    facts = report()
    if '--push' not in sys.argv:
        print(json.dumps(facts, ensure_ascii=False))
        return 0
    return 0 if push(facts) else 1


if __name__ == '__main__':
    sys.exit(main())
