"""The reporter's parsing and what must never leave a server. No server needed: python3 -m unittest"""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).parent.parent / 'files' / 'guard_report.py'
spec = importlib.util.spec_from_file_location('guard_report', SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

UFW = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
34127                      ALLOW IN    Anywhere
19999/tcp                  ALLOW IN    162.19.24.164              # netdata
22                         DENY IN     Anywhere
Anywhere                   REJECT IN   92.4.87.225
34127 (v6)                 ALLOW IN    Anywhere (v6)
"""
SS = """tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 4096 127.0.0.1:8125 0.0.0.0:* users:(("netdata",pid=2,fd=3))
tcp   LISTEN 0 4096 [::]:8220 [::]:* users:(("docker-proxy",pid=3,fd=3))
udp   UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
udp   UNCONN 0 0 51.210.105.166%ens3:68 0.0.0.0:* users:(("systemd-network",pid=4,fd=3))
"""


class ParsingTest(unittest.TestCase):
    def test_firewall_keeps_allow_rules_only_and_no_comment(self):
        with mock.patch.object(guard, 'sh', return_value=UFW), mock.patch.object(guard.shutil, 'which', return_value=None):
            facts = guard.firewall()
        self.assertTrue(facts['active'])
        self.assertTrue(facts['deny_incoming'])
        self.assertEqual(facts['allow'], ['34127 <- Anywhere', '19999/tcp <- 162.19.24.164', '34127 (v6) <- Anywhere (v6)'])

    def test_firewall_says_so_when_inactive_or_not_denying(self):
        off = 'Status: inactive\n'
        with mock.patch.object(guard, 'sh', return_value=off), mock.patch.object(guard.shutil, 'which', return_value=None):
            self.assertFalse(guard.firewall()['active'])
        open_door = UFW.replace('deny (incoming)', 'allow (incoming)')
        with mock.patch.object(guard, 'sh', return_value=open_door), mock.patch.object(guard.shutil, 'which', return_value=None):
            self.assertFalse(guard.firewall()['deny_incoming'])

    def test_listening_drops_loopback_and_quiet_sockets(self):
        with mock.patch.object(guard, 'sh', return_value=SS):
            self.assertEqual(guard.listening(), ['tcp 0.0.0.0:22 sshd', 'tcp [::]:8220 docker-proxy', 'udp 0.0.0.0:51820 ?'])

    def test_logins_are_grouped_with_their_key(self):
        out = ('2026-11-03T02:00:35+0100 h sshd[1]: Accepted publickey for ubuntu from 82.67.205.71 port 5 ssh2: ED25519 SHA256:abc\n'
               '2026-11-03T03:00:35+0100 h sshd[2]: Accepted publickey for ubuntu from 82.67.205.71 port 6 ssh2: ED25519 SHA256:abc\n')
        with mock.patch.object(guard, 'run', return_value=(0, out)):
            self.assertEqual(guard.logins(), [{'user': 'ubuntu', 'ip': '82.67.205.71', 'key': 'SHA256:abc', 'n': 2, 'last': '2026-11-03T03:00'}])

    def test_old_tls_is_only_tls_1_0_and_1_1_and_no_other_directive_leaves(self):
        config = 'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n  ssl_protocols TLSv1.2 TLSv1.3;\n# ssl_protocols SSLv3;\nsecret_thing hunter2;\n'
        with mock.patch.object(guard.glob, 'glob', return_value=[]), mock.patch.object(guard, 'read_root', return_value=config):
            self.assertEqual(guard.web(), {'old_tls': ['TLSv1 TLSv1.1 TLSv1.2']})


class CertificatesTest(unittest.TestCase):
    NGINX = '''
    ssl_certificate "/etc/nginx/ssl/site.crt";
    ssl_certificate_key "/etc/nginx/ssl/site.key";
    ssl_client_certificate /etc/nginx/ssl/pull_ca.pem;
    # ssl_certificate /etc/nginx/ssl/old.crt;
    ssl_trusted_certificate /etc/nginx/ssl/gone.pem;
    '''
    PEM = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'
    KEY = '-----BEGIN PRIVATE KEY-----\nhunter2\n-----END PRIVATE KEY-----\n'
    OPENSSL = ('notAfter=Nov  1 17:00:00 2029 GMT\n'
               'subject=C = US, O = "CloudFlare, Inc.", CN = origin-pull.cloudflare.net\n'
               'sha256 Fingerprint=9A:1A:C2\n')

    def read(self, path, limit=0):
        files = {'/etc/nginx/nginx.conf': self.NGINX, '/etc/nginx/ssl/site.crt': self.KEY + self.PEM + self.PEM,
                 '/etc/nginx/ssl/pull_ca.pem': self.PEM}
        return files.get(path)

    def facts(self):
        with mock.patch.object(guard.glob, 'glob', return_value=[]), \
             mock.patch.object(guard, 'read_root', side_effect=self.read), \
             mock.patch.object(guard, 'run', return_value=(0, self.OPENSSL)) as openssl:
            return guard.certificates(), openssl

    def test_each_file_nginx_names_once_with_its_use_and_never_a_commented_one(self):
        facts, _ = self.facts()
        self.assertEqual([(item['path'], item['use']) for item in facts],
                         [('/etc/nginx/ssl/gone.pem', 'trust'), ('/etc/nginx/ssl/pull_ca.pem', 'trust'),
                          ('/etc/nginx/ssl/site.crt', 'server')])

    def test_the_facts_of_a_certificate(self):
        facts, _ = self.facts()
        self.assertEqual(facts[1]['certs'],
                         [{'cn': 'origin-pull.cloudflare.net', 'until': '2029-11-01', 'sha256': '9a1ac2'}])

    def test_every_certificate_of_a_file_counts_and_a_missing_file_says_none(self):
        facts, _ = self.facts()
        self.assertEqual(len(facts[2]['certs']), 2)
        self.assertEqual(facts[0]['certs'], [])

    def test_a_key_in_the_same_file_never_reaches_openssl_or_the_report(self):
        facts, openssl = self.facts()
        self.assertNotIn('hunter2', json.dumps(facts))
        self.assertTrue(all('hunter2' not in call.kwargs['stdin'] for call in openssl.call_args_list))

    def test_a_block_openssl_refuses_is_left_out(self):
        with mock.patch.object(guard, 'read_root', return_value=self.PEM), \
             mock.patch.object(guard, 'run', return_value=(1, '')):
            self.assertEqual(guard.certificates_in('/x'), [])


class NothingSecretLeavesTest(unittest.TestCase):
    def container(self):
        return {'Name': '/app', 'Image': 'sha256:1', 'Config': {'Image': 'x:1', 'Env': ['DATABASE_PASSWORD=hunter2'], 'Cmd': ['--token=hunter2']},
                'State': {'Pid': 0}, 'HostConfig': {'Privileged': False}, 'Mounts': [],
                'NetworkSettings': {'Ports': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}, {'HostIp': '127.0.0.1', 'HostPort': '81'}]}}}

    def image(self):
        return {'Id': 'sha256:1', 'Created': '2026-01-02T00:00:00Z',
                'Config': {'Env': ['PG_VERSION=18.6', 'API_SECRET=hunter2', 'SOME_VERSION_TOKEN=hunter2', 'PATH=/bin'], 'Labels': {'secret': 'hunter2'}}}

    def test_a_containers_env_command_and_labels_never_reach_the_report(self):
        facts = guard.container_facts(self.container(), self.image())
        self.assertNotIn('hunter2', json.dumps(facts))
        self.assertEqual(facts['versions'], {'PG_VERSION': '18.6'})
        self.assertEqual(facts['public'], ['8080'])
        self.assertFalse(facts['root_power'])

    def test_the_docker_socket_or_privileged_is_root_power(self):
        with_socket = {**self.container(), 'Mounts': [{'Source': '/var/run/docker.sock'}]}
        self.assertTrue(guard.container_facts(with_socket, self.image())['root_power'])
        privileged = {**self.container(), 'HostConfig': {'Privileged': True}}
        self.assertTrue(guard.container_facts(privileged, self.image())['root_power'])

    def test_a_git_token_is_named_by_path_never_by_value(self):
        with mock.patch.object(guard, 'sh', return_value='/home/ubuntu/app/.git/config\n'), \
             mock.patch.object(guard, 'read_root', return_value='url = https://x:ghp_hunter2@github.com/a/b.git'):
            self.assertEqual(guard.git_tokens(), ['/home/ubuntu/app/.git/config'])


class ReportTest(unittest.TestCase):
    def test_a_section_that_fails_is_named_and_the_others_still_report(self):
        def broken():
            raise RuntimeError('ufw exited 1 hunter2')

        with mock.patch.dict(guard.SECTIONS, {'firewall': broken, 'system': lambda: {'os': 'x'}}, clear=True):
            facts = guard.report()
        self.assertEqual(facts['errors'], {'firewall': 'RuntimeError'})
        self.assertEqual(facts['system'], {'os': 'x'})
        self.assertNotIn('firewall', {key for key in facts if key != 'errors'})
        self.assertNotIn('hunter2', json.dumps(facts))

    def test_the_signature_is_what_tipis_web_checks(self):
        self.assertEqual(guard.signature('k', '100', b'{}'),
                         __import__('hmac').new(b'k', b'100.{}', 'sha256').hexdigest())

    def looking(self, status=None, error=None):
        answer = mock.MagicMock(status=status)
        answer.__enter__.return_value = answer
        with tempfile.TemporaryDirectory() as folder:
            pathlib.Path(folder, 'key').write_text('k\n')
            env = {'CREDENTIALS_DIRECTORY': folder, 'GUARD_URL': 'https://x/fleet_reports', 'GUARD_HOST': 'venus-2'}
            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(guard.urllib.request, 'urlopen', return_value=answer, side_effect=error) as opened:
                return guard.asked(), opened

    def test_only_a_200_means_asked(self):
        self.assertTrue(self.looking(status=200)[0])
        self.assertFalse(self.looking(status=204)[0])
        self.assertFalse(self.looking(error=guard.urllib.error.URLError('down'))[0])
        self.assertFalse(self.looking(error=OSError('reset'))[0])

    def test_the_question_is_a_signed_get_with_an_empty_body(self):
        request = self.looking(status=204)[1].call_args.args[0]
        self.assertEqual('GET', request.get_method())
        self.assertIsNone(request.data)
        self.assertEqual('venus-2', request.get_header('X-guard-host'))
        timestamp = request.get_header('X-guard-timestamp')
        self.assertEqual(guard.signature('k', timestamp, b''), request.get_header('X-guard-signature'))

    def test_not_asked_means_no_report_at_all_and_a_clean_exit(self):
        with mock.patch.object(guard, 'asked', return_value=False), mock.patch.object(guard, 'report') as report, \
             mock.patch.object(guard.sys, 'argv', ['guard-report', '--if-asked', '--push']):
            self.assertEqual(0, guard.main())
        report.assert_not_called()

    def test_asked_reports_and_pushes(self):
        with mock.patch.object(guard, 'asked', return_value=True), mock.patch.object(guard, 'report', return_value={}), \
             mock.patch.object(guard, 'push', return_value=True) as pushed, \
             mock.patch.object(guard.sys, 'argv', ['guard-report', '--if-asked', '--push']):
            self.assertEqual(0, guard.main())
        pushed.assert_called_once()

    def test_the_timer_alone_never_looks(self):
        with mock.patch.object(guard, 'asked') as looked, mock.patch.object(guard, 'report', return_value={}), \
             mock.patch.object(guard, 'push', return_value=True), \
             mock.patch.object(guard.sys, 'argv', ['guard-report', '--push']):
            self.assertEqual(0, guard.main())
        looked.assert_not_called()

    def test_an_outside_check_only_runs_where_asked(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(guard.outside())


if __name__ == '__main__':
    unittest.main()
