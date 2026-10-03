"""Read-only runtime gate for marked disposable guests; never probe external hosts."""
import ipaddress
import hashlib
import json
import re
import subprocess  # nosec B404 # Read-only inventory calls with a fixed executable allowlist.
import sys
import time
from pathlib import Path


def run(*args):
    if args[0] not in {'ip','sysctl','nft','ss','rspamadm','rspamd'}:
        raise ValueError('Unapproved inventory executable')
    return subprocess.check_output(args, text=True, timeout=15)  # nosec B603 # Only fixed read-only argument tuples constructed below; no shell or message input.


def validate(role):
    if role not in {"sender", "receiver", "relay"}:
        raise ValueError("Unknown role")
    if Path('/etc/peal-owned').read_text().strip() != 'PEAL-' + role:
        raise ValueError('Guest ownership marker mismatch')
    routes = json.loads(run('ip', '-j', 'route', 'show', 'table', 'all'))
    for route in routes:
        dst = route.get('dst', '')
        if dst == 'default' or route.get('gateway'):
            raise ValueError('Default/gateway route present')
        if dst and dst != 'default':
            net = ipaddress.ip_network(dst, strict=False)
            if not any(net.subnet_of(ipaddress.ip_network(allowed)) for allowed in
                       ('127.0.0.0/8', '10.77.0.0/24', '192.168.56.0/24')):
                raise ValueError('Unexpected IPv4 route')
    ipv6 = json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all'))
    if any(item.get('dst') not in ('::1', '::1/128') for item in ipv6):
        raise ValueError('Unexpected IPv6 route')
    for name, expected in (('net.ipv4.ip_forward','0'), ('net.ipv6.conf.all.forwarding','0'),
                           ('net.ipv6.conf.all.disable_ipv6','1')):
        if run('sysctl', '-n', name).strip() != expected:
            raise ValueError('Unsafe forwarding/IPv6 setting')
    rules = run('nft', 'list', 'ruleset')
    required = ('table inet peal', 'hook input priority filter; policy drop;',
                'hook forward priority filter; policy drop;', 'hook output priority filter; policy drop;',
                'iifname "enp0s3" ip saddr 192.168.56.1 tcp dport 22 accept',
                'oifname "enp0s8" ip daddr 10.77.0.20 udp dport 53 accept')
    canonical=re.sub(r'counter packets [0-9]+ bytes [0-9]+','counter packets 0 bytes 0',rules)
    # Reviewed full nft textual structure; presentation changes intentionally block pending review.
    expected_rules='e8cc965c0fc36424f8eabb2108d47790e2b8a2260fec80adbe15dfac32e24188'
    if any(item not in rules for item in required) or hashlib.sha256(canonical.encode()).hexdigest()!=expected_rules:
        raise ValueError('Firewall differs from reviewed structure; inspect full artifact')
    sockets = run('ss', '-lntup')
    if role == 'receiver':
        for endpoint in ('127.0.0.1:1025', '127.0.0.1:8025', '10.77.0.20:25'):
            if endpoint not in sockets:
                raise ValueError('Missing receiver endpoint: ' + endpoint)
        if any(f'{addr}:{port}' in sockets for addr in ('0.0.0.0', '10.77.0.20', '[::]') for port in (1025,8025,11332,11333,11334,6379)):  # nosec B104 # Detects and REJECTS wildcard service bindings; never binds a socket.
            raise ValueError('Administrative/capture endpoint exposed')
    for module in (() if role == 'relay' else ('spf','dkim','dmarc')):
        effective = run('rspamadm', 'configdump', module)
        if 'check_local = true' not in effective or 'check_authed = true' not in effective:
            raise ValueError('Local/authentication evaluation not enabled')
    if role!='relay':
        if 'max_dns_requests = 10' not in run('rspamadm','configdump','spf'):
            raise ValueError('SPF request budget changed')
        if Path('/opt/peal/lab-tld.dat').read_text().splitlines()[-1]!='test':
            raise ValueError('Private lab suffix unavailable')
        modules={p.name for p in Path('/etc/rspamd/peal-modules').iterdir()}
        if modules!={name+'.lua' for name in ('spf','dkim_signing','dmarc','milter_headers','settings')}:
            raise ValueError('Unexpected loaded module set')
    if role=='receiver' and 'quarantine' not in run('rspamadm','configdump','actions'):
        raise ValueError('Quarantine action unavailable')
    if '4.2.1' not in run('rspamd', '--version'):
        raise ValueError('Wrong Rspamd release')
    return {'role':role, 'collected_unix':time.time(), 'routes':routes, 'ipv6_routes':ipv6,
            'firewall':rules, 'sockets':sockets, 'status':'passed-static-runtime-gate',
            'limits':'Still requires positive and negative lab-local connectivity and observed authentication.'}


if __name__ == '__main__':
    try:
        print(json.dumps(validate(sys.argv[1]), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, IndexError) as error:
        print(json.dumps({'status':'blocked', 'reason':str(error)}))
        raise SystemExit(2)
