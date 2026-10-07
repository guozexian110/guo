"""Bounded CF edge tests and guarded DNS updates. No credentials in output/files."""
import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DOMAIN = 'gzxgzxgzx.de5.net'
SERVERS = ('https://s3.array2026.com', 'https://v1.uhdnow.com')
CF_RANGES = tuple(ipaddress.ip_network(s) for s in (
    '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22',
    '103.31.4.0/22','141.101.64.0/18','108.162.192.0/18',
    '190.93.240.0/20','188.114.96.0/20','197.234.240.0/22',
    '198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
    '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'))
TLS = ssl.create_default_context()


class CheckError(RuntimeError):
    pass


def report(**values):
    print(json.dumps(values, ensure_ascii=False), flush=True)


def valid_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and any(ip in network for network in CF_RANGES)
    except ValueError:
        return False


def proxy_path(upstream):
    return '/' + urllib.parse.quote(upstream, safe='')


def read_edge(ip, upstream, limit, *, binary=False):
    """Connect to the IP while keeping owned-domain TLS SNI and HTTP Host."""
    sock = None
    start = time.monotonic()
    try:
        sock = socket.create_connection((ip, 443), timeout=5)
        sock = TLS.wrap_socket(sock, server_hostname=DOMAIN)
        sock.settimeout(8)
        sock.sendall(('GET '+proxy_path(upstream)+' HTTP/1.1\r\nHost: '+DOMAIN+
                      '\r\nUser-Agent: CF-Emby-Check/2\r\nAccept: */*\r\n'
                      'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii'))
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status != 200:
            raise CheckError('http_status_' + str(response.status))
        content_type = (response.getheader('Content-Type') or '').lower()
        if binary and (not content_type or any(t in content_type for t in ('text/', 'json', 'html'))):
            raise CheckError('invalid_download_type')
        if not binary and 'json' not in content_type:
            raise CheckError('invalid_api_type')
        count = 0
        chunks = []
        while count <= limit:
            chunk = response.read(min(65536, limit + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if not binary:
                chunks.append(chunk)
            if time.monotonic() - start > 18:
                raise CheckError('download_deadline')
        if binary and count != limit:
            raise CheckError('incomplete_or_oversized_download')
        if not binary and count > limit:
            raise CheckError('oversized_json')
        return b''.join(chunks), count, time.monotonic() - start
    finally:
        if sock is not None:
            sock.close()


def validate_info(body):
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeError):
        raise CheckError('invalid_json') from None
    if not isinstance(obj, dict) or not all(isinstance(obj.get(k), str) and obj[k] for k in ('Id', 'Version', 'ServerName')):
        raise CheckError('not_emby_public_info')


def health(ip):
    for server in SERVERS:
        body, _, _ = read_edge(ip, server + '/emby/System/Info/Public', 65536)
        validate_info(body)


def speed(ip, size):
    # This measures a CF test file THROUGH the owned Worker, not movie throughput.
    _, count, elapsed = read_edge(ip, 'https://speed.cloudflare.com/__down?bytes='+str(size), size, binary=True)
    return count * 8 / elapsed / 1_000_000


def probe(ip):
    try:
        health(ip)
        value = speed(ip, 1048576)
        return {'ip': ip, 'mbps': round(value, 3), 'healthy': True}
    except (CheckError, OSError, http.client.HTTPException, ValueError) as e:
        return {'ip': ip, 'healthy': False, 'reason': str(e) if isinstance(e, CheckError) else type(e).__name__}


def select(candidates, current, *, workers=6):
    candidates = list(dict.fromkeys(([current] if current else []) + candidates))
    if not candidates or any(not valid_ip(ip) for ip in candidates):
        raise CheckError('invalid_candidate_list')
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        samples = list(pool.map(probe, candidates))
    for sample in samples:
        report(stage='screen', **sample)
    passed = sorted((r for r in samples if r.get('healthy')), key=lambda r: r['mbps'], reverse=True)
    if not passed:
        raise CheckError('no_valid_candidate_dns_unchanged')
    finalists = [r['ip'] for r in passed[:3]]
    if current and current not in finalists:
        finalists.append(current)
    results = []
    for ip in finalists:
        try:
            health(ip)
            values = [speed(ip, 4194304) for _ in range(3)]
            value = statistics.median(values)
            result = {'ip': ip, 'mbps': round(value, 3), 'samples_mbps': [round(v, 3) for v in values]}
            results.append(result)
            report(stage='repeat', **result)
        except (CheckError, OSError, http.client.HTTPException, ValueError):
            report(stage='repeat', ip=ip, healthy=False)
    if not results:
        raise CheckError('no_repeatable_candidate_dns_unchanged')
    winner = max(results, key=lambda r: r['mbps'])
    baseline = next((r for r in results if r['ip'] == current), None)
    # Avoid switching on ordinary measurement noise. Repeated failure may recover.
    if baseline and winner['mbps'] < baseline['mbps'] * 1.20:
        winner = baseline
    return winner


class Cloudflare:
    def __init__(self):
        token = os.environ.get('CF_TOKEN')
        zone = os.environ.get('CF_ZONE_ID')
        record = os.environ.get('CF_RECORD_ID')
        if not all((token, zone, record)):
            raise CheckError('missing_cf_secrets')
        if not all(len(s) == 32 and all(c in '0123456789abcdef' for c in s.lower()) for s in (zone, record)):
            raise CheckError('invalid_cf_record_ids')
        self.url = 'https://api.cloudflare.com/client/v4/zones/'+zone+'/dns_records/'+record
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method='GET', payload=None):
        headers = {'Authorization': 'Bearer '+self.token, 'Content-Type': 'application/json'}
        request = urllib.request.Request(self.url, data=json.dumps(payload).encode() if payload is not None else None,
                                         headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                obj = json.load(response)
        except (OSError, ValueError):
            raise CheckError('cf_api_request_failed') from None
        if not isinstance(obj, dict) or obj.get('success') is not True or not isinstance(obj.get('result'), dict):
            raise CheckError('cf_api_rejected')
        return obj['result']

    def get(self):
        obj = self.call()
        if obj.get('name') != DOMAIN or obj.get('type') != 'A':
            raise CheckError('cf_record_does_not_match_owned_domain')
        return obj

    def set_ip(self, ip):
        obj = self.call('PATCH', {'content': ip})
        if obj.get('name') != DOMAIN or obj.get('type') != 'A' or obj.get('content') != ip or obj.get('proxied') is not False:
            raise CheckError('cf_update_not_confirmed')
        return obj


def guard_update(cf, before, winner, *, delay=30):
    """Keep other DNS settings; never force orange-cloud records to DNS-only."""
    if before.get('proxied') is not False:
        raise CheckError('proxied_record_preserved_no_ip_override')
    latest = cf.get()
    keys = ('content', 'name', 'type', 'proxied', 'ttl', 'comment', 'tags', 'settings')
    if any(latest.get(k) != before.get(k) for k in keys):
        raise CheckError('record_changed_during_test_dns_unchanged')
    old = before['content']
    if winner == old:
        report(stage='dns', action='unchanged', ip=old)
        return
    if not valid_ip(winner):
        raise CheckError('invalid_winner')
    health(winner)
    attempted = False
    try:
        attempted = True
        cf.set_ip(winner)
        health(winner)
        time.sleep(delay)
        health(winner)
        after = cf.get()
        if after.get('content') != winner or after.get('proxied') is not False:
            raise CheckError('dns_changed_after_update')
        report(stage='dns', action='updated', ip=winner, emby_interfaces_verified=True)
    except (CheckError, OSError, http.client.HTTPException, ValueError, KeyboardInterrupt):
        if attempted:
            try:
                observed = cf.get()
                if observed.get('content') == winner and observed.get('proxied') is False:
                    cf.set_ip(old)
                    if cf.get().get('content') != old:
                        raise CheckError('rollback_not_confirmed')
                    report(stage='dns', action='rolled_back', ip=old)
                elif observed.get('content') == old and observed.get('proxied') is False:
                    report(stage='dns', action='unchanged', ip=old)
                else:
                    raise CheckError('concurrent_change_not_overwritten')
            except (CheckError, OSError, ValueError):
                raise CheckError('post_check_failed_rollback_unconfirmed') from None
        raise CheckError('post_check_failed_original_ip_restored') from None


def main():
    parser = argparse.ArgumentParser(description='CF edge benchmark on the machine running this script.')
    parser.add_argument('--apply', action='store_true', help='Update owned DNS using CF_TOKEN/CF_ZONE_ID/CF_RECORD_ID environment variables.')
    parser.add_argument('--check-current', action='store_true', help='Health-check current DNS without reranking or updates.')
    parser.add_argument('--candidate-file', default=str(Path(__file__).with_name('candidates.json')))
    parser.add_argument('--ip', help='Validate/apply one IP selected on the home network, without hosted reranking.')
    args = parser.parse_args()
    cf = Cloudflare() if args.apply else None
    before = cf.get() if cf else None
    current = before['content'] if before and not before.get('proxied') else None
    if args.apply and before.get('proxied') is not False:
        raise CheckError('proxied_record_preserved_no_ip_override')
    if args.check_current:
        ips = sorted({entry[4][0] for entry in socket.getaddrinfo(DOMAIN, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)})
        if not ips:
            raise CheckError('dns_has_no_ipv4')
        for ip in ips:
            health(ip)
        report(stage='health', passed=True, ips=ips)
        return
    if args.ip:
        if not valid_ip(args.ip):
            raise CheckError('invalid_selected_ip')
        health(args.ip)
        winner = {'ip': args.ip, 'source': 'provided_home_selection'}
    else:
        candidates = json.loads(Path(args.candidate_file).read_text(encoding='utf-8'))
        winner = select(candidates, current)
    location = os.environ.get('CF_MEASUREMENT_LOCATION', 'this_machine')
    report(stage='selected', measurement_location=location,
           test='cf_test_file_through_worker_not_movie', **winner)
    if cf:
        guard_update(cf, before, winner['ip'])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        report(stage='error', reason='interrupted')
        sys.exit(1)
    except Exception as exc:
        # Do not log raw HTTP exceptions, API responses, headers, or secrets.
        report(stage='error', reason=str(exc) if isinstance(exc, CheckError) else type(exc).__name__)
        sys.exit(1)
