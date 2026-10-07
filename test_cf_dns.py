import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cf_dns', Path(__file__).with_name('cf_dns.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Socket:
    def __init__(self, response): self.response = response
    def makefile(self, mode): return io.BytesIO(self.response)
    def settimeout(self, timeout): pass
    def sendall(self, data): self.sent = data
    def close(self): pass


class CF:
    def __init__(self):
        self.state = {'name':mod.DOMAIN, 'type':'A', 'content':'172.66.160.223', 'proxied':False, 'ttl':300, 'comment':'preserve', 'tags':['owner:test']}
        self.writes = []
    def get(self): return dict(self.state)
    def set_ip(self, ip):
        self.writes.append(ip)
        self.state['content'] = ip
        return self.get()


class Tests(unittest.TestCase):
    def test_candidate_must_be_cf_ipv4(self):
        self.assertTrue(mod.valid_ip('172.66.160.223'))
        for value in ('192.0.2.1','127.0.0.1','8.8.8.8','::1','not-ip'):
            self.assertFalse(mod.valid_ip(value))

    def test_emby_schema_rejects_error_page_or_generic_json(self):
        for body in (b'<h1>1034</h1>',b'{"error":"failed"}',b'[]',b'{"Id":"","Version":"1","ServerName":"S"}'):
            with self.assertRaises(mod.CheckError): mod.validate_info(body)
        mod.validate_info(b'{"Id":"abc","Version":"4.8","ServerName":"test"}')

    def request(self, response, **kwargs):
        sock = Socket(response)
        with patch.object(mod.socket,'create_connection',return_value=sock), patch.object(mod.TLS,'wrap_socket',return_value=sock):
            return mod.read_edge('172.66.160.223',mod.SERVERS[0]+'/emby/System/Info/Public',5,**kwargs)

    def test_http_error_never_counts_as_support(self):
        with self.assertRaisesRegex(mod.CheckError,'http_status_403'):
            self.request(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\n1034')

    def test_html_download_never_counts_as_speed(self):
        with self.assertRaisesRegex(mod.CheckError,'invalid_download_type'):
            self.request(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nerror',binary=True)

    def test_truncated_download_never_counts_as_speed(self):
        with self.assertRaisesRegex(mod.CheckError,'incomplete'):
            self.request(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\n12',binary=True)

    def test_complete_binary_is_counted(self):
        body,count,elapsed=self.request(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\n12345',binary=True)
        self.assertEqual(count,5)
        self.assertEqual(body,b'')

    def test_no_valid_candidate_has_no_fallback(self):
        with patch.object(mod,'probe',return_value={'ip':'172.66.160.223','healthy':False}), patch.object(mod,'report'):
            with self.assertRaisesRegex(mod.CheckError,'no_valid_candidate'):
                mod.select(['172.66.160.223'],None)

    def test_small_speed_gain_keeps_current(self):
        old='172.66.160.223';new='162.159.136.13'
        with patch.object(mod,'probe',side_effect=lambda ip:{'ip':ip,'healthy':True,'mbps':100 if ip==old else 110}), patch.object(mod,'health'), patch.object(mod,'speed',side_effect=lambda ip,size:100 if ip==old else 110), patch.object(mod,'report'):
            self.assertEqual(mod.select([new],old)['ip'],old)

    def test_success_preserves_metadata(self):
        cf=CF(); before=cf.get()
        with patch.object(mod,'health'), patch.object(mod,'report'):
            mod.guard_update(cf,before,'162.159.136.13',delay=0)
        self.assertEqual(cf.writes,['162.159.136.13'])
        self.assertEqual(cf.state['comment'],before['comment'])
        self.assertEqual(cf.state['tags'],before['tags'])

    def test_failed_post_check_restores_original(self):
        cf=CF(); before=cf.get()
        with patch.object(mod,'health',side_effect=[None,mod.CheckError('failed')]), patch.object(mod,'report'):
            with self.assertRaisesRegex(mod.CheckError,'original_ip_restored'):
                mod.guard_update(cf,before,'162.159.136.13',delay=0)
        self.assertEqual(cf.writes,['162.159.136.13',before['content']])

    def test_orange_cloud_is_never_disabled(self):
        cf=CF();cf.state['proxied']=True
        with self.assertRaisesRegex(mod.CheckError,'proxied_record_preserved'):
            mod.guard_update(cf,cf.get(),'162.159.136.13',delay=0)
        self.assertEqual(cf.writes,[])

    def test_concurrent_dns_edit_is_preserved(self):
        cf=CF();before=cf.get();cf.state['comment']='changed'
        with self.assertRaisesRegex(mod.CheckError,'record_changed'):
            mod.guard_update(cf,before,'162.159.136.13',delay=0)
        self.assertEqual(cf.writes,[])

    def test_cf_api_success_false_is_not_success(self):
        cf=object.__new__(mod.Cloudflare);cf.url='https://example.com';cf.token='not-real'
        cf.opener=type('Opener',(),{'open':lambda *a,**kw:io.BytesIO(b'{"success":false,"result":null}')})()
        with self.assertRaisesRegex(mod.CheckError,'cf_api_rejected'): cf.call()


if __name__=='__main__': unittest.main()
