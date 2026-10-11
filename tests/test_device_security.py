import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'server'))
import device_security as security
from wda_client import WDAClient

class SecurityTests(unittest.TestCase):
    def test_private_credential_reuse_and_unsafe_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            token=security.control_token(root)
            self.assertEqual(len(token),64)
            self.assertEqual(security.control_token(root),token)
            file=root/security.TOKEN_FILE
            self.assertEqual(file.stat().st_mode & 0o777,0o600)
            file.chmod(0o644)
            with self.assertRaises(ValueError):security.control_token(root)
            file.unlink();(root/'target').write_text(token);file.symlink_to(root/'target')
            with self.assertRaises(OSError):security.control_token(root)
    def test_git_directory_is_rejected_before_writing_any_credential(self):
        from iphone_use import Runtime
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'.git').mkdir()
            for operation in (security.control_token,Runtime):
                with self.assertRaises(ValueError):operation(root)
            self.assertFalse((root/security.TOKEN_FILE).exists())
            self.assertFalse((root/'.auth.lock').exists())
    def test_client_requires_authentication(self):
        with self.assertRaises(ValueError):WDAClient()
    def test_run_file_injects_secret_privately_without_mutating_build_or_source(self):
        for version in (1,2):
            with self.subTest(version=version),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);products=root/'derived_data/Build/Products';products.mkdir(parents=True)
                (root/'runtime').mkdir()
                target={'TestBundlePath':'__TESTROOT__/Debug-iphoneos/WebDriverAgentRunner-Runner.app/PlugIns/WebDriverAgentRunner.xctest',
                        'EnvironmentVariables':{'VERBOSE_LOGGING':'1','USE_IP':'192.168.1.9'}}
                document={'Runner':target} if version==1 else {'TestConfigurations':[{'TestTargets':[target]}]}
                source=products/'wda.xctestrun';raw=plistlib.dumps(document);source.write_bytes(raw)
                path=security.authenticated_xctestrun(root,8100)
                self.assertEqual(source.read_bytes(),raw)
                secured=plistlib.loads(path.read_bytes());runner=secured['Runner'] if version==1 else secured['TestConfigurations'][0]['TestTargets'][0]
                self.assertEqual(runner['EnvironmentVariables']['IPHONE_USE_DEVICE_TOKEN'],security.control_token(root))
                self.assertEqual(runner['EnvironmentVariables']['VERBOSE_LOGGING'],'0')
                self.assertNotIn('USE_IP',runner['EnvironmentVariables'])
                self.assertNotIn('__TESTROOT__',runner['TestBundlePath'])
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_old_build_fingerprint_is_invalidated(self):
        import wda_setup,hashlib,json
        config={'udid':'fixture'}
        old=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()
        self.assertNotEqual(old,wda_setup._fingerprint(config))
    def test_source_admission_refuses_missing_or_additional_patch_changes(self):
        with patch.object(security.subprocess,'run') as run:
            run.return_value.stdout=security.PATCH.read_bytes()
            security.verify_source(Path('/synthetic/source'))
            for diff in (b'',security.PATCH.read_bytes()+b'other change'):
                run.return_value.stdout=diff
                with self.assertRaises(ValueError):security.verify_source(Path('/synthetic/source'))

@unittest.skipUnless(sys.platform=='darwin', 'Objective-C native checks require macOS')
class NativeAuthenticationTests(unittest.TestCase):
    def test_actual_phone_authenticator_rejects_missing_wrong_and_ambiguous_headers(self):
        section=security.PATCH.read_text().split('diff --git a/WebDriverAgentLib/Routing/FBUseAuthentication.h ',1)[1].split('diff --git ',1)[0]
        header='\n'.join(line[1:] for line in section.splitlines() if line.startswith('+') and not line.startswith('+++'))+'\n'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'FBUseAuthentication.h').write_text(header)
            (root/'check.m').write_text(r'''
#import "FBUseAuthentication.h"
int main(void) { @autoreleasepool {
  NSString *token=FBUseToken();
  if (!token) return FBUseAuthorized(@"Bearer invalid") ? 1 : 0;
  NSString *auth=[@"Bearer " stringByAppendingString:token];
  if (!FBUseAuthorized(auth) || FBUseAuthorized(nil) || FBUseAuthorized(@"Bearer invalid")) return 2;
  NSString *prefix=[NSString stringWithFormat:@"GET / HTTP/1.1\r\nAuthorization: %@",auth];
  if (!FBUseStreamAuthorized([prefix dataUsingEncoding:NSUTF8StringEncoding])) return 3;
  NSArray *bad=@[
    [prefix stringByAppendingString:@"\r\nOrigin: https://foreign.example"],
    [prefix stringByAppendingFormat:@"\r\nauthorization: %@",auth],
    [prefix stringByAppendingString:@"\r\nTransfer-Encoding: chunked"],
    [prefix stringByAppendingString:@"\r\nContent-Length: 1"],
    [prefix stringByReplacingOccurrencesOfString:@"GET /" withString:@"POST /"],
    [prefix stringByReplacingOccurrencesOfString:@"Authorization:" withString:@"Authorization :"]];
  for (NSString *value in bad) if (FBUseStreamAuthorized([value dataUsingEncoding:NSUTF8StringEncoding])) return 4;
  return 0;
}}
''')
            subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-framework','Foundation',str(root/'check.m'),'-o',str(root/'check')],check=True,capture_output=True)
            for token in ('','invalid','a'*64):
                env={**os.environ,'IPHONE_USE_DEVICE_TOKEN':token}
                result=subprocess.run([str(root/'check')],env=env,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr.decode())

class ProbeSecurityTests(unittest.TestCase):
    def test_status_redirect_never_forwards_credential(self):
        import threading
        from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
        from wda_setup import SetupManager
        paths=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header('Location','/would-leak-credential')
                self.send_header('Content-Length','0')
                self.end_headers()
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                manager=SetupManager(Path(directory),'http://127.0.0.1:'+str(server.server_port))
                result=manager._probe_status()
                self.assertFalse(result['ready'])
                self.assertEqual(paths,['/status'])
        finally:server.shutdown();server.server_close();worker.join()
