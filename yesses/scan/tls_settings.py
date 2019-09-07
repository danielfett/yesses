from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.robot_plugin import RobotScanResultEnum, RobotScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand

import requests
import logging

log = logging.getLogger('scan/tlssettings')


class TLSSettings:
    def __init__(self, domains=None, tls_profile='intermediate'):
        self.domains = domains
        self.tls_profile = tls_profile

    def run(self):
        self.results = {
            'TLS-Profile-Mismatch-Error-Domains': [],
            'TLS-Profile-Match-Domains': [],
            'TLS-Error-Domains': [],
        }

        for domain in self.domains:
            self.scan_domain(domain)

        return self.results

    def scan_domain(self, domain):
        scanner = TLSSettingsScanner(domain, self.tls_profile)
        if scanner.server_error is not None:
            self.results['TLS-Error-Domains'].append({
                'domain': domain,
                'error': scanner.server_error,
            })
            continue
        results = scanner.run()
        all_errors = results['certificate_validation_errors'] + results['profile_errors'] + results['vulnerability_errors']
        if len(all_errors) == 0:
            self.results['TLS-Profile-Match-Domains'].append(domain)
        else:
            self.results['TLS-Profile-Mismatch-Domains'].append({
                'domain': domain,
                'error': ', '.join(all_errors),
            })
            
        
class TLSSettingsScanner:
    PROFILES_URL = 'https://statics.tls.security.mozilla.org/server-side-tls-conf-5.0.json'
    PROFILES = None
    
    SCAN_COMMANDS = {
        "SSLv2": Sslv20ScanCommand,
        "SSLv3": Sslv30ScanCommand,
        "TLSv1": Tlsv10ScanCommand,
        "TLSv1.1": Tlsv11ScanCommand,
        "TLSv1.2": Tlsv12ScanCommand,
        "TLSv1.3": Tlsv13ScanCommand,
    }
    
    def __init__(self, domain, target_profile_name):
        if TLSSettingsScanner.PROFILES is None:
            TLSSettingsScanner.PROFILES = requests.get(self.PROFILES_URL).json()
            log.info(f"Loaded version {TLSSettingsScanner.PROFILES['version']} of the Mozilla TLS configuration recommendations.")

        self.target_profile = TLSSettingsScanner.PROFILES[target_profile_name]
            
        self.scanner = SynchronousScanner()
        try:
            server_tester = ServerConnectivityTester(
                hostname=domain,
            )
        log.info(f'Testing connectivity with {server_tester.hostname}:{server_tester.port}...')
        self.server_info = server_tester.perform()
        self.server_error = None
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        log.warning(f'Could not connect to {e.server_info.hostname}: {e.error_message}')
        self.server_error = e.error_message
        self.server_info = None

        
    def run(self):
        if self.server_info is None:
            return
        
        certificate_valid, certificate_validation_errors = self.check_certificate()
        self.scan_supported_ciphers_and_protocols()
        profile_ok, profile_errors = self.check_server_matches_profile()
        vulnerabilities, vulnerability_errors = self.check_vulnerabilities()

        return {
            'certificate_validation_errors': certificate_validation_errors,
            'profile_errors': profile_errors,
            'vulnerability_errors': vulnerability_errors,
        }

    
    def scan(self, command):
        return self.scanner.run_scan_command(self.server_info, command())
        
        
    def scan_supported_ciphers_and_protocols(self):
        supported_ciphers = []
        supported_protocols = []
        for name, details in protocols.items():
            log.debug(f"Testing protocol {name}")
            result = self.scan(details['command'])
            ciphers = [cipher.openssl_name for cipher in result.accepted_cipher_list]
            supported_ciphers.extend(ciphers)
            if len(ciphers):
                supported_protocols.append(name)

        self.supported_ciphers = set(supported_ciphers)
        self.supported_protocols = set(supported_protocols)
   
    def check_server_matches_profile(self):
        errors = []
        
        allowed_protocols = set(self.target_profile['tls_versions'])
        illegal_protocols = self.supported_protocols - allowed_protocols

        for protocol in illegal_protocols:
            errors.append(f'must not support "{protocol}"')

        allowed_ciphers = set(self.target_profile['openssl_ciphersuites'] + self.target_profile['openssl_ciphers'])
        illegal_ciphers = self.supported_ciphers - allowed_ciphers

        for cipher in illegal_ciphers:
            errors.append(f'must not support "{cipher}"')
     
        return errors
    
    def check_certificate(self):
        result = self.scan(CertificateInfoScanCommand)

        errors = []

        for r in result.path_validation_result_list:
            if not r.was_validation_successful:
                errors.append(f"validation not successful: {r.verify_string} (trust store {r.trust_store.name})")

        if result.path_validation_error_list:
            validation_errors = (fail.error_message for fail in result.path_validation_error_list)
            errors.append(f'Validation failed: {", ".join(validation_errors)}')

        if not result.leaf_certificate_subject_matches_hostname:
            errors.append(f'Leaf certificate subject does not match hostname!')

        if not result.received_chain_has_valid_order:
            errors.append(f'Certificate chain has wrong order.')

        if result.verified_chain_has_sha1_signature:
            errors.append(f'SHA1 signature found in chain.')

        if result.verified_chain_has_legacy_symantec_anchor:
            errors.append(f'Symantec legacy certificate found in chain.')

        if result.leaf_certificate_signed_certificate_timestamps_count < 2:
            errors.append(f'Not enought SCTs in certificate, only found {result.leaf_certificate_signed_certificate_timestamps_count}.')

        if len(errors) == 0:
            log.debug(f"Certificate is ok")
        else:
            log.debug(f"Error validating certificate")
            for error in errors:
                log.debug(f"  → {error}")

        return errors


    def check_vulnerabilities(self):
        errors = []

        result = self.scan(HeartbleedScanCommand)

        if result.is_vulnerable_to_heartbleed:
            errors.append(f'Server is vulnerable to Heartbleed attack')

        result = self.scan(OpenSslCcsInjectionScanCommand)

        if result.is_vulnerable_to_ccs_injection:
            errors.append(f'Server is vulnerable to OpenSSL CCS Injection (CVE-2014-0224)')

        result = self.scan(RobotScanCommand)

        if result.robot_result_enum in [
                RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        ]:
            errors.append(f"Server is vulnerable to ROBOT attack.")

        return errors
    

        
test_cases = [
    
    {
        'domain': 'expired.badssl.com',
        'expect': {
            'certificate_valid': False,
            'vulnerabilities': False,
        }
    },
    {
        'domain': 'wrong.host.badssl.com',
        'expect': {
            'certificate_valid': False,
            'vulnerabilities': False,
        }
    },
    {
        'domain': 'self-signed.badssl.com',
        'expect': {
            'certificate_valid': False,
            'vulnerabilities': False,
        }
    },
    {
        'domain': 'untrusted-root.badssl.com',
        'expect': {
            'certificate_valid': False,
            'vulnerabilities': False,
        }
    },
    {
        'domain': 'mozilla-old.badssl.com',
        'profile': 'old',
        'expect': {
            'certificate_valid': True,
            'vulnerabilities': False,
            'profile_matched': True,
        }
    },
    {
        'domain': 'mozilla-intermediate.badssl.com',
        'profile': 'intermediate',
        'expect': {
            'certificate_valid': True,
            'vulnerabilities': False,
            'profile_matched': True,
        }
    },
    {
        'domain': 'mozilla-modern.badssl.com',
        'profile': 'modern',
        'expect': {
            'certificate_valid': True,
            'vulnerabilities': False,
            'profile_matched': True,
        }
    },
    {
        'domain': 'invalid-expected-sct.badssl.com',
        'expect': {
            'certificate_valid': False,
        }
    },
    
]

for test in test_cases:
    print(f"\n\n=== Now testing: {test['domain']}")
    result = demo_synchronous_scanner(protocols, test['domain'], test.get('profile', None))
    for matched_key, matched_value in test['expect'].items():
        if result[matched_key] != matched_value:
            print (f"Expected {matched_key} to be {matched_value}, but it is {result[matched_key]}")



