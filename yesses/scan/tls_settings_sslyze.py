from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.robot_plugin import RobotScanResultEnum, RobotScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand

import requests
import json
import logging

log = logging.getLogger('scan/tlssettingslocal')


class TLSSettingsLocal:
    def __init__(self, domains=None, allowed_profiles=['intermediate', 'modern']):


        → Hier weiter, TLSSettingsScanner benutzen.
        
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
    
    def __init__(self, domain):
        if TLSSettingsScanner.PROFILES is None:
            TLSSettingsScanner.PROFILES = json.loads(requests.get(self.PROFILES_URL).text)
            
        self.scanner = SynchronousScanner()
        try:
            server_tester = ServerConnectivityTester(
                hostname=domain,
            )
        log.info(f'Testing connectivity with {server_tester.hostname}:{server_tester.port}...')
        self.server_info = server_tester.perform()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        log.warning(f'Could not connect to {e.server_info.hostname}: {e.error_message}')
        return

    def run(self):
        certificate_valid, certificate_validation_errors = self.check_certificate()
        profiles, profile_errors = self.get_profiles()
        vulnerabilities, vulnerability_errors = check_vulnerabilities(scanner, server_info)

        return {
            'certificate_valid': certificate_valid,
            'certificate_validation_errors': certificate_validation_errors,
            'profiles': profiles,
            'profile_errors': profile_errors,
            'vulnerabilities': vulnerabilities,
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

    def get_supported_profiles(self):
        supported_profiles = []
        profile_errors = {}
        self.scan_supported_ciphers_and_protocols()

        for name, profile in self.PROFILES['configurations'].items():
            profile_matched, illegal_ciphers, illegal_protocols = self.check_server_matches_profile(profile)
            if profile_matched:
                supported_profiles.append(name)
                log.debug(f"matches {required_profile}")
            else:
                profile_errors[name] = {
                    'illegal_ciphers': illegal_ciphers,
                    'illegal_protocols': illegal_protocols
                }
                log.debug(f"does not match {required_profile}:")
                if illegal_ciphers:
                    log.debug(f"  → illegal ciphers: {', '.join(illegal_ciphers)}")
                if illegal_protocols:
                    log.debug(f"  → illegal protocols: {', '.join(illegal_protocols)}")
                    
        return supported_profiles, profile_errors

    
    def check_server_matches_profile(self, profile):
        allowed_ciphers = set(profile['openssl_ciphersuites'] + profile['openssl_ciphers'])
        allowed_protocols = set(profile['tls_versions'])

        illegal_ciphers = self.supported_ciphers - allowed_ciphers
        illegal_protocols = self.supported_protocols - allowed_protocols

        matches = (len(illegal_ciphers) == 0) and (len(illegal_protocols) == 0)
        return matches, illegal_ciphers, illegal_protocols

    
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

        return (len(errors) == 0), errors


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

        return (len(errors) > 0), errors
    

        
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



