from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
import logging

log = logging.getLogger('discover/domains_and_ips')

class WebScanTLS:
    def __init__(self, hosts):
        self.hosts = hosts

    def run(self):
        TrustStoresRepository.update_default()
        for host in self.hosts:
            self.test_host(host)

    def test_host(self, hostname):
        host_data = {
            'hostname': hostname,
        }
        try:
            server_tester = ServerConnectivityTester(
                hostname=hostname,
                port=443
            )
            log.info(f'Testing TLS connectivity with {server_tester.hostname}:{server_tester.port}.')
            server_info = server_tester.perform()
        except ServerConnectivityError as e:
            log.warn(f'Could not connect to {e.server_info.hostname}: {e.error_message}')
            host_data['available'] = False
            return host_data

        command = Tlsv11ScanCommand()

        synchronous_scanner = SynchronousScanner()

        scan_result = synchronous_scanner.run_scan_command(server_info, command)
        for cipher in scan_result.accepted_cipher_list:
            print(f'    {cipher.name}')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    import sys
    d = WebScanTLS(sys.argv[1:])
    print (d.run())
