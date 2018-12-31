import unittest
import collections
from unittest.mock import Mock, patch
import socket
from socket import error as socket_error

from concurrent import futures

from os import sys, path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from pyportscanner import pyscanner
from pyportscanner.etc.service_port import ServicePort


@patch('pyportscanner.pyscanner.socket', autospec=True)
@patch('pyportscanner.pyscanner.read_input', autospec=True)
class PortScannerTest(unittest.TestCase):
    def setUp(self):
        self.target_ports = [80, 443]
        self.thread_limit = 100
        self.timeout = 10
        port_80 = ServicePort('HTTP', 80, 'TCP', 0.1)
        port_443 = ServicePort('TLS', 443, 'TCP', 0.09)
        self.mock_port_list = {
            80: port_80,
            443: port_443,
        }
        self.test_ip = 'test_ip_address'
        self.test_host = 'http://test_domain.com'
        self.test_domain = 'test_domain.com'

    def test_init_func(self, mock_read_input, mock_socket):
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        self.assertIsNotNone(scanner)
        self.assertEqual(scanner.get_target_ports(), self.target_ports)
        self.assertEqual(scanner.thread_limit, self.thread_limit)
        self.assertEqual(scanner.timeout_val, self.timeout)

    def test_extract_list_success(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner.extract_list(2)
        self.assertEqual(result, [80, 443])
        result = scanner.extract_list(1)
        self.assertEqual(result, [80])

    def text_extract_list_error(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        self.assertRaises(scanner.extract_list(-1), ValueError)

    def test_get_target_ports(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner.get_target_ports()
        self.assertIsNotNone(result)
        self.assertEqual(result, self.target_ports)

    def test_get_top_k_ports(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner.get_top_k_ports(2)
        self.assertIsNotNone(result)
        self.assertEqual(result, self.target_ports)

    def test_scan_input_ip_success(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_socket.inet_aton.return_value = None
        mock_socket.gethostbyname.return_value = self.test_ip
        mock_scan_results = {
            80: 'OPEN',
            443: 'CLOSE',
        }
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        # private instance methods in python are name mangled
        # see https://docs.python.org/3.5/tutorial/classes.html#private-variables
        scanner._PortScanner__scan_ports = Mock(return_value=mock_scan_results)
        result = scanner.scan(self.test_ip)
        self.assertEqual(result, mock_scan_results)
        mock_socket.gethostbyname.assert_called_once_with(self.test_ip)

    def test_scan_os_error_success(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_socket.inet_aton.side_effect = OSError
        mock_socket.gethostbyname.return_value = self.test_ip
        mock_scan_results = {
            80: 'OPEN',
            443: 'CLOSE',
        }
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        # private instance methods in python are name mangled
        # see https://docs.python.org/3.5/tutorial/classes.html#private-variables
        scanner._PortScanner__scan_ports = Mock(return_value=mock_scan_results)
        result = scanner.scan(self.test_host)
        self.assertEqual(result, mock_scan_results)
        scanner._PortScanner__scan_ports.assert_called_once_with(self.test_ip, '')
        mock_socket.gethostbyname.assert_called_once_with(self.test_domain)

    def test_scan_socket_error_success(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_socket.inet_aton.side_effect = socket_error
        mock_socket.gethostbyname.return_value = self.test_ip
        mock_scan_results = {
            80: 'OPEN',
            443: 'CLOSE',
        }
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        # private instance methods in python are name mangled
        # see https://docs.python.org/3.5/tutorial/classes.html#private-variables
        scanner._PortScanner__scan_ports = Mock(return_value=mock_scan_results)
        result = scanner.scan(self.test_host)
        self.assertEqual(result, mock_scan_results)
        scanner._PortScanner__scan_ports.assert_called_once_with(self.test_ip, '')
        mock_socket.gethostbyname.assert_called_once_with(self.test_domain)

    def test_scan_server_unknown(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_socket.gethostbyname.side_effect = socket_error
        mock_socket.inet_aton.side_effect = socket_error
        mock_scan_results = {
            80: 'OPEN',
            443: 'CLOSE',
        }
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        # private instance methods in python are name mangled
        # see https://docs.python.org/3.5/tutorial/classes.html#private-variables
        scanner._PortScanner__scan_ports = Mock(return_value=mock_scan_results)
        result = scanner.scan(self.test_host)
        self.assertEqual(result, {})
        scanner._PortScanner__scan_ports.assert_not_called()
        mock_socket.gethostbyname.assert_called_once_with(self.test_domain)

    @patch('pyportscanner.pyscanner.concurrent.futures.ThreadPoolExecutor', autospec=True)
    def test_scan_ports_success(self, mock_executor, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_future1 = Mock(spec=futures.Future)
        mock_future1.done.return_value = True
        mock_future1.result.return_value = (80, 'OPEN')
        mock_future2 = Mock(spec=futures.Future)
        mock_future2.done.side_effect = [False, True]
        mock_future2.result.return_value = (443, 'OPEN')
        mock_executor.return_value.__enter__.return_value.submit.side_effect = [mock_future1, mock_future2]
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner._PortScanner__scan_ports(self.test_ip, '')
        self.assertEqual(result, {80: 'OPEN', 443: 'OPEN'})

    @patch('pyportscanner.pyscanner.concurrent.futures.ThreadPoolExecutor', autospec=True)
    def test_scan_ports_exception(self, mock_executor, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_future1 = Mock(spec=futures.Future)
        mock_future1.done.return_value = True
        mock_future1.result.return_value = (80, 'OPEN')
        mock_future2 = Mock(spec=futures.Future)
        mock_future2.done.side_effect = [False, True]
        mock_future2.result.side_effect = socket_error
        mock_executor.return_value.__enter__.return_value.submit.side_effect = [mock_future1, mock_future2]
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner._PortScanner__scan_ports(self.test_ip, '')
        self.assertEqual(result, {80: 'OPEN', 443: 'CLOSE'})

    @patch('pyportscanner.pyscanner.concurrent.futures.ThreadPoolExecutor', autospec=True)
    def test_scan_ports_thread_limit(self, mock_executor, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_future1 = Mock(spec=futures.Future)
        mock_future1.done.return_value = True
        mock_future1.result.return_value = (80, 'OPEN')
        mock_future2 = Mock(spec=futures.Future)
        mock_future2.done.side_effect = [False, True]
        mock_future2.result.side_effect = socket_error
        mock_executor.return_value.__enter__.return_value.submit.side_effect = [mock_future1, mock_future2]
        scanner = pyscanner.PortScanner(self.target_ports, 1, self.timeout)
        result = scanner._PortScanner__scan_ports(self.test_ip, '')
        self.assertEqual(result, {80: 'OPEN', 443: 'CLOSE'})

    def test_check_futures_succes(self, mock_read_input, mock_socket):
        mock_read_input.return_value = self.mock_port_list
        mock_future1 = Mock(spec=futures.Future)
        mock_future1.done.return_value = True
        mock_future1.result.return_value = (80, 'OPEN')
        mock_future2 = Mock(spec=futures.Future)
        mock_future2.done.return_value = False
        test_futures = collections.deque()
        test_futures.append(mock_future1)
        test_futures.append(mock_future2)
        test_output = {
            80: 'CLOSE',
            443: 'CLOSE',
        }
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        scanner._PortScanner__check_futures(test_output, test_futures)
        self.assertEqual(len(test_futures), 1)
        self.assertEqual(test_output, {80: 'OPEN', 443: 'CLOSE'})

    @patch('pyportscanner.pyscanner.platform', autospec=True)
    def test_TCP_connect_open(self, mock_platform, mock_read_input, mock_socket):
        test_message = 'test_message_djiqojiocn'
        mock_platform.system.return_value = 'Linux'
        mock_tcp_socket = Mock(spec=socket.socket)
        mock_tcp_socket.setsockopt.return_value = None
        mock_tcp_socket.settimeout.return_value = None
        # assume the port is open
        mock_tcp_socket.connect_ex.return_value = 0
        mock_tcp_socket.sendall.return_value = None
        mock_tcp_socket.close.return_value = None
        mock_udp_socket = Mock(spec=socket.socket)
        mock_udp_socket.sendto.return_value = None
        mock_socket.socket.side_effect = [mock_tcp_socket, mock_udp_socket]
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner._PortScanner__TCP_connect(self.test_ip, 80, test_message)
        self.assertEqual(result, (80, 'OPEN'))
        mock_tcp_socket.connect_ex.assert_called_once_with((self.test_ip, 80))
        mock_tcp_socket.sendall.assert_called_once_with(test_message.encode('utf8'))
        mock_tcp_socket.close.assert_called_once_with()
        mock_tcp_socket.settimeout.assert_called_once_with(self.timeout)
        mock_udp_socket.sendto.assert_called_once_with(test_message.encode('utf8'), (self.test_ip, 80))
        mock_udp_socket.close.assert_called_once_with()

    @patch('pyportscanner.pyscanner.platform', autospec=True)
    def test_TCP_connect_close(self, mock_platform, mock_read_input, mock_socket):
        test_message = 'test_message_djiqojiocn'
        mock_platform.system.return_value = 'Linux'
        mock_tcp_socket = Mock(spec=socket.socket)
        mock_tcp_socket.setsockopt.return_value = None
        mock_tcp_socket.settimeout.return_value = None
        # assume the port is close
        mock_tcp_socket.connect_ex.return_value = 1
        mock_tcp_socket.sendall.return_value = None
        mock_tcp_socket.close.return_value = None
        mock_udp_socket = Mock(spec=socket.socket)
        mock_udp_socket.sendto.return_value = None
        mock_socket.socket.side_effect = [mock_tcp_socket, mock_udp_socket]
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner._PortScanner__TCP_connect(self.test_ip, 80, test_message)
        self.assertEqual(result, (80, 'CLOSE'))
        mock_tcp_socket.connect_ex.assert_called_once_with((self.test_ip, 80))
        mock_tcp_socket.sendall.assert_not_called()
        mock_tcp_socket.close.assert_called_once_with()
        mock_tcp_socket.settimeout.assert_called_once_with(self.timeout)
        mock_udp_socket.sendto.assert_called_once_with(test_message.encode('utf8'), (self.test_ip, 80))
        mock_udp_socket.close.assert_called_once_with()

    @patch('pyportscanner.pyscanner.platform', autospec=True)
    def test_TCP_connect_socket_error(self, mock_platform, mock_read_input, mock_socket):
        test_message = 'test_message_djiqojiocn'
        mock_platform.system.return_value = 'Linux'
        mock_tcp_socket = Mock(spec=socket.socket)
        mock_tcp_socket.setsockopt.return_value = None
        mock_tcp_socket.settimeout.return_value = None
        # assume the port is close
        mock_tcp_socket.connect_ex.side_effect = socket_error
        mock_tcp_socket.sendall.return_value = None
        mock_tcp_socket.close.return_value = None
        mock_udp_socket = Mock(spec=socket.socket)
        mock_udp_socket.sendto.return_value = None
        mock_socket.socket.side_effect = [mock_tcp_socket, mock_udp_socket]
        scanner = pyscanner.PortScanner(self.target_ports, self.thread_limit, self.timeout)
        result = scanner._PortScanner__TCP_connect(self.test_ip, 80, test_message)
        self.assertEqual(result, (80, 'CLOSE'))
        mock_tcp_socket.connect_ex.assert_called_once_with((self.test_ip, 80))
        mock_tcp_socket.close.assert_called_once_with()
        mock_tcp_socket.settimeout.assert_called_once_with(self.timeout)
        mock_udp_socket.sendto.assert_called_once_with(test_message.encode('utf8'), (self.test_ip, 80))
        mock_udp_socket.close.assert_called_once_with()
