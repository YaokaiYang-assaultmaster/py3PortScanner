import concurrent.futures
import platform
import socket
import time
from collections import deque
from socket import error as socket_error

from pyportscanner.etc.helper import read_input, get_domain


class PortScanner:
    @classmethod
    def __usage(cls):
        """
        Return the usage information for invalid input host name.
        """
        print('Python Port Scanner')
        print('Please make sure the input host name is in the form of "foo.com" or "http://foo.com!"\n')

    @property
    def timeout_val(self):
        return self.__timeout

    @timeout_val.setter
    def timeout_val(self, timeout):
        if timeout != int(timeout):
            raise TypeError('Timeout must be an integer')
        elif timeout <= 0:
            raise ValueError(
                'Invalid timeout value: {}.'
                'Timeout must be greater than 0'.format(timeout)
            )
        else:
            self.__timeout = timeout

    @timeout_val.getter
    def timeout_val(self):
        return self.__timeout

    @property
    def thread_limit(self):
        return self.__thread_limit

    @thread_limit.setter
    def thread_limit(self, thread_limit):
        if thread_limit != int(thread_limit):
            raise TypeError('thread limit must be an integer')
        elif thread_limit <= 0 or thread_limit > 50000:
            self.__thread_limit = 100
            raise ValueError(
                'Invalid thread limit {}.'
                'Thread limit must be within 0 to 50000 '.format(thread_limit)
            )
        else:
            self.__thread_limit = thread_limit

    @thread_limit.getter
    def thread_limit(self):
        return self.__thread_limit

    def __init__(self, target_ports=None, thread_limit=100, timeout=10, verbose=False):
        """
        Constructor of a PortScanner object. If target_ports is a list, this list of ports will be used as
        the port list to be scanned. If the target_ports is a int, it should be 50, 100 or 1000, indicating
        which default list will be used.

        :param target_ports: If this args is a list, then this list of ports is going to be scanned,
        default to all ports we have in file.
        If this args is an int, then it specifies the top X number of ports to be scanned based on usage
        frequency rank.
        :type target_ports: list or int
        :param verbose: If True, the scanner will print out scanning result. If False, the scanner
        will scan silently.
        :type verbose boolean
        """
        # default ports to be scanned are all ports in file
        self.__port_map = read_input()

        # default thread number limit
        self.__thread_limit = thread_limit

        # default connection timeout time in seconds
        self.__timeout = timeout

        self.__verbose = verbose

        if target_ports is None:
            self.targets = self.__port_map.keys()
        elif type(target_ports) == list:
            self.targets = target_ports
        elif type(target_ports) == int:
            self.targets = self.extract_list(target_ports)

    def extract_list(self, target_port_rank):
        """
        Extract the top X ranked ports based usage frequency.
        If a number greater than the total number of ports we have is specified, scan all ports.

        :param target_port_rank: top X commonly used port list to be returned.
        :return: top X commonly used port list.
        """
        if target_port_rank <= 0:
            raise ValueError(
                'Invalid input {}. No ports can be selected'.format(target_port_rank)
            )

        service_port_list = sorted(self.__port_map.values())
        port_list = list(ele.port_num for ele in service_port_list)
        return sorted(port_list[:target_port_rank])

    def get_target_ports(self):
        """
        Return the list of ports being scanned.

        :return: list of ports scanned by current Scanner object.
        :rtype: list
        """
        return self.targets

    def get_top_k_ports(self, k):
        """
        Return top K commonly used ports.

        :param k: top K ports to be returned.
        :type k: int
        :return: top K commonly used ports.
        :rtype: list
        """
        port_list = self.extract_list(k)
        return port_list

    def scan(self, objective, message=''):
        """
        This is the function need to be called to perform port scanning.

        :param objective: the objective that is going to be scanned. Could be a host name or an IPv4 address.
        :param message: the message that is going to be included in the scanning packets
        in order to prevent ethical problem (default: '').
        :return: a dict object containing the scan results for a given host in the form of
        {port_number: status}
        :rtype: dict
        """
        try:
            socket.inet_aton(objective)
            host_name = objective
        except OSError or socket_error:
            # this is not an valid IPv4 address
            host_name = get_domain(objective)

        if self.__verbose:
            print('\n')
            print('*' * 60 + '\n')
            print('Start scanning target: {}'.format(host_name))

        try:
            server_ip = socket.gethostbyname(host_name)
            if self.__verbose:
                print('Target IP is: {}'.format(str(server_ip)))

        except Exception:
            # If the DNS resolution of a website cannot be finished, abort the host.
            if self.__verbose:
                print('Target {} unknown! Scan failed.'.format(host_name))
                self.__usage()
            return {}

        start_time = time.time()
        output = self.__scan_ports(server_ip, message)
        stop_time = time.time()

        if self.__verbose:
            print('Target {} scanned in  {} seconds'.format(host_name, stop_time - start_time))
            print('Scan completed!\n')

        return output

    def __scan_ports(self, ip, message):
        """
        Controller of the __scan_ports_helper() function

        :param ip: the ip address that is being scanned
        :type ip: str
        :param delay: the time in seconds that a TCP socket waits until timeout
        :type delay: int
        :param message: the message that is going to be included in the scanning packets,
        in order to prevent ethical problem, default to ''.
        :type message: str
        :return: a dict that stores result in {port, status} style pairs.
        status can be 'OPEN' or 'CLOSE'.
        """
        output = dict()
        for port in self.targets:
            output[port] = 'CLOSE'
        
        futures = deque()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.__thread_limit) as executor:
            for port in self.targets:
                future = executor.submit(self.__TCP_connect, ip, port, message)
                futures.append(future)
                while len(futures) >= self.__thread_limit:
                    self.__check_futures(output, futures)
                    time.sleep(0.01)

            # make sure all thread outputs are stored.
            while futures:
                self.__check_futures(output, futures)
                time.sleep(0.01)

        # Print opening ports from small to large
        if self.__verbose:
            for port in self.targets:
                if output[port] == 'OPEN':
                    service = self.__port_map.get(port, None)
                    if service:
                        port_proto = '{}/{}'.format(port, service.proto.upper())
                    else:
                        port_proto = '{}/{}'.format(port, 'UNKNOWN')
                    print('{:10}: {:>10}\n'.format(port_proto, output[port]))

        return output

    @classmethod
    def __check_futures(cls, output, futures):
        """
        Check the executing status of Futures and retrieve the results from them.
        :param output: dict for storing the results
        :param futures: list of concurrent.futures.Future object
        """
        for _ in range(len(futures)):
            future = futures.popleft()
            if future.done():
                try:
                    port, status = future.result()
                    output[port] = status
                except socket_error:
                    pass
            else:
                futures.append(future)

    def __TCP_connect(self, ip, port_number, message):
        """
        Perform status checking for a given port on a given ip address using TCP handshake

        :param ip: the ip address that is being scanned
        :type ip: str
        :param port_number: the port that is going to be checked
        :type port_number: int
        :param message: the message that is going to be included in the scanning packets,
        in order to prevent ethical problem, default to ''.
        :type message: str
        """
        # Initialize the TCP socket object based on different operating systems.
        # All systems except for 'Windows' will be treated equally.
        curr_os = platform.system()
        if curr_os == 'Windows':
            TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            TCP_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            TCP_sock.settimeout(self.__timeout)
        else:
            TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            TCP_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            TCP_sock.settimeout(self.__timeout)

        b_message = message.encode('utf-8', errors='replace')

        # Initialize a UDP socket to send scanning alert message if there exists an non-empty message
        UDP_sock = None
        try:
            if message:
                UDP_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                UDP_sock.sendto(b_message, (ip, int(port_number)))

            result = TCP_sock.connect_ex((ip, int(port_number)))
            if message and result == 0:
                TCP_sock.sendall(b_message)

            # If the TCP handshake is successful, the port is OPEN. Otherwise it is CLOSE
            if result == 0:
                return port_number, 'OPEN'
            else:
                return port_number, 'CLOSE'

        except socket_error as e:
            # Failed to perform a TCP handshake means the port is probably close.
            return port_number, 'CLOSE'
        finally:
            if UDP_sock:
                UDP_sock.close()
            TCP_sock.close()
