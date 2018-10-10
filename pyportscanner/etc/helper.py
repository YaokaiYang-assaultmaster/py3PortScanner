import re
from urllib.parse import urlparse
import pkg_resources

from pyportscanner.etc.service_port import ServicePort


def read_input():
    """
    Read the 'nmap-services.txt' file and store all the information into
    a dict() of {port, ServicePort} pairs for reference later.
    """
    resource_package = __name__
    resource_path = 'nmap-services.dat'
    resource = pkg_resources.resource_stream(resource_package, resource_path)

    port_map = dict()
    line_regex = '([a-zA-Z0-9-]+)\s+(\d+)/(\w+)\s+(\d+\.\d+)\s+(\#.*)'
    pattern = re.compile(line_regex)
    for line in resource:
        line = line.decode('utf-8')
        # skip comments
        if line.startswith('#'):
            continue
        result = pattern.match(line)
        if result:
            service_name = result.group(1)
            port_num = int(result.group(2))
            proto = result.group(3)
            freq = float(result.group(4))
            service_port = ServicePort(service_name, port_num, proto, freq)
            if port_num not in port_map:
                port_map[port_num] = service_port
            elif port_map[port_num].freq < freq:
                # only keeps the port and protocol with highest usage frequency
                port_map[port_num] = service_port

    return port_map


def get_domain(url):
    """
    Return the hostname, or domain name, of a url.
    e.g. for 'http://google.com/path', it will return google.com
    :param url: String url
    :return: hostname of the url (note the hostname does not include the protocol part)
    """
    if not url:
        return u""
    full_url = u"http://{}"
    if not url.startswith(u"http://") and not url.startswith(u"https://"):
        # otherwise the urlparse will return empty values
        full_url = full_url.format(url)
    else:
        full_url = url
    parse_result = urlparse(full_url)
    return parse_result.hostname
