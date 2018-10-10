from functools import total_ordering


@total_ordering
class ServicePort(object):
    """
    A class wrapper for storing the information
    parsed out from nmap-services.txt file,
    including the service name, port number, protocol and open frequency.

    Sorting of the ServicePort object is done in the following ways:
      1. Those with higher frequency are considered as greater.
      2. If two objects have the same frequency, the one with a larger port number
        is considered as greater.
    """
    def __init__(self, service_name, port_num, proto, freq):
        self.service_name = service_name
        self.port_num = port_num
        self.proto = proto
        self.freq = freq

    def __eq__(self, other):
        return self.freq == other.freq and self.port_num == other.port_num

    def __ne__(self, other):
        return self.freq != other.freq or self.port_num != other.port_num

    def __lt__(self, other):
        if self.freq == other.freq:
            return self.port_num < other.port_num
        else:
            return self.freq > other.freq
