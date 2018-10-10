from pyportscanner import PortScanner


def main():
    # Initialize a Scanner object that will scan top 50 commonly used ports.
    scanner = PortScanner.PortScanner(target_ports=100, verbose=True)

    host_name = 'google.com'

    message = 'put whatever message you want here'

    '''
    output contains a dictionary of {port:status} pairs
    in which port is the list of ports we scanned 
    and status is either 'OPEN' or 'CLOSE'
    '''

    res = scanner.scan(host_name, message)
    '''
    ************************************************************
    
    Start scanning website: google.com
    Server ip is: 172.217.6.110
    80/TCP    :       OPEN
    
    2000/UDP  :       OPEN
    
    5060/UDP  :       OPEN
    
    8008/TCP  :       OPEN
    
    Host google.com scanned in  10.033627033233643 seconds
    Scan completed!
    '''

    '''
    > res
    {9: 'CLOSE',
     17: 'CLOSE',
     19: 'CLOSE',
     21: 'CLOSE',
     22: 'CLOSE',
     25: 'CLOSE',
     26: 'CLOSE',
     49: 'CLOSE',
     53: 'CLOSE',
     67: 'CLOSE',
     68: 'CLOSE',
     69: 'CLOSE',
     80: 'OPEN',
     81: 'CLOSE',
     88: 'CLOSE',
     110: 'CLOSE',
     111: 'CLOSE',
     113: 'CLOSE',
     123: 'CLOSE',
     135: 'CLOSE',
     136: 'CLOSE',
     137: 'CLOSE',
     138: 'CLOSE',
     139: 'CLOSE',
     143: 'CLOSE',
     158: 'CLOSE',
     161: 'CLOSE',
     162: 'CLOSE',
     177: 'CLOSE',
     179: 'CLOSE',
     199: 'CLOSE',
     427: 'CLOSE',
     443: 'CLOSE',
     445: 'CLOSE',
     465: 'CLOSE',
     514: 'CLOSE',
     515: 'CLOSE',
     518: 'CLOSE',
     520: 'CLOSE',
     548: 'CLOSE',
     554: 'CLOSE',
     587: 'CLOSE',
     593: 'CLOSE',
     623: 'CLOSE',
     626: 'CLOSE',
     631: 'CLOSE',
     646: 'CLOSE',
     993: 'CLOSE',
     995: 'CLOSE',
     999: 'CLOSE',
     1022: 'CLOSE',
     1025: 'CLOSE',
     1026: 'CLOSE',
     1027: 'CLOSE',
     1029: 'CLOSE',
     1030: 'CLOSE',
     1031: 'CLOSE',
     1032: 'CLOSE',
     1433: 'CLOSE',
     1434: 'CLOSE',
     1645: 'CLOSE',
     1646: 'CLOSE',
     1718: 'CLOSE',
     1719: 'CLOSE',
     1720: 'CLOSE',
     1723: 'CLOSE',
     1812: 'CLOSE',
     1813: 'CLOSE',
     1900: 'CLOSE',
     2000: 'OPEN',
     2001: 'CLOSE',
     2049: 'CLOSE',
     2222: 'CLOSE',
     2223: 'CLOSE',
     3283: 'CLOSE',
     3389: 'CLOSE',
     3456: 'CLOSE',
     3703: 'CLOSE',
     4045: 'CLOSE',
     4500: 'CLOSE',
     5000: 'CLOSE',
     5060: 'OPEN',
     5353: 'CLOSE',
     5355: 'CLOSE',
     5666: 'CLOSE',
     5900: 'CLOSE',
     8000: 'CLOSE',
     8008: 'OPEN',
     8080: 'CLOSE',
     8443: 'CLOSE',
     8888: 'CLOSE',
     9200: 'CLOSE',
     10000: 'CLOSE',
     17185: 'CLOSE',
     20031: 'CLOSE',
     31337: 'CLOSE',
     32768: 'CLOSE',
     32769: 'CLOSE',
     32770: 'CLOSE',
     32771: 'CLOSE'}
    '''


if __name__ == "__main__":
    main()
