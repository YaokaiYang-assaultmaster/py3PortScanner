import pyportscanner as ps


def main():
    # Initialize a Scanner object that will scan top 50 commonly used ports.
    scanner = ps.PortScanner(target_ports=50)

    host_name = 'google.com'

    message = 'put whatever message you want here'

    '''
    output contains a dictionary of {port:status} pairs
    in which port is the list of ports we scanned 
    and status is either 'OPEN' or 'CLOSE'
    '''

    # This line sets the thread limit of the scanner to 1500
    scanner.set_thread_limit(1500)

    # This line sets the timeout delay to 15s
    scanner.set_delay(15)

    # This line shows the target port list of the scanner
    scanner.show_target_ports()
    '''
    Current port list is: 
    [blah, blah ....]
    '''

    # This line shows the timeout delay of the scanner
    scanner.show_delay()
    '''
    Current timeout delay is 15 seconds.
    '''

    # This line shows the top 100 commonly used ports.
    scanner.show_top_k_ports(100)
    '''
    Top 100 commonly used ports:
    [blah, blah ....]
    '''

    output = scanner.scan(host_name, message)
    '''
    start scanning website: google.com
    server ip is: 172.217.4.110
    80: OPEN

    443: OPEN

    2000: OPEN

    5060: OPEN

    host google.com scanned in  30.956103 seconds
    finish scanning!
    '''


if __name__ == "__main__":
    main()
