# Python Port Scanner v0.3

An easy to use Python3 package that could perform port scanning conveniently.

An output example is showed as following:  
![Output Example](https://github.com/YaokaiYang-assaultmaster/py3PortScanner/blob/master/ExampleGraph/portscanner_output_new.png)

## Installation  
### Install with pip  
```
pip install pyportscanner
```

### Install with setup scripts  
1. Clone or download this repository.
2. Install the package using `python setup.py install`.   
3. Voilà! You are ready to go!

## QuickStart
1. Add `from pyportscanner import pyscanner` to the beginning of your code.
2. Initialize a new PortScanner object using `scanner = pyscanner.PortScanner(target_ports=100, timeout=10, verbose=True)`.
3. Then call `scanner.scan(objective)` to perform a port scan to a specific target.
The target could either be an IPv4 address or a host name.
4. __Note that the total scan time for a target website is highly related to the timeout value set for the Scanner object. Thus for the seek of efficiency, the timeout should not be too long.__

## Documentation 
### _class pyportscanner.pyscanner.PortScanner(target_ports=None, thread_limit=100, timeout=10, verbose=False)_
PortScanner is the class provides methods to execute the port scan request. A PortScanner object is needed for performing
the port scan request.  

- _target_ports_ can be a list or int. If this args is a list, then the list of ports specified by it is going to be scanned, 
default to all ports we have in file. If this args is an int, then it specifies the top X number of ports to be scanned based on usage
frequency rank.
- _thread_limit_ is the number of thread being used for scan.  
- _timeout_ is the timeout for the socket to wait for a response.
- _verbose_ specifies whether the results would be print out or not. If `True`, results will be print out. 

### _Functions_  
__PortScanner.scan(objective, message = '')__ 

Scan an objective with the given message included in the packets sent out.  

- _objective_ is the target that is going to be scanned. It could be an IPv4 address or a hostname.  
- _message_ is the message that is going to be included in the scanning packets sent out. If not provided, no message will be included in the packets.    

An example usage case is showed in [_examples/PortScanExample.py_](https://github.com/YaokaiYang-assaultmaster/py3PortScanner/blob/master/examples/PortScanExample.py).  

### Unit Test

In order to run unit test, execute the following command under the root directory.

```Python
pytest --cov pyportscanner/ tests/
``` 

## [Change logs](https://github.com/YaokaiYang-assaultmaster/py3PortScanner/blob/master/CHANGELOG.md)
