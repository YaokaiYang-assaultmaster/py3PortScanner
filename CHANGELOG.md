# Changelog

Versions are monotonically increased based on Semantic Versioning.

***

## V0.3 (10/09/2018)

### Backward incompatible changes:
No longer compatible with python 2.7.
For a version compatible with python 2.7, refer to [v0.2](https://github.com/YaokaiYang-assaultmaster/PythonPortScanner).

### Deprecations
None

### Changes
Migrate to python version >= 3.0.
Integrate the whole [nmap](https://github.com/nmap/nmap) port list into the project.

## V0.2 (09/12/2017)

### Backward incompatible changes
None

### Deprecations
None

### Changes
Fixed [issue #1](https://github.com/YaokaiYang-assaultmaster/PythonPortScanner/issues/1). 
Specifically, fixed Windows has no `SO_REUSEPORT` for TCP socket error and change message 
encoding to `utf-8` before sending out. 

***

## V0.1 (05/30/2017)

### Backward incompatible changes
None

### Deprecations
None

### Changes
Initialized the whole project. First version finished. 
