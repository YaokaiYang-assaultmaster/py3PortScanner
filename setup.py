import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGELOG.md')) as f:
    CHANGES = f.read()

dev_requires = [
    'pytest',
    'pytest-cov',
]


setup(
    author='Yaokai Yang',
    name='pyportscanner',
    version='0.3.2',
    description='Port Scanner for Python3+',
    long_description=README,
    long_description_content_type='text/markdown',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    url='https://github.com/YaokaiYang-assaultmaster/py3PortScanner',
    packages=find_packages(),
    package_data={'pyportscanner': ['etc/*.dat']},
    include_package_data=True,
    zip_safe=False,
    extras_require={
      'dev': dev_requires,
    },
)
