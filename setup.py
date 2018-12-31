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
    author='Jeff Yang',
    name='pyportscanner',
    version='0.3',
    description='Port Scanner for Python3+',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
      "Programming Language :: Python",
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
