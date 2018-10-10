from setuptools import setup


kwargs = {
    'author': 'Jeff Yang',
    'name': 'pyportscanner',
    'version': '0.3',
    'description': 'Port Scanner for Python',
    'long_description': \
    """pyportscanner is a port scanner tool wrote up in origin
    python code.
    It uses TCP handshake for probing open ports on a remote machine
    specified by its hostname. """,
    'packages': ['pyportscanner', 'pyportscanner.etc'],
    'package_data': {'pyportscanner': ['etc/*.dat']},
}

setup(
    **kwargs,
)
