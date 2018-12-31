import unittest
from unittest.mock import Mock, patch

from os import sys, path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from pyportscanner.etc import helper

class HelperTest(unittest.TestCase):
    def test_get_domain(self):
        test_url = 'https://docs.python.org/3/library/unittest.mock.html#unittest.mock.Mock'
        result = helper.get_domain(test_url)
        self.assertEqual(result, 'docs.python.org')

