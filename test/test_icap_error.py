import unittest
from icapserver import ICAPError

class TestICAPError(unittest.TestCase):
    
    def test_ICAPError_init_default_messages(self):
        sut = ICAPError()
        self.assertEqual("Internal Server Error", sut.message)
        
    def test_ICAPError_init_default_code(self):
        sut = ICAPError()
        self.assertEqual(500, sut.code)

    def test_ICAPError_init_non_default_message(self):
        sut = ICAPError(400)
        self.assertEqual("Bad Request", sut.message)

    def test_ICAPError_init_non_default_code(self):
        sut = ICAPError(404)
        self.assertEqual(404, sut.code)
        