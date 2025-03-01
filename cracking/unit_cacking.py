import unittest
import hashlib
from unittest.mock import patch, mock_open
from cracking import hash_md5, brute_force_crack, load_wordlist

class TestMD5Cracker(unittest.TestCase):

    def test_hash_md5(self):
        """Test MD5 hash function"""
        self.assertEqual(hash_md5("password"), hashlib.md5("password".encode()).hexdigest())
        self.assertEqual(hash_md5("123456"), hashlib.md5("123456".encode()).hexdigest())

    @patch("builtins.open", new_callable=mock_open, read_data="password\n123456\nadmin\n")
    def test_load_wordlist(self, mock_file):
        """Test loading wordlist file"""
        wordlist = load_wordlist("dummy.txt")
        self.assertIsNotNone(wordlist)
        self.assertIn("password", wordlist)
        self.assertIn("admin", wordlist)

    @patch("cracking.load_wordlist", return_value=["password", "123456", "admin"])
    @patch("cracking.update_display")  # Mocking GUI updates to avoid tkinter errors
    def test_brute_force_crack_wordlist(self, mock_display, mock_wordlist):
        """Test dictionary attack with a predefined hash"""
        md5_hash = hash_md5("password")
        cracked_password, attempts, time_taken = brute_force_crack(md5_hash)
        self.assertEqual(cracked_password, "password")
        self.assertGreater(attempts, 0)
        self.assertGreater(time_taken, 0)

    @patch("cracking.update_display")  # Mocking GUI updates to avoid tkinter errors
    def test_brute_force_crack_bruteforce(self, mock_display):
        """Test brute-force attack with a short password"""
        md5_hash = hash_md5("abc")  # A short 3-character password
        cracked_password, attempts, time_taken = brute_force_crack(md5_hash)
        self.assertEqual(cracked_password, "abc")
        self.assertGreater(attempts, 0)
        self.assertGreater(time_taken, 0)

if __name__ == "__main__":
    unittest.main()
