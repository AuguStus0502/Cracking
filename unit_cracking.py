import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO
import bcrypt
import mysql.connector
from email.message import EmailMessage
from email.parser import BytesParser
from email import policy
from tkinter import Tk, filedialog
import os

# Mocking MySQL for testing
class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db_manager = DatabaseManager()
        self.db_manager.connection = MagicMock()
        self.db_manager.cursor = MagicMock()

    def test_connect(self):
        # Ensure the connection method is called
        self.db_manager.connect()
        self.db_manager.connection.cursor.assert_called_once()
        self.db_manager.cursor.execute.assert_called_once()

    def test_create_database_and_tables(self):
        # Test creation of database and tables
        self.db_manager.create_database_and_tables()
        self.db_manager.cursor.execute.assert_any_call("CREATE DATABASE IF NOT EXISTS email_forensics")
        self.db_manager.cursor.execute.assert_any_call("CREATE TABLE IF NOT EXISTS users")
        self.db_manager.cursor.execute.assert_any_call("CREATE TABLE IF NOT EXISTS emails")

    def test_authenticate_user_success(self):
        self.db_manager.cursor.fetchone = MagicMock(return_value=(1, "testuser", bcrypt.hashpw("password".encode(), bcrypt.gensalt()).decode()))
        self.assertTrue(self.db_manager.authenticate_user("testuser", "password"))

    def test_authenticate_user_failure(self):
        self.db_manager.cursor.fetchone = MagicMock(return_value=None)
        self.assertFalse(self.db_manager.authenticate_user("wronguser", "password"))

    def test_register_user_success(self):
        self.db_manager.cursor.fetchone = MagicMock(return_value=None)  # Username doesn't exist
        self.db_manager.cursor.execute = MagicMock()
        self.db_manager.connection.commit = MagicMock()

        self.assertTrue(self.db_manager.register_user("newuser", "password"))
        self.db_manager.cursor.execute.assert_called_with("INSERT INTO users (username, password) VALUES (%s, %s)", ("newuser", MagicMock()))

    def test_register_user_failure(self):
        self.db_manager.cursor.fetchone = MagicMock(return_value=(1, "existinguser", "hashedpassword"))
        self.assertFalse(self.db_manager.register_user("existinguser", "password"))

class TestBasicEmailParser(unittest.TestCase):
    @patch("builtins.open", new_callable=MagicMock)
    @patch("email.parser.BytesParser.parse", return_value=MagicMock())
    def test_parse_email(self, mock_parse, mock_open):
        # Simulating a parsed email
        mock_email = MagicMock()
        mock_email.get.return_value = "example@domain.com"
        mock_parse.return_value = mock_email

        parser = BasicEmailParser("test.eml")
        parser.parse_email()

        # Assert methods are called
        mock_open.assert_called_once_with("test.eml", "rb")
        mock_parse.assert_called_once()

    def test_get_email_content(self):
        msg = MagicMock()
        msg.is_multipart.return_value = False
        msg.get_payload.return_value = "Test email content"
        parser = BasicEmailParser("test.eml")
        content = parser._get_email_content(msg)

        self.assertEqual(content, "Test email content")

    @patch("bs4.BeautifulSoup")
    def test_analyze_links(self, mock_beautiful_soup):
        mock_soup = MagicMock()
        mock_soup.find_all.return_value = [MagicMock(href="http://example.com")]
        parser = BasicEmailParser("test.eml")
        parser._analyze_links("Test content")
        
        # Check that links were extracted
        self.assertIn("http://example.com", parser.result_text)

    @patch("mysql.connector.connect")
    def test_save_to_database(self, mock_connect):
        mock_db = MagicMock()
        mock_cursor = MagicMock()
        mock_db.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_db

        msg = MagicMock()
        msg.get.return_value = "example@domain.com"
        parser = BasicEmailParser("test.eml")
        parser.save_to_database()

        # Test that the email data was inserted into the database
        mock_cursor.execute.assert_called_with(
            "INSERT INTO emails (sender, receiver, subject, date_received) VALUES (%s, %s, %s, %s)",
            ("example@domain.com", "N/A", "N/A", "N/A")
        )


class TestLoginWindow(unittest.TestCase):
    @patch("tkinter.messagebox.showerror")
    @patch("tkinter.messagebox.showinfo")
    @patch("tkinter.filedialog.askopenfilename", return_value="test.eml")
    def test_login(self, mock_file, mock_showinfo, mock_showerror):
        root = Tk()
        login_window = LoginWindow(root)
        
        # Simulate a successful login
        db_manager = DatabaseManager()
        db_manager.authenticate_user = MagicMock(return_value=True)

        login_window.username_entry.insert(0, "testuser")
        login_window.password_entry.insert(0, "password")
        login_window.authenticate()

        # Assert the main window is opened after a successful login
        mock_showinfo.assert_called_once()

    def test_register(self):
        # Simulating successful registration
        db_manager = DatabaseManager()
        db_manager.register_user = MagicMock(return_value=True)
        
        root = Tk()
        login_window = LoginWindow(root)
        login_window.username_entry.insert(0, "newuser")
        login_window.password_entry.insert(0, "password")

        login_window.register()
        # Ensure registration success message is shown
        messagebox.showinfo.assert_called_with("Success", "Registration Successful! Please Login.")

class TestEmailForensicGUI(unittest.TestCase):
    @patch("tkinter.filedialog.askopenfilename", return_value="test.eml")
    @patch("BasicEmailParser")
    def test_load_email_file(self, mock_parser, mock_askopenfilename):
        root = Tk()
        gui = EmailForensicGUI(root)
        gui.load_email_file()
        self.assertEqual(gui.file_path, "test.eml")
        gui.analyze_button.config.assert_called_with(state=tk.NORMAL)

    @patch("BasicEmailParser.parse_email")
    def test_analyze_email(self, mock_parse_email):
        root = Tk()
        gui = EmailForensicGUI(root)
        gui.file_path = "test.eml"
        gui.analyze_email()
        mock_parse_email.assert_called_once()

if __name__ == "__main__":
    unittest.main()
