import pytest
import tkinter as tk
from MOD_CODE_IPV4_IPV61 import IPApp

@pytest.fixture
def app_instance():
    # Initialize the IPApp instance
    root = tk.Tk()
    app_instance = IPApp(root)
    yield app_instance
    root.destroy()

def test_refresh_status_speed(app_instance):
    # Test the refresh_status_speed method
    app_instance.refresh_status_speed()
    # Write assertions based on the expected behavior of refresh_status_speed method

def test_refresh_ips(app_instance):
    # Test the refresh_ips method
    app_instance.refresh_ips()
    # Write assertions based on the expected behavior of refresh_ips method

def test_add_ip(app_instance):
    # Test the add_ip method
    # Mock user input or directly call the method with test data
    app_instance.add_ip()
    # Write assertions based on the expected behavior of add_ip method

def test_check_website_availability(app_instance):
    # Test the check_website_availability method
    # Mock website URL or directly call the method with test URL
    app_instance.check_website_availability()
    # Write assertions based on the expected behavior of check_website_availability method
