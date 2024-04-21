import tkinter as tk
from tkinter import ttk
import socket
import speedtest
import requests
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# tkinter App
class IPApp:
    def __init__(self, master):
        self.master = master
        self.status_value = ttk.Label(self.master, text="Unknown", foreground="red")
        self.speed_value = ttk.Label(self.master, text="Unknown", foreground="red")

    def refresh_status_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            ping = st.results.ping
            download_speed = st.download() / 10**6
            upload_speed = st.upload() / 10**6

            self.status_value.config(text="Connected", foreground="green")
            self.speed_value.config(text=f"Ping: {ping:.2f} ms | Download: {download_speed:.2f} Mbps | Upload: {upload_speed:.2f} Mbps")

        except Exception as e:
            self.status_value.config(text="Disconnected", foreground="red")
            self.speed_value.config(text="Speedtest Error")

    def get_ip_addresses(self):
        ipv4_addresses = []
        ipv6_addresses = []
        try:
            hostname = socket.gethostname()
            ip_info = socket.getaddrinfo(hostname, None)

            for info in ip_info:
                ip_address = info[4][0]
                if ':' in ip_address:
                    ipv6_addresses.append(f"IPv6: {ip_address}")
                else:
                    ipv4_addresses.append(f"IPv4: {ip_address}")
        except Exception as e:
            ipv4_addresses.append("Error: " + str(e))
            ipv6_addresses.append("Error: " + str(e))

        return ipv4_addresses, ipv6_addresses


class TestIPApp(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = IPApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_refresh_status_speed(self):
        self.app.refresh_status_speed()
        status_text = self.app.status_value.cget("text")
        self.assertIn(status_text, ["Connected", "Disconnected"])

    def test_get_ip_addresses(self):
        ipv4_addresses, ipv6_addresses = self.app.get_ip_addresses()
        self.assertIsInstance(ipv4_addresses, list)
        self.assertIsInstance(ipv6_addresses, list)


if __name__ == "__main__":
    app.run(debug=True)
