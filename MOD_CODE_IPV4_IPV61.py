import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import socket
import speedtest
import requests
from flask import Flask, render_template
import pytest

# Flask App
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# tkinter App
class IPApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Internet Status and Speed")
        self.master.geometry("600x600")
        self.master.config(bg="#f0f0f0")

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.main_frame = ttk.Frame(master, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.status_label = ttk.Label(self.main_frame, text="Internet Status: ")
        self.status_value = ttk.Label(self.main_frame, text="Unknown", foreground="red")
        self.speed_label = ttk.Label(self.main_frame, text="Internet Speed: ")
        self.speed_value = ttk.Label(self.main_frame, text="Unknown", foreground="red")
        self.refresh_button = ttk.Button(self.main_frame, text="Refresh", command=self.refresh_status_speed)
        self.ip_label_v4 = ttk.Label(self.main_frame, text="IPv4 Addresses:")
        self.ip_listbox_v4 = tk.Listbox(self.main_frame, width=30)
        self.ip_label_v6 = ttk.Label(self.main_frame, text="IPv6 Addresses:")
        self.ip_listbox_v6 = tk.Listbox(self.main_frame, width=50)
        self.ip_entry = ttk.Entry(self.main_frame, width=30)
        self.add_button = ttk.Button(self.main_frame, text="Add", command=self.add_ip)
        
        self.website_label = ttk.Label(self.main_frame, text="Check Website Availability:")
        self.website_entry = ttk.Entry(self.main_frame, width=30)
        self.website_check_button = ttk.Button(self.main_frame, text="Check", command=self.check_website_availability)
        self.website_status_label = ttk.Label(self.main_frame, text="Website Status: ", foreground="red")

        self.setup_layout()
        self.refresh_ips()
        self.refresh_status_speed()

    def setup_layout(self):
        layout = [
            (self.status_label, self.status_value),
            (self.speed_label, self.speed_value),
            (self.refresh_button,),
            (self.ip_label_v4, self.ip_label_v6),
            (self.ip_listbox_v4, self.ip_listbox_v6),
            (self.ip_entry, self.add_button),
            (self.website_label,),
            (self.website_entry, self.website_check_button),
            (self.website_status_label,)
        ]

        for row, widgets in enumerate(layout):
            for col, widget in enumerate(widgets):
                widget.grid(row=row, column=col, sticky="w", padx=5, pady=5)

    def test_refresh_status_speed(self):
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

    def test_refresh_ips(self):
        self.ip_listbox_v4.delete(0, tk.END)
        self.ip_listbox_v6.delete(0, tk.END)

        ipv4_addresses, ipv6_addresses = self.get_ip_addresses()
        for ip in ipv4_addresses:
            self.ip_listbox_v4.insert(tk.END, ip)
        for ip in ipv6_addresses:
            self.ip_listbox_v6.insert(tk.END, ip)

    def test_get_ip_addresses(self):
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

    def add_ip(self):
        ip_address = self.ip_entry.get()
        try:
            socket.inet_pton(socket.AF_INET, ip_address)
            self.ip_listbox_v4.insert(tk.END, f"IPv4: {ip_address}")
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, ip_address)
                self.ip_listbox_v6.insert(tk.END, f"IPv6: {ip_address}")
            except OSError:
                print("Invalid IP address")

    def clear_website_entry(self, event):
        self.website_entry.delete(0, tk.END)

    def check_website_availability(self):
        website_url = self.website_entry.get()
        try:
            response = requests.head(website_url)
            if response.status_code == 200:
                self.website_status_label.config(text=f"Website Status: Online", foreground="green")
            else:
                self.website_status_label.config(text=f"Website Status: Offline", foreground="red")
        except Exception as e:
            self.website_status_label.config(text=f"Website Status: Error - {e}", foreground="red")

class LoginApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Login")
        self.master.geometry("500x400")
        self.master.configure(bg="#f0f0f0")

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.main_frame = ttk.Frame(self.master, padding=20, style="Main.TFrame")
        self.main_frame.pack(expand=True)

        self.logo_label = ttk.Label(self.main_frame, text="Login", font=("Helvetica", 20), background="#f0f0f0", foreground="navy")
        self.username_label = ttk.Label(self.main_frame, text="Username:", background="#f0f0f0")
        self.password_label = ttk.Label(self.main_frame, text="Password:", background="#f0f0f0")
        self.username_entry = ttk.Entry(self.main_frame)
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.login_button = ttk.Button(self.main_frame, text="Login", command=self.login, style="Accent.TButton")

        self.logo_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        self.username_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.password_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=(10, 0))

        # Style configurations
        self.style.configure("Main.TFrame", background="#f0f0f0")
        self.style.configure("Accent.TButton", background="#007bff", foreground="white", font=("Helvetica", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#0056b3")])

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        # Check if username and password match
        if username == "Migsmiguel" and password == "12345":
            self.master.destroy()
            root = tk.Tk()
            IPApp(root)
            root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

def main():
    root = tk.Tk()
    login_app = LoginApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
