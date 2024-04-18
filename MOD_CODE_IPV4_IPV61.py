import tkinter as tk
import socket
import speedtest

class IPApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Internet Status and Speed")

        # Labels to display internet status and speed
        self.status_label = tk.Label(master, text="Internet Status: ")
        self.status_label.grid(row=0, column=0, sticky=tk.W)

        self.status_value = tk.Label(master, text="Unknown", fg="red")
        self.status_value.grid(row=0, column=1, sticky=tk.W)

        self.speed_label = tk.Label(master, text="Internet Speed: ")
        self.speed_label.grid(row=1, column=0, sticky=tk.W)

        self.speed_value = tk.Label(master, text="Unknown", fg="red")
        self.speed_value.grid(row=1, column=1, sticky=tk.W)

        # Refresh button to update status and speed
        self.refresh_button = tk.Button(master, text="Refresh", command=self.refresh_status_speed)
        self.refresh_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # IP addresses section
        self.ip_label_v4 = tk.Label(master, text="IPv4 Addresses:")
        self.ip_label_v4.grid(row=3, column=0, sticky=tk.W)

        self.ip_listbox_v4 = tk.Listbox(master, width=30)
        self.ip_listbox_v4.grid(row=4, column=0, rowspan=3, padx=5, pady=5)

        self.ip_label_v6 = tk.Label(master, text="IPv6 Addresses:")
        self.ip_label_v6.grid(row=3, column=1, sticky=tk.W)

        self.ip_listbox_v6 = tk.Listbox(master, width=50)
        self.ip_listbox_v6.grid(row=4, column=1, rowspan=3, padx=5, pady=5)

        # Add IP Entry Field
        self.ip_entry = tk.Entry(master, width=30)
        self.ip_entry.grid(row=7, column=0, padx=5, pady=5)

        # Add IP Button
        self.add_button = tk.Button(master, text="Add", command=self.add_ip)
        self.add_button.grid(row=7, column=1, padx=5, pady=5)

        # Display IP addresses initially
        self.refresh_ips()
        # Display internet status and speed initially
        self.refresh_status_speed()

    def refresh_status_speed(self):
        # Check internet status and speed
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            ping = st.results.ping
            download_speed = st.download() / 10**6  # Convert to Mbps
            upload_speed = st.upload() / 10**6  # Convert to Mbps

            self.status_value.config(text="Connected", fg="green")
            self.speed_value.config(text=f"Ping: {ping:.2f} ms | Download: {download_speed:.2f} Mbps | Upload: {upload_speed:.2f} Mbps")
        except Exception as e:
            self.status_value.config(text="Disconnected", fg="red")
            self.speed_value.config(text="Speedtest Error")

    def refresh_ips(self):
        # Clear previous IP addresses
        self.ip_listbox_v4.delete(0, tk.END)
        self.ip_listbox_v6.delete(0, tk.END)

        # Get and display IPv4 and IPv6 addresses
        ipv4_addresses, ipv6_addresses = self.get_ip_addresses()
        for ip in ipv4_addresses:
            self.ip_listbox_v4.insert(tk.END, ip)
        for ip in ipv6_addresses:
            self.ip_listbox_v6.insert(tk.END, ip)

    def get_ip_addresses(self):
        ipv4_addresses = []
        ipv6_addresses = []
        try:
            # Get hostname and all associated IPs
            hostname = socket.gethostname()
            ip_info = socket.getaddrinfo(hostname, None)

            # Extract IPv4 and IPv6 addresses
            for info in ip_info:
                ip_address = info[4][0]
                if ':' in ip_address:  # IPv6 address
                    ipv6_addresses.append(f"IPv6: {ip_address}")
                else:  # IPv4 address
                    ipv4_addresses.append(f"IPv4: {ip_address}")
        except Exception as e:
            ipv4_addresses.append("Error: " + str(e))
            ipv6_addresses.append("Error: " + str(e))

        return ipv4_addresses, ipv6_addresses

    def add_ip(self):
        # Get the IP address from the entry field
        ip_address = self.ip_entry.get()

        # Check if the input is a valid IP address
        try:
            socket.inet_pton(socket.AF_INET, ip_address)
            self.ip_listbox_v4.insert(tk.END, f"IPv4: {ip_address}")
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, ip_address)
                self.ip_listbox_v6.insert(tk.END, f"IPv6: {ip_address}")
            except OSError:
                print("Invalid IP address")

def main():
    root = tk.Tk()
    app = IPApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
