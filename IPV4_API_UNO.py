import tkinter as tk
import socket

class IPApp:
    def __init__(self, master):
        self.master = master
        self.master.title("IPv4 Addresses")
        
        self.ip_label = tk.Label(master, text="Current IPv4 Addresses:")
        self.ip_label.pack()

        self.ip_listbox = tk.Listbox(master, width=50)
        self.ip_listbox.pack()

        self.refresh_button = tk.Button(master, text="Refresh", command=self.refresh_ips)
        self.refresh_button.pack()

        self.refresh_ips()  # Display IP addresses initially

    def refresh_ips(self):
        # Clear previous IP addresses
        self.ip_listbox.delete(0, tk.END)

        # Get and display IPv4 addresses
        ip_addresses = self.get_ipv4_addresses()
        for ip in ip_addresses:
            self.ip_listbox.insert(tk.END, ip)

    def get_ipv4_addresses(self):
        ipv4_addresses = []
        try:
            # Get hostname and all associated IPs
            hostname = socket.gethostname()
            ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)

            # Extract IPv4 addresses
            for addr in ip_addresses:
                ipv4_addresses.append(addr[4][0])
        except Exception as e:
            ipv4_addresses.append("Error: " + str(e))

        return ipv4_addresses

def main():
    root = tk.Tk()
    app = IPApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
