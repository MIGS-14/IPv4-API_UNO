import tkinter as tk
import socket

class IPApp:
    def __init__(self, master):
        self.master = master
        self.master.title("IPv4 Addresses")
        self.master.config(bg="#E1F8DC")  # Set background color
        
        self.ip_frame = tk.Frame(master, bg="#E1F8DC")  # Frame for IP addresses
        self.ip_frame.pack(pady=10)

        self.ip_label = tk.Label(self.ip_frame, text="Current IPv4 Addresses:", bg="#f0f0f0")
        self.ip_label.pack()

        self.ip_listbox = tk.Listbox(self.ip_frame, width=50)
        self.ip_listbox.pack()

        self.button_frame = tk.Frame(master, bg="#E1F8DC")  # Frame for buttons
        self.button_frame.pack(pady=10)

        self.refresh_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_ips, bg="#d3d3d3", activebackground="#a9a9a9")
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.quit_button = tk.Button(self.button_frame, text="Quit", command=self.master.quit, bg="#d3d3d3", activebackground="#a9a9a9")
        self.quit_button.pack(side=tk.LEFT, padx=5)

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
