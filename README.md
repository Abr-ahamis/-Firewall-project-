
---

## **Firewall Project**

A **firewall** is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. This project is intended for **educational purposes** to help you understand how firewalls function.

### **Disclaimer**
This project is intended **only for educational purposes**. Unauthorized use of a firewall to block or manipulate network traffic without permission is illegal.

---

### **Features**

- Block or allow traffic based on IP addresses, ports, or protocols.
- Log all blocked and allowed traffic to a file.
- Simple command-line interface for managing rules.
- Supports basic TCP/UDP traffic filtering.
- Runs on Linux systems using `iptables` (requires root privileges).

---

### **How to Set Up and Use**

#### **1. Clone the Repository**

```bash
git clone https://github.com/your-username/firewall-project.git
cd firewall-project
```

#### **2. Install Requirements**

Make sure you have Python 3.x installed. Then, install the required libraries:

```bash
pip install argparse
```

#### **3. Run the Script**

```bash
sudo python firewall.py
```

---

### **Firewall Script Overview**

#### **How It Works**

1. The script uses `iptables` (Linux) to manage firewall rules.
2. It allows you to add, remove, or list rules for blocking or allowing traffic.
3. All blocked and allowed traffic is logged to a file for monitoring.

---

### **Key Sections of the Code**

```python
import os
import argparse
import subprocess

# Log file for firewall activity
LOG_FILE = "firewall_log.txt"

# Function to execute iptables commands
def run_iptables_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
        log_activity(f"Executed: {command}")
    except subprocess.CalledProcessError as e:
        log_activity(f"Error: {e}")

# Function to log firewall activity
def log_activity(message):
    with open(LOG_FILE, "a") as file:
        file.write(f"{message}\n")

# Function to add a rule
def add_rule(ip=None, port=None, protocol=None, action="DROP"):
    if ip:
        command = f"iptables -A INPUT -s {ip} -j {action}"
    elif port and protocol:
        command = f"iptables -A INPUT -p {protocol} --dport {port} -j {action}"
    else:
        log_activity("Invalid rule parameters")
        return
    run_iptables_command(command)

# Function to remove a rule
def remove_rule(ip=None, port=None, protocol=None, action="DROP"):
    if ip:
        command = f"iptables -D INPUT -s {ip} -j {action}"
    elif port and protocol:
        command = f"iptables -D INPUT -p {protocol} --dport {port} -j {action}"
    else:
        log_activity("Invalid rule parameters")
        return
    run_iptables_command(command)

# Function to list all rules
def list_rules():
    run_iptables_command("iptables -L -n -v")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple Firewall using iptables")
    parser.add_argument("--add", action="store_true", help="Add a rule")
    parser.add_argument("--remove", action="store_true", help="Remove a rule")
    parser.add_argument("--list", action="store_true", help="List all rules")
    parser.add_argument("--ip", type=str, help="IP address to block/allow")
    parser.add_argument("--port", type=int, help="Port number to block/allow")
    parser.add_argument("--protocol", type=str, help="Protocol (tcp/udp)")
    parser.add_argument("--action", type=str, default="DROP", help="Action (DROP/ACCEPT)")

    args = parser.parse_args()

    if args.add:
        add_rule(ip=args.ip, port=args.port, protocol=args.protocol, action=args.action)
    elif args.remove:
        remove_rule(ip=args.ip, port=args.port, protocol=args.protocol, action=args.action)
    elif args.list:
        list_rules()
    else:
        log_activity("No action specified")

if __name__ == "__main__":
    main()
```

---

### **How to Use the Firewall Script**

### **How to Use the Firewall Script**

The firewall script provides a simple command-line interface for managing firewall rules. Below are examples of how to use it:

---

#### **1. Add a Rule**
To block traffic from a specific IP address:
```bash
sudo python firewall.py --add --ip 192.168.1.100 --action DROP
```

To block traffic on a specific port and protocol:
```bash
sudo python firewall.py --add --port 22 --protocol tcp --action DROP
```

To allow traffic on a specific port and protocol:
```bash
sudo python firewall.py --add --port 80 --protocol tcp --action ACCEPT
```

---

#### **2. Remove a Rule**
To remove a rule blocking an IP address:
```bash
sudo python firewall.py --remove --ip 192.168.1.100 --action DROP
```

To remove a rule blocking a port and protocol:
```bash
sudo python firewall.py --remove --port 22 --protocol tcp --action DROP
```

---

#### **3. List All Rules**
To list all current firewall rules:
```bash
sudo python firewall.py --list
```

---

#### **4. Log File**
All firewall activity (blocked/allowed traffic and errors) is logged to `firewall_log.txt`. You can view the logs using:
```bash
cat firewall_log.txt
```

---

### **Advanced Features**

1. **Logging Traffic Details**  
   Modify the script to log detailed information about blocked/allowed traffic, such as timestamps, source IP, destination IP, and port.

2. **Persistent Rules**  
   Use `iptables-save` and `iptables-restore` to make firewall rules persistent across reboots.

3. **Rate Limiting**  
   Add rate-limiting rules to prevent brute-force attacks. For example:
   ```bash
   iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min -j ACCEPT
   iptables -A INPUT -p tcp --dport 22 -j DROP
   ```

4. **GUI for Rule Management**  
   Create a graphical user interface (GUI) using `tkinter` or `PyQt` to make it easier to manage rules.

---

### **Example: Logging Traffic Details**

Here’s how you can enhance the logging functionality to include more details:

```python
from datetime import datetime

def log_activity(message, ip=None, port=None, protocol=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    if ip:
        log_entry += f" | IP: {ip}"
    if port and protocol:
        log_entry += f" | Port: {port} | Protocol: {protocol}"
    with open(LOG_FILE, "a") as file:
        file.write(f"{log_entry}\n")
```

---

### **Example: Persistent Rules**

To make rules persistent across reboots:
1. Save the current rules:
   ```bash
   sudo iptables-save > /etc/iptables/rules.v4
   ```
2. Restore the rules on startup:
   Add the following line to `/etc/rc.local`:
   ```bash
   iptables-restore < /etc/iptables/rules.v4
   ```

---

### **README.md for GitHub**

Here’s a sample `README.md` for your GitHub repository:

```markdown
# Firewall Project

A simple firewall implementation using Python and `iptables` for educational purposes. This project demonstrates how to block or allow network traffic based on predefined rules.

## Features
- Block or allow traffic by IP, port, or protocol.
- Log all firewall activity to a file.
- Simple command-line interface for managing rules.

## Requirements
- Python 3.x
- Linux system with `iptables` installed.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/firewall-project.git
   cd firewall-project
   ```
2. Install dependencies:
   ```bash
   pip install argparse
   ```

## Usage
- Add a rule:
  ```bash
  sudo python firewall.py --add --ip 192.168.1.100 --action DROP
  ```
- Remove a rule:
  ```bash
  sudo python firewall.py --remove --ip 192.168.1.100 --action DROP
  ```
- List all rules:
  ```bash
  sudo python firewall.py --list
  ```

## Contributing
Contributions are welcome! Fork the repository and submit a pull request.



---

### **Example: Rate Limiting**

Here’s how you can add rate-limiting rules to prevent brute-force attacks on SSH:

```python
def add_rate_limiting():
    # Allow 5 connections per minute to SSH (port 22)
    run_iptables_command("iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/min -j ACCEPT")
    # Drop all other SSH traffic
    run_iptables_command("iptables -A INPUT -p tcp --dport 22 -j DROP")
```

### **Example: Whitelist and Blacklist Management**

You can manage whitelists and blacklists using a configuration file (`rules.json`):

```json
{
    "whitelist": [
        {"ip": "192.168.1.1", "port": 80, "protocol": "tcp"},
        {"ip": "192.168.1.2", "port": 443, "protocol": "tcp"}
    ],
    "blacklist": [
        {"ip": "10.0.0.1", "port": 22, "protocol": "tcp"},
        {"ip": "10.0.0.2", "port": 3389, "protocol": "tcp"}
    ]
}
```

Then, load and apply the rules in your script:

```python
import json

def load_rules():
    with open("rules.json", "r") as file:
        rules = json.load(file)
    
    for rule in rules["whitelist"]:
        add_rule(ip=rule.get("ip"), port=rule.get("port"), protocol=rule.get("protocol"), action="ACCEPT")
    
    for rule in rules["blacklist"]:
        add_rule(ip=rule.get("ip"), port=rule.get("port"), protocol=rule.get("protocol"), action="DROP")
```

---

### **Example: GUI for Rule Management**

Here’s a basic example using `tkinter` to create a GUI for managing rules:

```python
import tkinter as tk
from tkinter import messagebox

def add_rule_gui():
    ip = ip_entry.get()
    port = port_entry.get()
    protocol = protocol_entry.get()
    action = action_var.get()
    
    if ip or (port and protocol):
        add_rule(ip=ip, port=port, protocol=protocol, action=action)
        messagebox.showinfo("Success", "Rule added successfully!")
    else:
        messagebox.showerror("Error", "Invalid input")

# Create the main window
root = tk.Tk()
root.title("Firewall Rule Manager")

# IP Address
tk.Label(root, text="IP Address:").grid(row=0, column=0)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1)

# Port
tk.Label(root, text="Here’s the complete **Firewall Project** for your GitHub repository. This project demonstrates how to create a simple firewall using Python and `iptables` on Linux. It includes features like rule management, traffic logging, and a command-line interface.

---

## **Firewall Project**

### **Features**

- Block or allow traffic based on IP addresses, ports, or protocols.
- Log all blocked and allowed traffic to a file.
- Simple command-line interface for managing rules.
- Supports basic TCP/UDP traffic filtering.
- Runs on Linux systems using `iptables` (requires root privileges).

---

### **How to Set Up and Use**

#### **1. Clone the Repository**

```bash
git clone https://github.com/your-username/firewall-project.git
cd firewall-project
```

#### **2. Install Requirements**

Make sure you have Python 3.x installed. Then, install the required libraries:

```bash
pip install argparse
```

#### **3. Run the Script**

```bash
sudo python firewall.py
```

---

### **Firewall Script Overview**

#### **How It Works**

1. The script uses `iptables` (Linux) to manage firewall rules.
2. It allows you to add, remove, or list rules for blocking or allowing traffic.
3. All blocked and allowed traffic is logged to a file for monitoring.

---

### **Firewall Python Script**

```python
import os
import argparse
import subprocess
from datetime import datetime

# Log file for firewall activity
LOG_FILE = "firewall_log.txt"

# Function to execute iptables commands
def run_iptables_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return False

# Function to log firewall activity
def log_activity(action, rule):
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} - {action}: {rule}\n")

# Function to add a firewall rule
def add_rule(ip=None, port=None, protocol=None, action="DROP"):
    if not ip and not port:
        print("Error: You must specify an IP address or port.")
        return

    rule = f"iptables -A INPUT"
    if ip:
        rule += f" -s {ip}"
    if port:
        rule += f" -p {protocol or 'tcp'} --dport {port}"
    rule += f" -j {action}"

    if run_iptables_command(rule):
        log_activity("Rule Added", rule)
        print(f"Rule added: {rule}")
    else:
        print("Failed to add rule.")

# Function to remove a firewall rule
def remove_rule(ip=None, port=None, protocol=None, action="DROP"):
    if not ip and not port:
        print("Error: You must specify an IP address or port.")
        return

    rule = f"iptables -D INPUT"
    if ip:
        rule += f" -s {ip}"
    if port:
        rule += f" -p {protocol or 'tcp'} --dport {port}"
    rule += f" -j {action}"

    if run_iptables_command(rule):
        log_activity("Rule Removed", rule)
        print(f"Rule removed: {rule}")
    else:
        print("Failed to remove rule.")

# Function to list all firewall rules
def list_rules():
    run_iptables_command("iptables -L INPUT -v -n")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple Firewall Management Tool")
    parser.add_argument("--add", action="store_true", help="Add a new rule")
    parser.add_argument("--remove", action="store_true", help="Remove a rule")
    parser.add_argument("--list", action="store_true", help="List all rules")
    parser.add_argument("--ip", type=str, help="IP address to block/allow")
    parser.add_argument("--port", type=int, help="Port number to block/allow")
    parser.add_argument("--protocol", type=str, choices=["tcp", "udp"], help="Protocol (tcp/udp)")
    parser.add_argument("--action", type=str, choices=["DROP", "ACCEPT"], default="DROP", help="Action (DROP/ACCEPT)")

    args = parser.parse_args()

    if args.add:
        add_rule(ip=args.ip, port=args.port, protocol=args.protocol, action=args.action)
    elif args.remove:
        remove_rule(ip=args.ip, port=args.port, protocol=args.protocol, action=args.action)
    elif args.list:
        list_rules()
    else:
        print("Error: No action specified. Use --add, --remove, or --list.")

if __name__ == "__main__":
    main()
```
