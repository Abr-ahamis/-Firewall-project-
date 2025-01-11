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
        print("No valid option provided. Use --help for usage information.")

if __name__ == "__main__":
    main()
