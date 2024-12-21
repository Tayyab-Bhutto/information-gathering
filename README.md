# information-gathering
import socket
import os
import sys
import dns.resolver
import threading

# Function to perform DNS lookup (gathering DNS information)
def dns_lookup(domain):
    print(f"\n[*] Performing DNS Lookup for {domain}")
    try:
        # Get A record (IP address)
        answers = dns.resolver.resolve(domain, 'A')
        for ip in answers:
            print(f"IP Address for {domain}: {ip}")
        
        # Get Name Servers (NS records)
        ns_records = dns.resolver.resolve(domain, 'NS')
        print(f"\nName Servers for {domain}:")
        for ns in ns_records:
            print(f"- {ns}")
    
    except Exception as e:
        print(f"[!] Error with DNS Lookup: {e}")

# Function to perform simple port scanning
def port_scan(target, ports):
    print(f"\n[*] Scanning target: {target}")
    open_ports = []

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout for the connection attempt
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    threads = []
    # Start a new thread for each port to speed up the scan
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    if open_ports:
        print(f"\nOpen Ports on {target}:")
        for port in open_ports:
            print(f"- {port}")
    else:
        print(f"No open ports found on {target}.")

# Main function to take user input and call relevant functions
def main():
    # Gather target details
    print("[*] Information Gathering & Scanning Script")
    target_domain = input("[+] Enter the domain or IP address to scan: ").strip()

    if not target_domain:
        print("[!] Please provide a valid domain or IP.")
        sys.exit(1)

    # Perform DNS lookup
    dns_lookup(target_domain)

    # Perform port scan (common ports)
    ports_to_scan = [22, 80, 443, 53, 21, 25, 110, 143, 8080, 3306]
    port_scan(target_domain, ports_to_scan)

if __name__ == "__main__":
    main()
