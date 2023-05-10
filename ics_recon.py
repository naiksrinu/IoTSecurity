# ICS Recon Script Ver 1.8
# Performs ICS Devices Scanning, Protocols, CVE scan
# __author__ = Naik 
# Description : The ICS Recon script provides a set of security-related tasks that can be performed for network scanning, protocol identification, system information discovery, and application identification. 
# The advantages of this script include the ability to quickly identify open ports on a given network range, get real-time log analysis for network traffic, monitor critical system resources like CPU and memory usage, 
# and identify potential vulnerabilities in web applications. Further, it will evolve machine learning algorithms  integrated within  to provide more accurate predictions of potential system vulnerabilities and threats # detection.

import argparse
import json
import os
import psutil
import requests
from scapy.all import *
import nmap


def network_scanning(network_range):
    scanner = nmap.PortScanner()
    scanner.scan(network_range, arguments="-p-")
    open_ports = {}
    for host in scanner.all_hosts():
        for port in scanner[host]["tcp"]:
            open_ports[port] = scanner[host]["tcp"][port]["name"]
    output = {"Open Ports": open_ports}
    print(json.dumps(output, indent=4))


def protocol_identification():
    def packet_handler(packet):
        if packet.haslayer(TCP):
            tcp_pkt = packet[TCP]
            src_port = tcp_pkt.sport
            dst_port = tcp_pkt.dport
            print(f"TCP packet from {packet.src} to {packet.dst}: src port {src_port}, dst port {dst_port}")

    sniff(filter="tcp", prn=packet_handler)


def system_info_discovery():
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage("/").percent

    output = {
        "CPU Usage": cpu_usage,
        "Memory Usage": memory_usage,
        "Disk Usage": disk_usage
    }

    print(json.dumps(output, indent=4))


def application_identification():
    target_url = input("Enter target URL: ")

    response = requests.get(target_url)

    if "application_version" in response.text:
        app_version = response.text.split("application_version")[1].split(">")[1].split("<")[0]

        cve_list = get_cve_list(app_version)

        output = {"Application Version": app_version, "CVE List": cve_list}

        print(json.dumps(output, indent=4))

    else:
        print("Application version not found on target")


def get_cve_list(version):
    command = f"searchsploit {version}"

    output = os.popen(command).read()

    cve_list = []

    for line in output.split("\n"):
        if "CVE-" in line:
            cve_list.append(line)

    return cve_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform various security-related tasks")
    parser.add_argument("option", type=int, help="Select an option: 1. Network Scanning, 2. Protocol Identification, "
                                                 "3. System Information Discovery, 4. Application Identification")
    parser.add_argument("--network-range", help="The network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--target-url", help="The URL of the target application")

    args = parser.parse_args()

    if args.option == 1:
        if not args.network_range:
            print("Error: network range must be specified")
            exit(1)
        network_scanning(args.network_range)
    elif args.option == 2:
        protocol_identification()
    elif args.option == 3:
        system_info_discovery()
    elif args.option == 4:
        if not args.target_url:
            print("Error: target URL must be specified")
            exit(1)
        application_identification(args.target_url)
    else:
        print("Invalid option selected")
