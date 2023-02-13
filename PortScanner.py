import socket
import threading
import math
import subprocess
import platform
import time
import sys
import os
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Value
from datetime import datetime

# TODO: PRINT ALWAYS WHEN OPEN PORT FOUND AFTER EG. 
# Scanning Progress: 88.89%  | Currently scanned: 8/9 ports | Open ports found: 3

# TODO: MAKE MORE FEATURES
# Host discovery — probing by IP address and providing information on the systems that respond
# Port scanning — identifying services that are available for use
# Version detection — identifying applications and their versions
# OS detection — determining the operating system along with some hardware characteristics


def banner():
    print('''
      
$$$$$$$\                       $$\                                                                      
$$  __$$\                      $$ |                                                                     
$$ |  $$ | $$$$$$\   $$$$$$\ $$$$$$\          $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\  $$$$$$$\ $$$$$$\   $$$$$$\ 
$$$$$$$  |$$  __$$\ $$  __$$\\_$$  _|        $$  _____|$$  _____|\____$$\ $$  __$$\ $$  __$$\$$  __$$\ $$  __$$\ 
$$  ____/ $$ /  $$ |$$ |  \__| $$ |          \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |      $$ |  $$ |$$ |       $$ |$$\        \____$$\ $$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |       
$$ |      \$$$$$$  |$$ |       \$$$$  |      $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
\__|       \______/ \__|        \____/       \_______/  \_______|\_______|\__|  \__|\__|  \__| \_______|\__|
|                                                                                                          |
|----------------------------------------------------------------------------------------------------------|''')

def clear():
    if os.name == 'nt':
        _ = os.system('cls')
#mac/linux
    else:
        _ = os.system('clear')
clear()

def get_Host_name_IP(host):
    try:
        host_name = socket.gethostbyaddr(host)
        print("Hostname :  ", host_name)
    except:
        print("Unable to get Hostname and IP")

def get_host_info(host):
    try:
        hostname = socket.gethostbyaddr(host)[0]
    except:
        print("Unable to get information")

    try:
        response = os.system("ping -c 1 " + host)
    except Exception as e:
        print("Error Occured: ", e)
    if response == 0:
        print("\nHost: {} is up!\n".format(host))
        print("Hostname: ", hostname)
    else:
        print("\nHost: {} is down!\n".format(host))


def progressBar(progress, total):
    progress + 1
    percent = 100 * (progress / float(total))
    bar = '█' * math.floor(percent) +  '-' * (100 - math.floor(percent))
    if percent == 100:
        print(f"|{bar}| {percent:.2f}%")
    else:
        print(f"|{bar}| {percent:.2f}%", end = "\r")


def ping_scan(ip_address, start_ip, end_ip):
    for i in range(start_ip, end_ip + 1):
        host = ip_address + "." + str(i)
        response = subprocess.run(["ping", "-n", "1", host], stdout=subprocess.PIPE)
        if response.returncode == 0:
            arp_output = subprocess.run(["arp", host], stdout=subprocess.PIPE).stdout.decode()
            mac_address = arp_output.split()[3]
            manufacturer = get_manufacturer(mac_address)
            print(f"{host} is reachable. MAC: {mac_address} Manufacturer: {manufacturer}")
        else:
            print(f"{host} is not reachable.")
        
def ping_subnet(subnet):
    arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE).stdout.decode()
    for line in arp_output.split("\n"):
        if subnet in line:
            ip_address = line.split()[1].strip("(")[:-1]
            mac_address = line.split()[3]
            manufacturer = get_manufacturer(mac_address)
            print(f"{ip_address} has MAC: {mac_address} Manufacturer: {manufacturer}")
current_port = 0
lock = threading.Lock()
print_lock = threading.Lock()

def thread_scan(host, start_port, end_port, open_ports, progress, current_port, thread_count):
    progress.append(1)
    total_ports = end_port - start_port + 1
    try:
        addr = socket.getaddrinfo(host, None)[0][4][0]
    except socket.gaierror as e:
        with print_lock:
            print(f"Error Occured: {e}")
        return
    for port in range(start_port, end_port+1):
        #progressBar(current_port.value, total_ports)
        if (thread_count == 1):
            print(f"Scanning Progress: {sum(progress)/total_ports:.2%} ",
                "| Currently scanned: {}/{} ports ".format(current_port.value + 1, total_ports), end='\r')
        else:
            lock.acquire()
            print(f"Scanning Progress: {sum(progress)/total_ports / thread_count:.2%} ",
                "| Currently scanned: {}/{} ports ".format(current_port.value + thread_count, total_ports * thread_count), end='\r')
            lock.release()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((addr, port))
        if result == 0:
            open_ports.append(port)
        with current_port.get_lock():
            current_port.value += 1
            progress.append(1)
        with print_lock:
            sock.close()


def host_discovery(host):
    start_ip = host.split(".")[:-1]
    start_ip.append("1")
    start_ip = ".".join(start_ip)
    end_ip = host.split(".")[:-1]
    end_ip.append("255")
    end_ip = ".".join(end_ip)
    print(f"Scanning IP addresses from {start_ip} to {end_ip}")
    for ip in range(int(start_ip.split(".")[-1]), int(end_ip.split(".")[-1])+1):
        ip_address = f"{start_ip.split('.')[0]}.{start_ip.split('.')[1]}.{start_ip.split('.')[2]}.{ip}"
        print("CURRENT: {}".format(ip_address))
        try:
            host_name = socket.gethostbyaddr(ip_address)[0]
            print(f"{ip_address} - {host_name}")
        except socket.herror:
            pass


def scanOption(host, start_port, end_port):
    current_port = Value('i', 0)
    open_ports = []
    progress = []
    thread_count = int(input("Enter the number of threads to use: "))
    try:
        addr = socket.getaddrinfo(host, None)[0][4][0]
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        print("Starting a scan on: {} at {}".format(host, dt_string))
    except socket.gaierror as e:
        print(f"Error Occured: {e}")
        return
    get_Host_name_IP(addr)
    chunk_size = (end_port - start_port + 1) // thread_count
    threads = []
    for i in range(thread_count):
        start = start_port + i * chunk_size
        end = start_port + (i + 1) * chunk_size - 1
        if i == thread_count - 1:
            end = end_port
        t = threading.Thread(target=thread_scan, args=(
            host, start, end, open_ports, progress, current_port, thread_count))
        threads.append(t)
        t.start()

    total_ports = end_port - start_port + 1

    for t in threads:
        t.join()
    if current_port.value == total_ports:
        print("\nScanning Progress: Done!")
    save_to_file = input(
        "Do you want to save the open ports to a txt file? (y/n): ")

    if save_to_file.lower() == 'y':
        file_name = input(
            "Enter the name of the text file (eg: open_ports.txt): ")
        with open(file_name, 'w') as f:
            for port in open_ports:
                f.write(str(port) + '\n')
        print("Open ports saved to {}".format(file_name))
        main()
    else:
        print("Open ports on {}: {}".format(host, open_ports))
        main()

def invalidOption():
    for i in range(3):
        print("Invalid option!", end="\r")
        time.sleep(0.5)
        sys.stdout.write('\033[2K\r')
        time.sleep(0.5)


def main():
    clear()
    banner()
    print("[+] 1 for Port Scan")
    print("[+] 2 for Host Discovery")
    print("[+] 3 for Ping scan")
    print("[-] 4 for Exit")
    option = input("- Enter mode: ")
    if option == "1":
        try:
            host = input("- Enter the ip/domain to scan: ")
            clear()
            banner()
            option == 0
            print("Current target: [{}]".format(host))
            print("[+] 1 for Most common ports")
            print("[+] 2 for Custom port range")
            print("[+] 3 for Single ports")
            print("[-] 4 for To go back")
            option2 = input("- Enter mode: ")
            if option2 == "1":
                print("- Most common ports")
            elif option2 == "2":
                start_port = int(input("- Enter start port: "))
                end_port = int(input("- Enter end port: "))
                scanOption(host, start_port, end_port)
            elif option2 == "3":
                start_port = int(input("- Enter port: "))
                end_port = start_port
                scanOption(host, start_port, end_port)
            elif option2 == "4":
                option == 0
                option2 == 0
                time.sleep()
                main()
            else:
                invalidOption()
                time.sleep(1)
                main()
        except:
            main()
    
    elif option == "2":
        network_range = input("- Enter network range(eg: 192.168.1.0/24): ")
        host_discovery(network_range)
        return
    elif option == "3":
        ip_range = input("- Enter ip range (eg: 192.168.1.0-255): ")


        ip_parts = ip_range.split("-")
        ip_address = ip_parts[0]
        start_ip = int(ip_parts[0].split(".")[-1])
        end_ip = int(ip_parts[1])

        ip_parts = ip_address.split(".")
        ip_parts.pop()
        new_ip = ".".join(ip_parts)


        print("Start Range: ", start_ip)
        print("End Range: ", end_ip)
        print("ip_address: ", ip_address)
        
        ping_scan(new_ip, start_ip, end_ip)
        return
    elif option == "4":
        print("Exiting...")
        sys.exit()
    else:
        invalidOption()
        main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
