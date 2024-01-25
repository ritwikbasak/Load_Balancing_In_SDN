from logging import Logger
import sys
import requests, time, psutil, json
import socket
from scapy.all import Ether, IP, TCP, Raw, sendp, srp1,UDP

def calculate_server_load(host_name):

    # Calculate CPU utilization
    cpu_percent = psutil.cpu_percent(interval=1)
        
    # Calculate memory usage
    mem = psutil.virtual_memory()
    memory_usage = mem.percent
        
    # Calculate available disk space
    disk = psutil.disk_usage('/')
    disk_space = disk.free/(2**30)

    alpha = 0.85
    beta = 0.1
    load = cpu_percent * alpha + memory_usage * beta + disk_space * (1 - alpha - beta)
    # for cpu-extensive operations alpha = 0.85, beta = 0.1
    server_load = "Server: {}, CPU Utilization: {}%, Memory Usage: {}%, Disk Space: {} bytes".format(host_name, cpu_percent, memory_usage, disk_space)  
    print(server_load)
    return load

if __name__ == "__main__":

    host_name = sys.argv[1]
    print(host_name)
    while True:
    
        load=calculate_server_load(host_name)
        packet = Ether(dst="00:00:00:00:00:03", src="00:00:00:00:00:02") / IP(src="192.168.217.102", dst="255.255.255.255") / TCP(dport=81, sport=12345) / Raw(load = f'Load={load}-{host_name}')
        sendp(packet, iface=f'{host_name}-eth1')
        print("Sent the packets successfully")

        time.sleep(5)
    

    




    








    