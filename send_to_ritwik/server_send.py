from logging import Logger
import sys
import requests, time, psutil, json
import socket

def calculate_server_load(host_name):

    # Calculate CPU utilization
    cpu_percent = psutil.cpu_percent(interval=1)
        
    # Calculate memory usage
    mem = psutil.virtual_memory()
    memory_usage = mem.percent
        
    # Calculate available disk space
    disk = psutil.disk_usage('/')
    disk_space = disk.free

    server_load = "Server: {}, CPU Utilization: {}%, Memory Usage: {}%, Disk Space: {} bytes".format(host_name, cpu_percent, memory_usage, disk_space)
        
    print(server_load)

    server_info = {
        'server_name': host_name,
        'cpu_utilization': cpu_percent,
        'memory_usage': memory_usage,
        'disk_space': disk_space
    }
    return server_info

if __name__ == "__main__":

    host_name = sys.argv[1]
    print(host_name)
    #Logger.info(host_name)
    controller_host = '127.0.0.1'
    controller_port = 5000  # Use the same port as in the controller
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((controller_host, controller_port))
        print("Connections successfull")
    except ConnectionRefusedError as e:
        print("Connection refused. Make sure the controller is running and reachable. " + str(e))
        time.sleep(1)
        
    except Exception as e:
        print(f"Error sending data: {e}")

    while True:
        server_info=calculate_server_load(host_name)
        info = json.dumps(server_info)
        server_socket.send(info.encode('utf-8'))
        time.sleep(10)
    

    




    








    