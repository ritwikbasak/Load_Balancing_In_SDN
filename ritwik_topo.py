import threading
import time, sys
import psutil
from mininet.net import Mininet
from mininet.topolib import TreeNet
from mininet.node import RemoteController
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import multiprocessing
import requests

def myNetwork():
    def start_daemons(host):
        host.cmd('python3 -m http.server 80 &')
        host.cmd(f'python3 serverload_send.py {host.name} &')
    
    clients = int(sys.argv[1])
    servers = int(sys.argv[2])
    net = Mininet( topo=None,
                   link=TCLink, #must be added in order to change link  parameters eg. bw,delay etc. 
                   build=False,
                   ipBase='10.0.0.0/8'
                   )

    info( '* Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      port=6653)

    info( '* Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls = OVSKernelSwitch)

    info( '* Add Client\n')
    client_list = []
    for i in range(clients):
        client_list.append(net.addHost(f'c{i}'))
    

    


    # net.addNAT().configDefault()
    info( '* Add Server hosts sharing same virtual ip\n')
    server_list=[]
    
    process_list = []
    for i in range(servers):
        # server_host = net.addHost(f'h{i}',cls=Host, ip=f'192.168.217.10{i}', mac = "00:00:00:00:00:0"+str(i), defaultRoute=None)
        # server_hosts.append(server_host)
        server_list.append(net.addHost(f'h{i}',cls=Host, ip=f'10.0.0.10{i}', mac = "00:00:00:00:00:0"+str(i), defaultRoute=None))
        process_list.append(multiprocessing.Process(target = start_daemons, args = (server_list[-1], )))
        # net.addLink(s2, server_host)
    
    # server_hosts[0].send('hello world')
    # data = c0.recv()
    # info('data at controller =', data)

    info( '* Add links between host and switches \n')
    for host in server_list + client_list:
        net.addLink(host, s1)

    #info( '* Add links between server hosts and controller\n')
    for host in server_list:
        net.addLink(host, s2)
    
    info( '* Starting network\n')
    net.build()
    # for i in client_list:
    #     i.cmd("python3 getrequest.py &")
    info( '* Starting controllers\n')
    for controller in net.controllers:
        controller.start()
        
    #net.addNAT().configDefault()

    info( '* Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])

    # server_threads = []

    # 
    
    
    


        # t = threading.Thread(target=calculate_server_load, args=(host_name,))
        # t.daemon = True  # Daemonize the thread
        # t.start()
    # server_threads.append(t)

    

    """for host in server_hosts:
        # host.cmd('xterm -e python3 server_deamon.py ' + host.name + ' > out' + host.name + '.txt 2>&1 &')
        host.cmd('xterm -e python3 server_deamon.py ' + host.name + ' &')"""
    
    """for host in server_hosts:
        print(f'Processes on {host.name}:')
        print(host.cmd('ps aux'))"""
    
    #server_hosts[0].cmd('xterm -e tail -f out' + server_hosts[0].name + '.txt &')



    info( '* Post configure switches and hosts\n')

    
    # server_hosts[1].cmd(cmd)

    for i in process_list:
        i.start()

    # total_time = 0.0
    # req_count = 0
    # def send_parallel_reqs(t1, t2, d):
    #     start_time = time.time_ns()
    #     for i in range(t2):
    #         t1.popen('wget 10.0.0.10')
    #     d[int((t1.name)[-1])] = (time.time_ns() - start_time) / (10 ** 6) # total time for t2 no. of reqs

    # # benchmarking_pool = [multiprocessing.Pool(processes = clients)]
    # # argument_list = [(i, 10) for i in client_list]
    # benchmarking_results = multiprocessing.Array('d', clients)
    # benchmarking_processes = []
    # for i in client_list:
    #     benchmarking_processes.append(multiprocessing.Process(target = send_parallel_reqs, args = (i, 10, benchmarking_results)))
    # # benchmarking_pool.join()

    # # print(f'{req_count} requests satisfied in time {total_time}\navg time = {total_time / req_count}')
    # # client_host.cmd(f'ab -n 100 -c 10 http://10.0.0.10/ > {sys.argv[1]}.txt')

    # for i in benchmarking_processes:
    #     i.start()
    # for i in benchmarking_processes:
    #     i.join()
    # print(*benchmarking_results)




    CLI(net)

    #time.sleep(5)

    

    net.stop()

if __name__ == "__main__":
    setLogLevel( 'info' )
    myNetwork()