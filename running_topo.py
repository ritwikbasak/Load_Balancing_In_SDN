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

def myNetwork():
    def start_daemons(host):
        # host.cmd('iperf3 -s -t 1000 &')
        #print(f'python3 serverload_send.py {host.name} &')
        host.cmd(f'python3 serverload_send.py {host.name} &')
        host.cmd('python3 -m http.server 80 &')
    
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
    for i in range(5):
        client_list.append(net.addHost(f'c{i}'))

    # net.addNAT().configDefault()
    info( '* Add Server hosts sharing same virtual ip\n')
    server_hosts=[]
    
    process_list = []
    for i in range(1,6):
        # server_host = net.addHost(f'h{i}',cls=Host, ip=f'192.168.217.10{i}', mac = "00:00:00:00:00:0"+str(i), defaultRoute=None)
        # server_hosts.append(server_host)
        server_host = net.addHost(f'h{i}',cls=Host, ip=f'10.0.0.10{i}', mac = "00:00:00:00:00:0"+str(i), defaultRoute=None)
        process_list.append(multiprocessing.Process(target = start_daemons, args = (server_host, )))
        server_hosts.append(server_host)
        # net.addLink(s2, server_host)
    
    # server_hosts[0].send('hello world')
    # data = c0.recv()
    # info('data at controller =', data)

    info( '* Add links between host and switches \n')
    for host in server_hosts + client_list:
        net.addLink(host, s1)

    #info( '* Add links between server hosts and controller\n')
    for host in server_hosts:
        net.addLink(host, s2)
    
    info( '* Starting network\n')
    net.build()
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

    #client_host.cmd(f'ab -n 100 -c 10 http://10.0.0.10/ > {sys.argv[1]}.txt')
    
    def parallel_send(h):
        h.cmd(f'python3 getrequest.py {h.name[-1]} Least_loaded')
    # client_host.cmd('python3 getrequest.py 0 LeastLoaded')
    kkk = []
    for i in client_list:
        kkk.append(multiprocessing.Process(target = parallel_send, args = (i, )))
        kkk[-1].start()
    for i in kkk:
        i.join()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel( 'info' )
    myNetwork()