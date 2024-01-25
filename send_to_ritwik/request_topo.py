from mininet.net import Mininet
from mininet.node import Controller, Host
from mininet.cli import CLI

net = Mininet(controller=Controller)

c1 = net.addController('c1')
h1 = net.addHost('h1', ip='10.0.0.1')
s1 = net.addSwitch('s1')

net.addLink(h1, s1)
net.addLink(s1, c1)

net.start()

CLI(net)
