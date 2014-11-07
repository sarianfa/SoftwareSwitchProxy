SoftwareSwitchProxy
===================
The main functionality is implemnted in virtualizer.py.
There are 2 versions of virtualizer.py one for openflow version 1.0 (of1.0/virtualizer.py) and one for openflow version 1.3 
(of1.3/virtualizer.py). of1.0/virtualizer.py uses "pox" libraries, while of1.3/virtualizer.py uses an updated set of "ryu" 
libraries. 
Note: because of1.0 does not support all the required features, of1.0/virtualizer.py only support a limited set 
of functionalities and it is not going to be improved any furthur for now.

Requirments on the machine
===================
To run the virtualizer you need to have an openflow switch installed on the machine you want to run the virtualzier. 
You also need a harware switch that is connected to your machine through one trunk port.
You should set the openflow version of the switch to match the version of the virtualizer.py that you want to run. 
For instance, in case of of1.3/virtualzier.py you might need the follwing settings for the OVS:

sudo /sbin/service openvswitch start
sudo ovs-vsctl add-br bridge0
sudo ovs-vsctl set bridge bridge0 protocols=OpenFlow13
sudo ovs-vsctl set-controller bridge0 tcp:127.0.0.1:9050

Where tcp:127.0.0.1:9050 is the address/port where the virtualizer.py will be running. 

The number of ports that are needed on the bridge0 is atleast one port that is defined on the interface that is physically 
connected to the hardware switch. The conencted port on the hardware swicth MUST be a trunk port. In our example scenario 
this port is connetced to the ovs machien through eth4. So we added the following port:

sudo ifconfig eth4 up
sudo ovs-vsctl add-port bridge0 eth4

ORDERING MATTERS
This physical interface must be the first interface that gets added to the OVS.

Depending on the number of ports on the hardware switch that you want to mirror on the software switch (in our case OVS), 
you should add those as virtual ports on the OVS. In our case we had:

sudo ovs-vsctl add-port bridge0 etp2 -- set interface etp2 type=internal
sudo ovs-vsctl add-port bridge0 etp3 -- set interface etp3 type=internal

where etp2 and etp3 are virtual interfaces that we created locally and are not connecte dto anything else in the system.

Requirements to change virtualizer.py 
===================
Depending on where the controllers for each customer are running, the controller IP address and ports need to change 
in the virtualizer.py. 
Depending on the customer ids and the ports/Vlan numebrs associated to each customer the initialized ports/vlan mappings 
need to change. 


The default parameters on the virtualizer.py are based on the following topology:


------------------------
|                       |--------|controller 1   
| | OVS | |virtualier|  |--------|controller 2
|       SS Machine      |
------------------------
     |eth4  
     |trunk
----------------
|               | 
|Hardware switch|
----------------
   |vlan 5     |vlan 6
machine 1     machine2

