# IP_Project
Quality Based Routing considering link latency and available bandwidth on links

Project is developed on POX controller and emulated in ExoGENI using traffic D-ITG traffic generator.

*Installing POX (eel version) on controller module :

$ git clone http://github.com/noxrepo/pox
$ cd pox
~/pox$ git checkout eel


*Executing Program on pox controller as follows :

$cd pox
$./pox.py qos_routing

*Installing D-ITG traffic generators
$apt-get install ditg
$cd /var/cache/apt/archives
$ls
$dpkg -x d[TAB] d-itg(create a directory)

*Running D-ITG on a node as follows :

D-ITG as a receiver:

$cd /var/cache/apt/archives/d-itg/usr/bin
$./ITGRecv


D-ITG as a sender :
$cd /var/cache/apt/archives/d-itg/usr/bin
$./ITGSend -a <Destination-IP-Address> -b <tos> -C <no.of packets> -c <packet size> -t < time in milliseconds>


