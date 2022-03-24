### pingscan

A tool to discover machines via ping and packet capture.

It is similar to arpscan.  But not using ARP and thus more portable.
Tested on linux and macosx.

strategy:

1. send out pings to a range specified by CIDR (e.g. 192.168.0.0/24)
2. use pcap to capture incoming packets to learn source ethernet
3. return list discovered machines with IP and Ethernet addr



Running (on macosx):

```
sudo pingscan -cidr 192.168.1.0/24 -dev en0 -timeout 10 -ouifile pingscan/ieee-oui.txt
```

Example output:
```
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.1 A06391418405 Netgear}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.36 8C8590B89AB8 Apple}
{192.168.1.3 D86C6343BB7D Google}
{192.168.1.5 ACBC3276D92D Apple}
{192.168.1.17 10DA433F5A94 Netgear}
{192.168.1.19 3412987286E8 Apple}
{192.168.1.3 D86C6343BB7D Google}
...
```



### IEEE OUI

the ieee-out.txt file was originally from http://standards.ieee.org/develop/regauth/oui/oui.txt

However, over the years the format of the file changed and it is no longer easily parsable.
Instead the nmap project has compatible format file which has updated latest files.

http://linuxnet.ca/ieee/oui/nmap-mac-prefixes

which can be used as ieee-oui.txt

### Running on Linux:

```
sudo go run pingscan/main.go -cidr 10.0.2.0/24 -dev eth0 -timeout 10 -ouifile pingscan/ieee-oui.txt
```

### Building docker image

First build a statically linked pingscan.

```
cd pingscan
make
```

Then docker build.


```
docker build -t pingscan .
```

### Testing using docker image

First run a few docker containers which will be found when you run pingscan. 

```
docker run --rm alpine sleep 100 &
docker run --rm alpine sleep 100 &
docker run --rm alpine sleep 100 &
docker run --rm alpine sleep 100 &
```

Then run pingscan

```
docker run --rm pingscan
```

### Testing using docker-compose

```
docker-compose up
```

The details in docker-compose.yml file.

It creates two networks.  Puts two alpine nodes in one network. One more in another. 
Then one pingscan is put in one of the networks and another pingscan in another.
The first pingscan will find two nodes. The second one will find one.


