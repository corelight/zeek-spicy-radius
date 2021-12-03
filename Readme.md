# zeek-spicy-radius

RFCs:

- https://datatracker.ietf.org/doc/html/rfc2865#section-3
- https://datatracker.ietf.org/doc/html/rfc3579

PCAP Source:

- https://wiki.wireshark.org/SampleCaptures#RADIUS_.28RFC_2865.29

Example Log:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	radius
#open	2021-12-03-20-57-07
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	username	nas_ip_addr	nas_port	framed_ip_addr	framed_ip_netmask	success
#types	time	string	addr	port	addr	port	enum	string	addr	count	addr	addr	bool
1440447767.446211	CHhAvVGS1DHFjwGM9	127.0.0.1	53031	127.0.0.1	1812	udp	steve	192.168.0.28	123	172.16.3.33	255.255.255.0	F
1440447839.948233	ClEkJM2Vm5giqnMf4h	127.0.0.1	65443	127.0.0.1	1812	udp	steve	192.168.0.28	123	172.16.3.33	255.255.255.0	T
1440447848.196390	C4J4Th3PJpwUYZZ6gc	127.0.0.1	57717	127.0.0.1	1812	udp	steve	192.168.0.28	123	172.16.3.33	255.255.255.0	T
1440447860.614016	CtPZjS20MLrsMUOJi2	127.0.0.1	64691	127.0.0.1	1812	udp	steve	192.168.0.28	123	172.16.3.33	255.255.255.0	T
1440447881.932731	CUM0KZ3MLUfNB0cl11	127.0.0.1	52178	127.0.0.1	1812	udp	steve	192.168.0.28	123	-	-	F
1440448190.335850	CP5puj4I8PtEU4qzYg	127.0.0.1	53127	127.0.0.1	1812	udp	steve	192.168.0.28	123	172.16.3.33	255.255.255.0	T
#close	2021-12-03-20-57-07
```