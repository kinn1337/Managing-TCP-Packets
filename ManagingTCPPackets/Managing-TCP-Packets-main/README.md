# Managing-TCP-Packets

This is a small program terminal that takes in a pcap file as a terminal input and outputs a chart in csv format stating the following for incomplete flows:
- Soure IP
- Source Port
- Destanation IP
- Destanation Port
- Complete Packets
- Incomplete Packets

And the following additional data values for complete flows:
- Total Bytes
- Average Bandwidth

A sample output can be seen below.

```
TCP Summary Table
165.230.140.98, 22, 24.187.209.82, 56444, 0, 1
24.187.209.82, 56444, 165.230.140.98, 22, 0, 1
165.230.140.98, 22, 24.187.209.82, 56472, 0, 8
165.230.140.98, 45766, 142.250.64.100, 80, 15, 1, 1205.0, 
222.2439024390244
142.250.64.100, 80, 165.230.140.98, 45766, 14, 0, 14584.0, 
2845.6585365853657
24.187.209.82, 56472, 165.230.140.98, 22, 0, 6

Additional Protocols Summary Table
UDP, 4, 340
ICMP, 0, 0
Other, 7, 420.000000
```
