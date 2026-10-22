# RnFilter

Listen and work with an nf queue socket.

Allows to pipe raw packets: 
```bash
rnfilter -q 3 -w  2> /dev/null | tcpdump -r -
```

Or write to a pcap: 
```bash
rnfilter -q 3 -f capture.pcap
```

(Debug usage) Follow the most usefull calls:
```bash
strace -f -x -e trace=sendmsg,recvmsg rnfilter -q 3
```