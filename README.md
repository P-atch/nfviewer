# NfViewer

Listen and work with an nf queue socket.

## Usage

Allows to pipe raw packets to tcpdump: 
```bash
sudo nfviewer -q 3 -w  2> /dev/null | tcpdump -r -
```
Same with Wireshark:
```bash
sudo nfviewer -q 3 -w 2> /dev/null | wireshark -k -i -
```

Or write to a pcap: 
```bash
sudo nfviewer -q 3 -f capture.pcap
```

(Debug usage) Follow the most usefull calls:
```bash
strace -f -x -e trace=sendmsg,recvmsg sudo nfviewer -q 3
```


## Install

Via Cargo:
```bash
cargo install nfviewer
```

Manually:
```bash
git clone git@gitlab.com:P-atch/nfviewer.git
cargo install
```
