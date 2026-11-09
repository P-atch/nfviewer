# NfViewer

Listen and work with an nf queue socket.

## Usage (as root)

```bash
A basic tool to listen for packets in Netfilter Queues

Usage: nfviewer [OPTIONS] --queue-id <QUEUE_ID>

Options:
  -q, --queue-id <QUEUE_ID>
  -w, --write-stdout         Write raw packets to stdout
  -f, --filename <FILENAME>  Write packets to this file (ignored if -w is used)
  -h, --help                 Print help
```

Allows to pipe raw packets to tcpdump: 
```bash
nfviewer -q 3 -w  2> /dev/null | tcpdump -r -
```
Same with Wireshark:
```bash
nfviewer -q 3 -w 2> /dev/null | wireshark -k -i -
```

Or write to a pcap: 
```bash
nfviewer -q 3 -f capture.pcap
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
