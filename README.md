# NfViewer

Listen and work with an nf queue socket.

## Usage

Allows to pipe raw packets: 
```bash
nfviewer -q 3 -w  2> /dev/null | tcpdump -r -
```

Or write to a pcap: 
```bash
nfviewer -q 3 -f capture.pcap
```

(Debug usage) Follow the most usefull calls:
```bash
strace -f -x -e trace=sendmsg,recvmsg nfviewer -q 3
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