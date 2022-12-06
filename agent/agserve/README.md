## What this is

The agent server is a Go program while the agent is in C.
The agent server program uses CGO interface to agrelay to
use C implementation of functions in pcap and monocypher.
The packets captured via pcap in agent relay will be sent to
the Go routine inside agent server via local UDP socket, and
the packet is processed in Go and replies are generated
and sent back to pcap via CGO interface.


## Golang version 1.19.3 and later
When you see an error like: cgo: malformed DWARF TagVariable entry   

Update golang to latest: at least 1.19.3.
https://github.com/golang/go/issues/53000

## Gcc version

If you see an error like:  unrecognized option '--high-entropy-va'
Update your gcc to latest version.

### Windows gcc
clang version 15.0.0 (https://github.com/llvm/llvm-project.git 4ba6a9c9f65bbc8bd06e3652cb20fd4dfc846137)

