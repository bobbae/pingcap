# Agent demo

Client side agent should be runnable in a very limited environment
running on small micro controllers as well as larger systems and
still support encryption, ethernet level bootstrap communication to enable
traffic even before IP address is assigned, JSON parsing and
interop with Go.


## Winpcap and libpcap

On Windows and Linux pcap can be used to capture ethernet frames and
generate ethernet frames in C programs.  This can be done in a 
portable way that works both on Windows and Linux and other Unix
type systems that support pcap, such as MacOS.

Specific details can be found in agclient.c and agserve.c.

## JSON parsing

Minimalist json parsing in C can be used to parse payloads.
As long as a very simple layout is used, it is possible to use
minimal amount of code and still avoid having to binary 
encode payload.

## Encryption

Use very small crypto package, monocypher, to demo public key
encryption in a embedded C program.
