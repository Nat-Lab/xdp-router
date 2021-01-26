xdp-router
---

`xdp-router` is a bare-minimum XDP router implementation with basic IPv4 and IPv6 support. 

It works by "hijacking" traffic with ethertype 0x0800 (IP) and 0x86DD (IPv6), perform a lookup with `bpf_fib_lookup`, and redirect the packet directly to its outbound interface with `bpf_redirect`. 

This forwarding procress bypasses the Linux network stack entirely, which in theory makes the forwarding blazing-fast. This, however, means that the Linux network stack won't see the packet at all. Firewalls (`nftables`/`iptables`, etc.), or even `tcpdump`, won't be able to see or modify any IP and IPv6 traffic when `xdp-router` is enabled. (so NAT won't work either.)

Multicast, broadcast, and unicast traffic destinating the router itself will still be copied to the CPU (i.e., sent to the Linux network stack) for potential application (e.g., BGP speakers, OSPF routers, etc.) to consume. Non-IP/IPv6 traffics (e.g., ARP) are also sent to the Linux network stack.

### Building

```
# apt install build-essential clang llvm libelf-dev gcc-multilib linux-headers-`dpkg --print-architecture`
$ git clone https://github.com/nat-lab/xdp-router
$ cd xdp-router
$ git submodule update --init
$ make
```

### Usage

To forward with XDP on an interface, load the XDP executable on the interface with `ip-link`. For example, to forward traffic from `ens193f0` with XDP, do the following:

```
# ip link set ens193f0 xdp object ./router.o
```

Note: to verify if a NIC is using XDP, do `ip link`. If you see something like `xdpgeneric`, that means your NIC driver does not support XDP, and you are using a generic SKB-based non-optimized XDP path. It will unlikely to give you any performance gain, and you are better off not use it. [Here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)'s a nice list of NIC drivers with XDP support and their corresponding kernel version.

To disable it:

```
# ip link set ens193f0 xdp off
```

### Acknowledgement

I found the following documents and codes  useful during the writeup:

- https://github.com/xdp-project/xdp-tutorial (basics)
- https://github.com/jamesits/linux-gre-keepalive (the `Makefile` was copied from here)
- https://github.com/torvalds/linux/tree/master/samples/bpf (loads of examples)