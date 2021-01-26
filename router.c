#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "router.h"

char _license[] SEC("license") = "GPL";

// helper: decr ttl by 1 for IP and IPv6
static inline void _decr_ttl(__u16 proto, void *h) {
    if (proto == ETH_P_IP) {
        struct iphdr *ip = h;
        __u32 c = ip->check;
        c += bpf_htons(0x0100);
        ip->check = (__u16)(c + (c >= 0xffff));
        --ip->ttl;
    } else if (proto == ETH_P_IPV6) --((struct ipv6hdr*) h)->hop_limit;
}

// main router logic
SEC("prog") int xdp_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    long rc;

    // invalid pkt: ethhdr overflow
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    // ptr to l3 protocol headers (or inner l2, if vlan)
    void *l3hdr = data + sizeof(struct ethhdr);

    // ethertype
    __u16 ether_proto = bpf_ntohs(eth->h_proto);

    struct bpf_fib_lookup fib_params = {};

    // vlan header found, just strip it.
    if (ether_proto == ETH_P_8021Q || ether_proto == ETH_P_8021AD) {
        // tagged pkt on non-trunked port, drop
        struct vlan_hdr *vhdr = l3hdr;
        if (l3hdr + sizeof(struct vlan_hdr) > data_end) return XDP_DROP;
        
        l3hdr += sizeof(struct vlan_hdr);
        ether_proto = vhdr->inner_ether_proto;
    }

    if (ether_proto == ETH_P_IP) {
        if (l3hdr + sizeof(struct iphdr) > data_end) return XDP_DROP;
        struct iphdr *ip = l3hdr;

        if (ip->ttl <= 1) return XDP_PASS;

        fib_params.family = AF_INET;
        fib_params.tos = ip->tos;
        fib_params.l4_protocol = ip->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;

        goto forward;
    }

    if (ether_proto == ETH_P_IPV6) {
        if (l3hdr + sizeof(struct ipv6hdr) > data_end) return XDP_DROP;
        struct ipv6hdr *ip6 = l3hdr;

        if (ip6->hop_limit <= 1) return XDP_PASS;

        fib_params.family = AF_INET6;
        fib_params.flowinfo = *(__be32 *) ip6 & bpf_htonl(0x0FFFFFFF);
        fib_params.l4_protocol = ip6->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip6->payload_len);
        *(struct in6_addr *) fib_params.ipv6_src = ip6->saddr;
        *(struct in6_addr *) fib_params.ipv6_dst = ip6->daddr;

        goto forward;
    }

    return XDP_PASS;

forward:
    fib_params.ifindex = ctx->ingress_ifindex;

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch(rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            _decr_ttl(ether_proto, l3hdr);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            return XDP_PASS;
    }

    return XDP_PASS;
}