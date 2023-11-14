#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14
SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{

    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

// static __inline unsigned int set_bandwidth(struct __sk_buff *skb)

// {

//     __u32 proto;
//     __u64 delay, now, t, t_next;
//     __u64 ret;
//     proto = skb->protocol;
//     if (proto != bpf_htons(ETH_P_IP) &&
//         proto != bpf_htons(ETH_P_IPV6))
//         return 0;

//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;
//     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
//     {
//         return 0;
//     }
//     struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
//     unsigned long long daddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
//     // unsigned long long saddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
//     uint16_t dstPortNumber = ntohs(tcph->dest);
//     // if (dstPortNumber != 60443)
//     //  return 0;
//     if (daddr != 0x0a0a2819) // 10.10.40.25
//         return 0;

//     // printk("get classid ok %x", skb->tc_classid);

//     // skb->tc_classid=0x10001;

//     // printk("set classid ok");

//     return 0x10002;
// }

// SEC("tc-ingress")
// unsigned int tc_bandwidth(struct __sk_buff *skb)

// {

//     return set_bandwidth(skb);
// }
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

SEC("tc-egress")
unsigned int tc_egress(struct __sk_buff *skb)
{
    __u32 proto;
    proto = skb->protocol;
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return TC_ACT_OK;
    }
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    unsigned long long daddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
    uint16_t dstPortNumber = __bpf_ntohs(tcph->dest);

    if (dstPortNumber != 5201)
        return TC_ACT_OK;
    bpf_printk("get dstPortNumber %x", dstPortNumber);
    if (daddr != 0xac120515) //  172.18.5.21
        return TC_ACT_OK;
    bpf_printk("get daddr %x", daddr);

    // skb->tc_classid = 0x100001;
    // bpf_printk("get classid ok %d", skb->tc_classid);
    // printk("set classid ok");

    return 0x100001;
}

char __license[] SEC("license") = "GPL";