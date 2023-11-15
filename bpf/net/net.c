#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14
#define AF_INET 2
#define AF_INET6 3

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
    if (daddr != 0xac120515) //  172.18.5.21
        return TC_ACT_OK;

    return 0x100001;
}

// ebpf可通过跟踪内核函数，统计不同层次的网络流量。各层的流量差异主要在于包头，重传，控制报文等等。

//    L4 TCP 纯数据流量：
//     上行：kprobe统计tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) size
//     下行：kprobe统计 tcp_cleanup_rbuf(struct sock *sk, int copied) copied

//     L4 UDP 纯数据流量：
//     上行：kprobe统计 udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) len
//     下行：kprobe统计 skb_consume_udp(struct sock *sk, struct sk_buff *skb, int len) len

//     L3 IP 流量
//     上行： kprobe统计 ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) skb->len
//     下行： kprobe统计 ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) skb->len

//     L2 全部网络包流量：
//     上行：tracepoint统计 net/net_dev_queue args->len
//     下行：tracepoint统计 net/netif_receive_skb args->len

struct ipv4_key_t
{
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

#define MAX_DATA_SIZE 4000

enum ssl_data_event_type
{
    kSSLRead,
    kSSLWrite
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, const char *);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

struct ssl_data_event_t
{
    enum ssl_data_event_type type;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    char data[MAX_DATA_SIZE];
    int32_t data_len;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tls_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

static __inline struct ssl_data_event_t *create_ssl_data_event(uint64_t current_pid_tgid)
{
    uint32_t kZero = 0;
    struct ssl_data_event_t *event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL)
    {
        return NULL;
    }

    const uint32_t kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;

    return event;
}

static int process_ssl_data(struct pt_regs *ctx, uint64_t id, enum ssl_data_event_type type,
                            const char *buf)
{
    int len = (int)(ctx)->ax;
    if (len < 0)
    {
        return 0;
    }

    struct ssl_data_event_t *event = create_ssl_data_event(id);
    if (event == NULL)
    {
        return 0;
    }

    event->type = type;
    // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
    event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE - 1)) : MAX_DATA_SIZE);
    bpf_probe_read(event->data, event->data_len, buf);
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(struct ssl_data_event_t));
    return 0;
}

//
SEC("uprobe/SSL_write")
int uprobe_ssL_write(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    //  uint32_t pid = current_pid_tgid >> 32;

    const char *buf = (const char *)(ctx)->si;
    bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    // uint32_t pid = current_pid_tgid >> 32;

    const char **buf = bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
    if (buf != NULL)
    {
        process_ssl_data(ctx, current_pid_tgid, kSSLWrite, *buf);
    }

    bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
    return 0;
}

// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
struct bpf_map_def SEC("maps") tcp_map = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct ipv4_key_t),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

// (struct sock *sk,struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int ktcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
    {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // FILTER_PID

    u16 family, lport, dport;
    u32 src_ip4, dst_ip4;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family != AF_INET)
    {
        return 0;
    }
    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

    struct ipv4_key_t ipv4_key = {.pid = pid};
    ipv4_key.saddr = src_ip4;
    ipv4_key.daddr = dst_ip4;
    ipv4_key.lport = lport;
    ipv4_key.dport = __bpf_ntohs(dport);

    if (src_ip4 == dst_ip4)
    {
        return 0;
    }
    u64 *valp = bpf_map_lookup_elem(&tcp_map, &ipv4_key);
    if (!valp)
    {
        u64 initval = 0;
        bpf_map_update_elem(&tcp_map, &ipv4_key, &initval, BPF_ANY);
        return 0;
    }
    long size = PT_REGS_PARM3(ctx);
    __sync_fetch_and_add(valp, size);
    return 0;
}

// SEC("kprobe/tcp_sendmsg")
// int ktcp_sendmsg(struct pt_regs *ctx)
// {
//     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
//     if (sk == NULL)
//     {
//         return 0;
//     }
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     // FILTER_PID

//     u16 family, lport, dport;
//     u32 src_ip4, dst_ip4;
//     bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

//     if (family != AF_INET)
//     {
//         return 0;
//     }
//     bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
//     bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
//     bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
//     bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

//     struct ipv4_key_t ipv4_key = {.pid = pid};
//     ipv4_key.saddr = src_ip4;
//     ipv4_key.daddr = dst_ip4;
//     ipv4_key.lport = lport;
//     ipv4_key.dport = __bpf_ntohs(dport);

//     if (src_ip4 == dst_ip4)
//     {
//         return 0;
//     }
//     u64 *valp = bpf_map_lookup_elem(&tcp_map, &ipv4_key);
//     if (!valp)
//     {
//         u64 initval = 0;
//         bpf_map_update_elem(&tcp_map, &ipv4_key, &initval, BPF_ANY);
//         return 0;
//     }
//     long size = PT_REGS_PARM3(ctx);
//     __sync_fetch_and_add(valp, size);
//     return 0;
// }

char __license[] SEC("license") = "GPL";