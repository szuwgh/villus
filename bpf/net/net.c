#include <vmlinux.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <builtins.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14
#define AF_INET 2
#define AF_INET6 3
#define MAX_DATA_SIZE 4000
#define MAX_BUF_SIZE 1500

unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

static const char GET[3] = "GET";
static const char POST[4] = "POST";
static const char PUT[3] = "PUT";
static const char DELETE[6] = "DELETE";
static const char HTTP[4] = "HTTP";

struct so_event
{
    u32 src_addr;
    u32 dst_addr;
    u16 src_port;
    u16 dst_port;
    u32 payload_length;
};

// struct
// {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024);
// } httpevent SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} httpevent SEC(".maps");

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

struct data_key
{
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

struct data_value
{
    int timestamp;
    // char comm[64];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct data_key);
    __type(value, struct data_value);
    __uint(max_entries, 2048);
} proc_http_session SEC(".maps");

// SEC("kprobe/tcp_sendmsg")
// int http_tcp_sendmsg(struct pt_regs *ctx)
// {
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u64 uid_gid = bpf_get_current_uid_gid();

//     struct data_key key = {};
//     key.src_ip = htonl(saddr);
//     key.dst_ip = htonl(daddr);
//     key.src_port = sport;
//     key.dst_port = htons(dport);

//     struct data_value value = {};
//     value.pid = pid_tgid >> 32;
//     value.uid = (u32)uid_gid;
//     value.gid = uid_gid >> 32;
//     bpf_get_current_comm(value.comm, 64);

//     proc_http_datas.update(&key, &value);
//     return 0;
// }

SEC("socket")
int socket_hander(struct __sk_buff *skb)
{

    u8 verlen;
    u16 proto;
    u32 nhoff = ETH_HLEN;
    // u32 ip_proto = 0;
    u32 tcp_hdr_len = 0;
    u16 tlen;
    u32 payload_offset = 0;
    u32 payload_length = 0;
    u8 hdr_len;

    proto = skb->protocol;
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (ip_is_fragment(skb, nhoff))
        return 0;

    // 获取IP头部的长度
    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    hdr_len &= 0x0f;
    hdr_len *= 4;

    if (hdr_len < sizeof(struct iphdr))
    {
        return 0;
    }

    // 这行代码计算了TCP头部的偏移量。它将以太网帧头部的长度（nhoff）与IP头部的长度（hdr_len）相加，得到TCP头部的起始位置
    tcp_hdr_len = nhoff + hdr_len;
    bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);

    // 数据包中加载IP头部的总长度字段。IP头部总长度字段表示整个IP数据包的长度，包括IP头部和tcp 头部和数据部分。
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

    // 用于计算TCP头部的长度
    u8 doff;
    bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct tcphdr, ack_seq) + 4, &doff, sizeof(doff));
    doff &= 0xf0;
    doff >>= 4;
    doff *= 4;

    // 以太网帧头部长度、IP头部长度和TCP头部长度相加，得到HTTP请求的数据部分的偏移量，然后通过减去总长度、IP头部长度和TCP头部长度，计算出HTTP请求数据的长度
    payload_offset = ETH_HLEN + hdr_len + doff;
    payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

    char line_buffer[7];
    if (payload_length < 7 || payload_offset < 0)
    {
        return 0;
    }
    bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);

    if (__bpf_memcmp(line_buffer, GET, 3) != 0 &&
        __bpf_memcmp(line_buffer, POST, 4) != 0 &&
        __bpf_memcmp(line_buffer, PUT, 3) != 0 &&
        __bpf_memcmp(line_buffer, DELETE, 6) != 0 &&
        __bpf_memcmp(line_buffer, HTTP, 4) != 0)
    { // 如果不是http请求，查看是否有 http session
        return 0;
    }
    bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
    struct iphdr ip;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(struct iphdr));

    struct tcphdr tcp;
    bpf_skb_load_bytes(skb, ETH_HLEN + hdr_len, &tcp, sizeof(struct tcphdr));

    struct so_event e = {};
    bpf_printk("payload_length:%d", payload_length);
    // bpf_skb_load_bytes(skb, payload_offset, e->payload, 150);
    e.src_addr = ip.saddr;
    e.dst_addr = ip.daddr;
    e.src_port = __bpf_ntohs(tcp.source);
    e.dst_port = __bpf_ntohs(tcp.dest);

    bpf_perf_event_output(skb, &httpevent, ((__u64)skb->len << 32) | BPF_F_CURRENT_CPU, &e, sizeof(struct so_event));
    return skb->len;
}

/***********************************************************
 * tc限流 嗅探相关
 ***********************************************************/

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} tc_daddr_map SEC(".maps");

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
    // struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // unsigned long long daddr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
    u32 daddr;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, 4);

    u32 *valp = bpf_map_lookup_elem(&tc_daddr_map, &daddr);
    bpf_printk("daddr:%d", daddr);
    if (valp)
    {
        bpf_printk("daddr:%d,valp:%d", daddr, *valp);
        return *valp;
    }
    // uint16_t dstPortNumber = __bpf_ntohs(tcph->dest);
    //  if (dstPortNumber != 5201)
    //      return TC_ACT_OK;
    // if (daddr != 0xac120515) //  172.18.5.21
    //     return TC_ACT_OK;

    return TC_ACT_OK;
}

/***********************************************************
 * htts嗅探相关
 ***********************************************************/

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
    int len = (int)PT_REGS_RC(ctx);
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

/***********************************************************
 * 统计相关
 ***********************************************************/

struct ipv4_key_t
{
    u32 saddr;
    u32 daddr;
    //  u16 lport;
    // u16 dport;
};

struct bpf_map_def SEC("maps") ipv4_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct ipv4_key_t),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

//  tcp_sendmsg(struct sock *sk,struct msghdr *msg, size_t size)   size
SEC("kprobe/tcp_sendmsg")
int ktcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
    {
        return 0;
    }
    // u32 pid = bpf_get_current_pid_tgid() >> 32;
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

    struct ipv4_key_t ipv4_key = {};
    ipv4_key.saddr = src_ip4;
    ipv4_key.daddr = dst_ip4;
    //  ipv4_key.lport = lport;
    //  ipv4_key.dport = __bpf_ntohs(dport);

    if (src_ip4 == dst_ip4)
    {
        return 0;
    }
    u64 *valp = bpf_map_lookup_elem(&ipv4_send_bytes, &ipv4_key);
    if (!valp)
    {
        u64 initval = 0;
        bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &initval, BPF_ANY);
        return 0;
    }
    long size = PT_REGS_PARM3(ctx);
    __sync_fetch_and_add(valp, size);
    return 0;
}

struct bpf_map_def SEC("maps") ipv4_recv_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct ipv4_key_t),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

// tcp_cleanup_rbuf(struct sock *sk, int copied)   copied
SEC("kprobe/tcp_cleanup_rbuf")
int ktcp_cleanup_rbuf(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
    {
        return 0;
    }
    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    //  FILTER_PID

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

    struct ipv4_key_t ipv4_key = {};
    ipv4_key.saddr = src_ip4;
    ipv4_key.daddr = dst_ip4;

    if (src_ip4 == dst_ip4)
    {
        return 0;
    }
    u64 *valp = bpf_map_lookup_elem(&ipv4_recv_bytes, &ipv4_key);
    if (!valp)
    {
        u64 initval = 0;
        bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, &initval, BPF_ANY);
        return 0;
    }
    long size = PT_REGS_PARM2(ctx);
    __sync_fetch_and_add(valp, size);
    return 0;
}

char __license[] SEC("license") = "GPL";