#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} input SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} output SEC(".maps");

SEC("sk_msg")
int sk_msg_redir_egress(struct sk_msg_md *msg)
{
	return bpf_msg_redirect_map(msg, &output, 0 /* key */, 0 /* flags */);
}

SEC("sk_msg")
int sk_msg_redir_ingress(struct sk_msg_md *msg)
{
        __u32 key = 0;

        if (msg->remote_port == bpf_htons(53))
                key = 1;

	return bpf_msg_redirect_map(msg, &output, key, BPF_F_INGRESS);
}

SEC("sk_skb")
int sk_skb_redir_egress(struct __sk_buff *skb)
{
        return bpf_sk_redirect_map(skb, &output, 0 /* key */, 0 /* flags */);
}

SEC("sk_skb")
int sk_skb_redir_ingress(struct __sk_buff *skb)
{
        return bpf_sk_redirect_map(skb, &output, 0 /* key */, BPF_F_INGRESS);
}
