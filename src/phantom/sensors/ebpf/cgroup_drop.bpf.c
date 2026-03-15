#include <linux/bpf.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

SEC("cgroup_skb/ingress")
int drop_ingress(struct __sk_buff *skb) {
    (void)skb;
    return 0;
}

SEC("cgroup_skb/egress")
int drop_egress(struct __sk_buff *skb) {
    (void)skb;
    return 0;
}

char _license[] SEC("license") = "GPL";
