#include <uapi/linux/bpf.h>

/*
 * Socket filter used for pre-capture ring buffering.
 * Return skb->len to pass full packet to userspace raw socket.
 * Return 0 to drop the packet.
 */
int packet_filter(struct __sk_buff *skb) {
    if (skb->len == 0) {
        return 0;
    }
    return skb->len;
}

char _license[] SEC("license") = "GPL";

