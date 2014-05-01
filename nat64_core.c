#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>

#include "nat64.h"
#include "nat64_session.h"
#include "nat64_factory.h"

#define NAT64_NETDEV_NAME KBUILD_MODNAME

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Julius Kriukas <julius@kriukas.lt>");
MODULE_DESCRIPTION("Linux NAT64 implementation (PLAT)");

struct kmem_cache	*session_cache;
struct kmem_cache	*bib_cache;

struct list_head	exipry_queue = LIST_HEAD_INIT(exipry_queue);

struct expiry_q	expiry_base[NUM_EXPIRY_QUEUES] =
{
	{{NULL, NULL}, 5*60},
	{{NULL, NULL}, 4*60},
	{{NULL, NULL}, 2*60*60},
	{{NULL, NULL}, 6},
	{{NULL, NULL}, 60}
};

struct net_device	*nat64_dev;

struct hlist_head	*hash6;
struct hlist_head	*hash4;
unsigned int		hash_size;

__be32       ipv4_addr = 0;
__be32       ipv4_netmask = 0xffffffff;
int          ipv4_prefixlen = 32;

static char *ipv4_prefix = NULL;
module_param(ipv4_prefix, charp, 0);
MODULE_PARM_DESC(ipv4_prefix, "IPv4 prefix (or address) used for NAT64 service, for example \"198.51.100.0/24\".");

struct in6_addr  prefix_base = {.s6_addr32[0] = 0, .s6_addr32[1] = 0, .s6_addr32[2] = 0, .s6_addr32[3] = 0};
int              prefix_len = 96;

static char     *ipv6_prefix = "64:ff9b::/96";
module_param(ipv6_prefix, charp, 0);
MODULE_PARM_DESC(ipv6_prefix, "IPv6 prefix used for NAT64 service address, default is \"64:ff9b::/96\".");

static void clean_expired_sessions(struct list_head *queue)
{
	struct list_head	*pos;
	struct list_head	*n;
	struct list_head	*next_session;
	struct session_entry	*session;
	struct bib_entry	*bib;
	int			i = 0;

	list_for_each_safe(pos, n, queue) {
		++i;
		session = list_entry(pos, struct session_entry, byexpiry);
		if(time_after(jiffies, session->expires)) {
			if(tcp_timeout_fsm(session))
				continue;
			//printk("nat64: [garbage-collector] removing session %pI4:%hu\n", &session->remote4_addr, ntohs(session->remote4_port));
			list_del(pos);
			next_session = session->list.next;
			list_del(&session->list);
			if(list_empty(next_session)) {
				bib = list_entry(next_session, struct bib_entry, sessions);
				//printk("nat64: [garbage-collector] removing bib %pI6c,%hu <--> %pI4:%hu\n", &bib->remote6_addr, ntohs(bib->remote6_port), &bib->local4_addr, ntohs(bib->local4_port));
				hlist_del(&bib->byremote);
				hlist_del(&bib->bylocal);
				kmem_cache_free(bib_cache, bib);
			}
			kmem_cache_free(session_cache, session);
		}
		else
		    break;
	}
	//printk("nat64: [garbage-collector] [0x%08x] iterations: %d.\n", (unsigned int)queue, i);
}

static void nat64_translate_6to4(struct sk_buff *old_skb, struct bib_entry *bib, __be16 dport, int proto)
{
	struct sk_buff	*skb;
	int		skb_len = LL_MAX_HEADER + sizeof(struct iphdr) + old_skb->len;

	switch(proto) {
	case IPPROTO_UDP:
		skb_len += sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		skb_len += tcp_hdrlen(old_skb);
		break;
	case IPPROTO_ICMP:
		skb_len += sizeof(struct icmphdr);
		break;
	}

	//printk("nat64: [6to4] Generating IPv4 packet %d.\n", skb_len);
	skb = alloc_skb(skb_len, GFP_ATOMIC);


	if (!skb) {
		printk("nat64: [6to4] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}
//	skb_reserve(skb, LL_MAX_HEADER);
	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(proto) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb, bib->local4_port, dport);
 		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, bib->local4_port, dport, tcp_hdrlen(old_skb));
		break;
	case IPPROTO_ICMP:
		factory_clone_icmp(old_skb, skb, bib->local4_port, dport);
		break;
	}

	factory_translate_ip6(old_skb, skb, bib->local4_addr, proto);

	skb->dev = nat64_dev;
	netif_rx(skb);
}

/*static struct bib_entry *ipv6_bib_lookup__(struct in6_addr saddr, __be32 daddr, __be16 sport, __be16 dport, int type)
{
	struct bib_entry	*bib;
	struct session_entry	*session;

	bib = bib_ipv6_lookup(&saddr, sport, type);

	if(!bib) {
		bib = bib_session_create(&saddr, daddr, sport, dport, type, UDP_DEFAULT);
	}
	else {
		session = session_ipv4_lookup(bib, daddr, dport);

		if(session)
			session_renew(session, UDP_DEFAULT);
		else
			session = session_create(bib, daddr, dport, UDP_DEFAULT);
	}

	return bib;
}*/

void inline nat64_handle_icmp6(struct sk_buff *skb, struct ipv6hdr *ip6h)
{
	struct icmphdr		*icmph;
	struct bib_entry	*bib;
	struct session_entry	*session;
	__be16			new_type;

	icmph = (struct icmphdr *)skb->data;
	skb_pull(skb, sizeof(struct icmphdr));

	if(icmph->type >> 7) {
		// Informational ICMP
		if(icmph->type == ICMPV6_ECHO_REQUEST)
			new_type = (ICMP_ECHO << 8) + icmph->code;
		else if(icmph->type == ICMPV6_ECHO_REPLY)
			new_type = (ICMP_ECHOREPLY << 8) + icmph->code;
		else
			return;

		bib = bib_ipv6_lookup(&ip6h->saddr, icmph->un.echo.id, IPPROTO_ICMP);
		if(bib) {
			session = session_ipv4_lookup(bib, extract_ipv4(ip6h->daddr, prefix_len), icmph->un.echo.id);

			if(session)
				session_renew(session, ICMP_DEFAULT);
			else
				session = session_create(bib, extract_ipv4(ip6h->daddr, prefix_len), icmph->un.echo.id, ICMP_DEFAULT);
		}
		else
			bib = bib_session_create(&ip6h->saddr, extract_ipv4(ip6h->daddr, prefix_len), icmph->un.echo.id, icmph->un.echo.id, IPPROTO_ICMP, ICMP_DEFAULT);

		nat64_translate_6to4(skb, bib, new_type, IPPROTO_ICMP);
	} else {
		// Error ICMP
		switch(icmph->type) {
		case ICMPV6_TIME_EXCEED:
			printk("nat64: [icmp6] Time Exceeded ICMPv6 type %hhu (Code: %hhu)\n", icmph->type, icmph->code);
			break;
		default:
			printk("nat64: [icmp6] Unknown ICMPv6 type %hhu (Code: %hhu)\n", icmph->type, icmph->code);
		}
		return;
	}
	//printk("nat64: [icmp6] Forwarding ECHO, new_type = %d\n", new_type);
}

int nat64_netdev_ipv6_input(struct sk_buff *old_skb)
{
	int	i;
	struct ipv6hdr	*ip6h = ipv6_hdr(old_skb);
	const struct udphdr	*udph;
	const struct tcphdr	*tcph;
	u8			proto;
	struct bib_entry	*bib;
	struct session_entry	*session;

	/* Skip empty or non IPv6 packets */
	if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6)
		return -1;

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {//||
	    //(!(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST))) {
		printk("nat64: [ipv6] source address is not unicast.\n");
		return -1;
	}

	// Check if destination address falls into nat64 prefix
	if(memcmp(&ip6h->daddr, &prefix_base, prefix_len / 8))
		return -1;

	skb_pull(old_skb, sizeof(struct ipv6hdr));
	proto = ip6h->nexthdr;

	//printk("NAT64: Incoming packet properties: [nexthdr = %d] [payload_len = %d] [old_skb->len = %d]\n", ip6h->nexthdr, ntohs(ip6h->payload_len), old_skb->len);
	//pr_debug("NAT64: Target registration information min_ip = %d, max_ip = %d\n", info->min_ip, info->max_ip);

	clean_expired_sessions(&exipry_queue);
	for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
		clean_expired_sessions(&expiry_base[i].queue);

	switch(proto) {
	case NEXTHDR_TCP:
		tcph = (struct tcphdr *)old_skb->data;
		skb_pull(old_skb, tcp_hdrlen(old_skb));

		bib = bib_ipv6_lookup(&ip6h->saddr, tcph->source, IPPROTO_TCP);
		if(bib) {
			session = session_ipv4_lookup(bib, extract_ipv4(ip6h->daddr, prefix_len), tcph->dest);

			if(session)
				tcp6_fsm(session, tcph);
			else
				session = session_create(bib, extract_ipv4(ip6h->daddr, prefix_len), tcph->dest, TCP_TRANS);
		}
		else if(tcph->syn)
		{
			bib = bib_session_create(&ip6h->saddr, extract_ipv4(ip6h->daddr, prefix_len), tcph->source, tcph->dest, IPPROTO_TCP, TCP_TRANS);
			if(!bib)
				return -1;

			session = list_entry(bib->sessions.next, struct session_entry, list);
			session->state = V6_SYN_RCV;
		}
		else
			return -1;

		nat64_translate_6to4(old_skb, bib, tcph->dest, IPPROTO_TCP);
		//nat64_generate_tcp(old_skb, ip6h, bib);
		return 0;
		break;
	case NEXTHDR_UDP:
		udph = (struct udphdr *)old_skb->data;
		skb_pull(old_skb, sizeof(struct udphdr));

		bib = bib_ipv6_lookup(&ip6h->saddr, udph->source, IPPROTO_UDP);
		if(bib) {
			session = session_ipv4_lookup(bib, extract_ipv4(ip6h->daddr, prefix_len), udph->dest);

			if(session)
				session_renew(session, UDP_DEFAULT);
			else
				session = session_create(bib, extract_ipv4(ip6h->daddr, prefix_len), udph->dest, UDP_DEFAULT);
		}
		else
			bib = bib_session_create(&ip6h->saddr, extract_ipv4(ip6h->daddr, prefix_len), udph->source, udph->dest, IPPROTO_UDP, UDP_DEFAULT);


		nat64_translate_6to4(old_skb, bib, udph->dest, IPPROTO_UDP);
		return 0;
		break;
	case NEXTHDR_ICMP:
		nat64_handle_icmp6(old_skb, ip6h);
		return 0;
		break;
	default:
		printk("nat64: [ipv6] Next header %d. Currently only TCP, UDP and ICMP6 is supported.\n", proto);
		return -1;
		break;
	}
}

static void nat64_translate_4to6_deep(struct sk_buff *old_skb, struct bib_entry *bib, __be16 sport)
{
	struct sk_buff	*skb;
	struct iphdr	*iph;
	struct tcphdr	*tcph;
	struct udphdr	*udph;
	struct in6_addr	remote6;
	int		skb_len = LL_MAX_HEADER + sizeof(struct ipv6hdr) + sizeof(struct icmphdr) + sizeof(struct ipv6hdr);

	iph = (struct iphdr *)old_skb->data;
 	skb_pull(old_skb, iph->ihl * 4);

	tcph = NULL;
	udph = NULL;
	switch(iph->protocol) {
	case IPPROTO_UDP:
		udph = (struct udphdr *)old_skb->data;
		skb_len += sizeof(struct udphdr);
		skb_pull(old_skb, sizeof(struct udphdr));
		break;
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)old_skb->data;
		skb_len += tcph->doff * 4;
		skb_pull(old_skb, tcph->doff * 4);
		break;
	}

	skb_len += old_skb->len;

	//printk("nat64: [4to6] Generating IPv6 packet.\n");
	skb = alloc_skb(skb_len, GFP_ATOMIC);

	if (!skb) {
		printk("nat64: [4to6] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}

	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(iph->protocol) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb, bib->remote6_port, udph->dest);
		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, bib->remote6_port, tcph->dest, tcph->doff * 4);
		break;
	}

	assemble_ipv6(&remote6, iph->daddr);
	factory_translate_ip4(old_skb, skb, &bib->remote6_addr, &remote6, iph->protocol, iph->ihl * 4);
	factory_clone_icmp(old_skb, skb, 0, sport);
	assemble_ipv6(&remote6, ip_hdr(old_skb)->saddr);
	factory_translate_ip4(old_skb, skb, &remote6, &bib->remote6_addr, IPPROTO_ICMPV6, ip_hdrlen(old_skb));

	skb->dev = nat64_dev;
	nat64_dev->stats.rx_packets++;
	nat64_dev->stats.rx_bytes += skb->len;
	netif_rx(skb);

//	printk("nat64: [ipv4] Sending translated IPv6 packet.\n");
}

static void nat64_translate_4to6(struct sk_buff *old_skb, struct bib_entry *bib, __be16 sport, int proto)
{
	struct sk_buff	*skb;
	struct in6_addr	remote6;
	int		skb_len = LL_MAX_HEADER + sizeof(struct ipv6hdr) + old_skb->len;

	switch(proto) {
	case IPPROTO_UDP:
		skb_len += sizeof(struct udphdr);
		break;
	case IPPROTO_TCP:
		skb_len += tcp_hdrlen(old_skb);
		break;
	case IPPROTO_ICMPV6:
		skb_len += sizeof(struct icmphdr);
		break;
	}

	//printk("nat64: [4to6] Generating IPv6 packet.\n");
	skb = alloc_skb(skb_len, GFP_ATOMIC);

	if (!skb) {
		printk("nat64: [4to6] Unable to allocate memory for new skbuff structure X(.\n");
		return;
	}
	skb_reserve(skb, skb_len);
	factory_clone_data(old_skb, skb);

	switch(proto) {
	case IPPROTO_UDP:
		factory_clone_udp(old_skb, skb, sport, bib->remote6_port);
		break;
	case IPPROTO_TCP:
		factory_clone_tcp(old_skb, skb, sport, bib->remote6_port, tcp_hdrlen(old_skb));
		break;
	case IPPROTO_ICMPV6:
		factory_clone_icmp(old_skb, skb, bib->remote6_port, sport);
		break;
	}
	assemble_ipv6(&remote6, ip_hdr(old_skb)->saddr);
	factory_translate_ip4(old_skb, skb, &remote6, &bib->remote6_addr, proto, ip_hdrlen(old_skb));

	skb->dev = nat64_dev;
	nat64_dev->stats.rx_packets++;
	nat64_dev->stats.rx_bytes += skb->len;
	netif_rx(skb);

//	printk("nat64: [ipv4] Sending translated IPv6 packet.\n");
}

static inline struct bib_entry *nat64_probe_icmp4(struct sk_buff *skb)
{
	struct iphdr		*iph;
	struct tcphdr		*tcph;
	struct udphdr		*udph;
	struct bib_entry	*bib = NULL;
	int			len = sizeof(struct icmphdr);

	if(skb->len < len + sizeof(struct iphdr))
		return NULL;

	iph = (struct iphdr *)(skb->data + len);
	len += iph->ihl * 4;

	if(skb->len < len)
		return NULL;

	if(iph->protocol == IPPROTO_TCP) {
		if(skb->len < len + sizeof(struct tcphdr))
			return NULL;

		tcph = (struct tcphdr *)(skb->data + len);
		bib = bib_ipv4_lookup(iph->saddr, tcph->source, IPPROTO_TCP);
	} else if(iph->protocol == IPPROTO_UDP) {
		if(skb->len < len + sizeof(struct udphdr))
			return NULL;

		udph = (struct udphdr *)(skb->data + len);
		bib = bib_ipv4_lookup(iph->saddr, udph->source, IPPROTO_UDP);
	}

	return bib;
}

static inline unsigned int nat64_handle_tcp4(struct sk_buff *skb, struct iphdr *iph)
{
	struct bib_entry	*bib;
	struct session_entry	*session;
	struct tcphdr		*tcph = tcp_hdr(skb);

	if(skb->len < sizeof(struct tcphdr) && skb->len < tcp_hdrlen(skb))
		return NF_ACCEPT;

	bib = bib_ipv4_lookup(iph->daddr, tcph->dest, IPPROTO_TCP);
	if(!bib)
	    return NF_ACCEPT;

	session = session_ipv4_lookup(bib, iph->saddr, tcph->source);
	if(!session)
	    return NF_ACCEPT;	//   ICMP 3 (Destination Unreachable) and a code of 13 (Communication Administratively Prohibited)

	tcp4_fsm(session, tcph);
	skb_pull(skb, tcp_hdrlen(skb));

	nat64_translate_4to6(skb, bib, tcph->source, IPPROTO_TCP);
	return NF_DROP;
}

static inline unsigned int nat64_handle_udp4(struct sk_buff *skb, struct iphdr *iph)
{
	struct bib_entry	*bib;
	struct session_entry	*session;
	struct udphdr		*udph = udp_hdr(skb);

	if(skb->len < sizeof(struct udphdr))
		return NF_ACCEPT;

	bib = bib_ipv4_lookup(iph->daddr, udph->dest, IPPROTO_UDP);
	if(!bib)
	    return NF_ACCEPT;

	session = session_ipv4_lookup(bib, iph->saddr, udph->source);
	if(!session)
	    return NF_ACCEPT;	//   ICMP 3 (Destination Unreachable) and a code of 13 (Communication Administratively Prohibited)

	session_renew(session, UDP_DEFAULT);
	skb_pull(skb, sizeof(struct udphdr));

	nat64_translate_4to6(skb, bib, udph->source, IPPROTO_UDP);
	return NF_DROP;
}

static inline unsigned int nat64_handle_icmp4(struct sk_buff *skb, struct iphdr *iph)
{
	__be16			new_type;
	struct bib_entry	*bib;
	struct icmphdr		*icmph = icmp_hdr(skb);

	if(skb->len < sizeof(struct icmphdr))
		return NF_ACCEPT;

	switch(icmph->type) {
	//		Informational messages
	case ICMP_ECHO:
		new_type = (ICMPV6_ECHO_REQUEST << 8) + icmph->code;
		bib = bib_ipv4_lookup(iph->daddr, icmph->un.echo.id, IPPROTO_ICMP);
		break;
	case ICMP_ECHOREPLY:
		new_type = (ICMPV6_ECHO_REPLY << 8) + icmph->code;
		bib = bib_ipv4_lookup(iph->daddr, icmph->un.echo.id, IPPROTO_ICMP);
		break;
	//		Error messages
	case ICMP_DEST_UNREACH:
		bib = nat64_probe_icmp4(skb);
		if(!bib)
			break;

		switch(icmph->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_SR_FAILED:
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_NOROUTE;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
		case ICMP_PREC_CUTOFF:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_ADM_PROHIBITED;
			break;
		case ICMP_PROT_UNREACH:
			new_type = (ICMPV6_PARAMPROB << 8) + ICMPV6_UNK_NEXTHDR;
		/*
		Code 2 (Protocol unreachable):  Translate to an ICMPv6
		Parameter Problem (Type 4, Code value 1) and make the
		Pointer point to the IPv6 Next Header field.
		*/
			return NF_ACCEPT;
			break;
		case ICMP_FRAG_NEEDED:
			new_type = (ICMPV6_PKT_TOOBIG << 8);
		/*
		Code 4 (Fragmentation needed and DF set):  Translate to an
		ICMPv6 Packet Too Big message (Type 2) with Code value
		set to 0.  The MTU field MUST be adjusted for the
		difference between the IPv4 and IPv6 header sizes, i.e.
		minimum(advertised MTU+20, MTU_of_IPv6_nexthop,
		(MTU_of_IPv4_nexthop)+20).  Note that if the IPv4 router
		set the MTU field to zero, i.e., the router does not
		implement [RFC1191], then the translator MUST use the
		plateau values specified in [RFC1191] to determine a
		likely path MTU and include that path MTU in the ICMPv6
		packet.  (Use the greatest plateau value that is less
		than the returned Total Length field.)  In order to avoid
		back holes caused by ICMPv4 filtering or non [RFC2460]
		compatible IPv6 hosts (a workaround discussed in Section
		4), the translator MAY set the MTU to 1280 for any MTU
		values which are smaller than 1280.  The translator
		HOULD provide a method for operators to enable or
		disable this function.
		*/
			return NF_ACCEPT;
			break;
		case ICMP_PORT_UNREACH:
			new_type = (ICMPV6_DEST_UNREACH << 8) + ICMPV6_PORT_UNREACH;
			break;
		case ICMP_PREC_VIOLATION:
		default:
			return NF_ACCEPT;
		}
		skb_pull(skb, sizeof(struct icmphdr));
		nat64_translate_4to6_deep(skb, bib, new_type);
		return NF_DROP;
	case ICMP_PARAMETERPROB:
		bib = nat64_probe_icmp4(skb);
		if(!bib)
			break;

		switch(icmph->code) {
		case 0:
			/*
			Code 0 (Pointer indicates the error):  Set the Code value to
			0 (Erroneous header field encountered) and update the
			pointer as defined in Figure 3 (If the Original IPv4
			Pointer Value is not listed or the Translated IPv6
			Pointer Value is listed as "n/a", silently drop the
			packet).
			*/
			return NF_ACCEPT;
			break;
		case 2:
			/*
			Code 2 (Bad length):  Set the Code value to 0 (Erroneous
			header field encountered) and update the pointer as
			defined in Figure 3 (If the Original IPv4 Pointer Value
			is not listed or the Translated IPv6 Pointer Value is
			listed as "n/a", silently drop the packet).
			*/
			return NF_ACCEPT;
			break;
		case 1:
		default:
			return NF_ACCEPT;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		new_type = (ICMPV6_TIME_EXCEED << 8) + icmph->code;
		bib = nat64_probe_icmp4(skb);
		if(!bib)
			break;

		skb_pull(skb, sizeof(struct icmphdr));
		nat64_translate_4to6_deep(skb, bib, new_type);
		return NF_DROP;
	//		All drops
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case 6:		// Alternative address
	case 9:		// Router advertisment
	case 10:	// Router solicitation
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_INFO_REQUEST:
	case ICMP_INFO_REPLY:
	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
	default:
		printk("nat64: [icmp] Unsupported = %d, code = %hu\n", icmph->type, icmph->code);
		return NF_ACCEPT;
	}

	if(!bib)
		return NF_ACCEPT;

	skb_pull(skb, sizeof(struct icmphdr));

	nat64_translate_4to6(skb, bib, new_type, IPPROTO_ICMPV6);
	return NF_DROP;
}

int nat64_netdev_ipv4_input(struct sk_buff *skb)
{
	struct iphdr	*iph = ip_hdr(skb);

	if(skb->len < sizeof(struct iphdr) || iph->version != 4 || (iph->daddr & ipv4_netmask) != ipv4_addr)
		return -1;

	//printk("nat64: [ipv4] Got IPv4 packet (len %d).\n", skb->len);

	skb_pull(skb, ip_hdrlen(skb));
	skb_reset_transport_header(skb);

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			nat64_handle_tcp4(skb, iph);
			return 0;
		case IPPROTO_UDP:
			nat64_handle_udp4(skb, iph);
			return 0;
		case IPPROTO_ICMP:
			nat64_handle_icmp4(skb, iph);
			return 0;
	}
	return -1;
}

static int nat64_allocate_hash(unsigned int size)
{
	int			i;
	//struct hlist_head	*hash;

	size = roundup(size, PAGE_SIZE / sizeof(struct hlist_head));
	hash_size = size;
	//nat64_data.vmallocked = 0;

	hash4 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
	                                           get_order(sizeof(struct hlist_head) * size));

	if(!hash4) {
		printk("nat64: Unable to allocate memory for hash4 via gfp X(.\n");
		return -1;
		//hash = vmalloc(sizeof(struct hlist_head) * size);
		//nat64_data.vmallocked = 1;
	}

	hash6 = (void *)__get_free_pages(GFP_KERNEL|__GFP_NOWARN,
	                                           get_order(sizeof(struct hlist_head) * size));
	if(!hash6) {
		printk("nat64: Unable to allocate memory for hash6 via gfp X(.\n");
		free_pages((unsigned long)hash4,
			get_order(sizeof(struct hlist_head) * hash_size));
		return -1;
	}

	for (i = 0; i < size; i++)
	{
		INIT_HLIST_HEAD(&hash4[i]);
		INIT_HLIST_HEAD(&hash6[i]);
	}

	for (i = 0; i < NUM_EXPIRY_QUEUES; i++)
		INIT_LIST_HEAD(&expiry_base[i].queue);

	return 0;
}

static void nat64_free_hash(void)
{
	int i;
	struct bib_entry	*bib;
	struct session_entry	*session;
	struct list_head	*pos;
	struct list_head	*temp;

	for(i = 0; i < hash_size; i++)
	{
		if(!hlist_empty(&hash6[i]))
		{
			bib = hlist_entry((&hash6[i])->first, struct bib_entry, byremote);

			list_for_each_safe(pos, temp, &bib->sessions) {
				session = list_entry(pos, struct session_entry, list);
				//printk("nat64: [session] removing session %pI4:%hu.\n", &session->remote4_addr,	ntohs(session->remote4_port));
				kmem_cache_free(session_cache, session);
			}
			printk("nat64: [bib] removing bib %pI6c,%hu <--> %pI4:%hu.\n", &bib->remote6_addr, ntohs(bib->remote6_port), &bib->local4_addr, ntohs(bib->local4_port));
			kmem_cache_free(bib_cache, bib);
		}
		//if(&hash6[i])
		//	kmem_cache_free(bib_cache, &hash6[i]);
	}

	free_pages((unsigned long)hash4,
		get_order(sizeof(struct hlist_head) * hash_size));
	free_pages((unsigned long)hash6,
		get_order(sizeof(struct hlist_head) * hash_size));
}

static int __init nat64_init(void)
{
	int   ret = -1;
	char *pos;


	if(!ipv4_prefix) {
		pr_err("ipv4_prefix parameter is mandatory.\n");
		ret = -1;
		goto error;
	}

	ret = in4_pton(ipv4_prefix, -1, (u8 *)&ipv4_addr, '/', NULL);
	if (!ret) {
		pr_err("IPv4 prefix is malformed: %s\n", ipv4_prefix);
		ret = -1;
		goto error;
	}

	pos = strchr(ipv4_prefix, '/');
	if (pos) {
		ipv4_prefixlen = simple_strtol(++pos, NULL, 10);
		if (ipv4_prefixlen > 32 || ipv4_prefixlen < 1) {
			pr_err("IPv4 prefix length %d is illegal: %s\n",
						ipv4_prefixlen,
						ipv4_prefix);
			ret = -1;
			goto error;
		}
		ipv4_netmask = inet_make_mask(ipv4_prefixlen);
		ipv4_addr = ipv4_addr & ipv4_netmask;
	}


	ret = in6_pton(ipv6_prefix, -1, (u8 *)&prefix_base, '/', NULL);
	if (!ret) {
		pr_err("IPv6 prefix is malformed: %s\n", ipv6_prefix);
		ret = -1;
		goto error;
	}

	pos = strchr(ipv6_prefix, '/');
	if (pos) {
		prefix_len = simple_strtol(++pos, NULL, 10);
		if (prefix_len != 96 && prefix_len != 64
				&& prefix_len != 56 && prefix_len != 48
				&& prefix_len != 40 && prefix_len != 32) {	
			pr_err("IPv6 prefix length %d is illegal, only 96, 64, 56, 48, 40 or 32 is allowed: %s\n", prefix_len, ipv6_prefix);
			ret = -1;
			goto error;
		}
	}



	if(nat64_allocate_hash(65536)) {
		pr_err("Unable to allocate memmory for main hash table.\n");
		ret = -ENOMEM;
		goto error;
	}

	session_cache = kmem_cache_create("nat64_session", sizeof(struct session_entry), 0, 0, NULL);
	if (!session_cache) {
		pr_err("Unable to create session_entry slab cache.\n");
		ret = -ENOMEM;
		goto cache_error;
	}

	bib_cache = kmem_cache_create("nat64_bib", sizeof(struct bib_entry), 0, 0, NULL);
	if (!bib_cache) {
		pr_err("Unable to create bib_entry slab cache.\n");
		ret = -ENOMEM;
		goto cache_bib_error;
	}


	ret = nat64_netdev_create(&nat64_dev, NAT64_NETDEV_NAME);
	if(ret) {
		pr_err("Unable to create nat64 device\n");
		goto dev_error;
	}

	pr_info("Module loaded.\n");

	pr_info("Translating %pI6c/%d => ::/0 to %pI4/%d => 0.0.0.0/0\n",
					&prefix_base, prefix_len,
					&ipv4_addr, ipv4_prefixlen);
	pr_info("Packets should be received and will be transmitted via nat64 device.\n");
	pr_info("Please issue these commands:\n");
	pr_info("\tip link set nat64 up\n");
	pr_info("\tip route add %pI6c/%d dev nat64\n", &prefix_base, prefix_len);
	pr_info("\tip route add %pI4/%d dev nat64\n", &ipv4_addr, ipv4_prefixlen);

	return 0;

dev_error:
	kmem_cache_destroy(bib_cache);
cache_bib_error:
	kmem_cache_destroy(session_cache);
cache_error:
	nat64_free_hash();
error:
	pr_info("Module is NOT loaded.\n");
	return ret;
}

static void __exit nat64_exit(void)
{
	nat64_netdev_destroy(nat64_dev);

	nat64_free_hash();

	kmem_cache_destroy(bib_cache);
	kmem_cache_destroy(session_cache);

	pr_info("Module unloaded.\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
