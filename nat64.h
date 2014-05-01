#pragma once

#include <linux/netdevice.h>

#define UDP_DEFAULT_ 5*60
#define ICMP_DEFAULT_ 1*60

#define BIB_ICMP	3

#define	NUM_EXPIRY_QUEUES	5
struct expiry_q
{
	struct list_head	queue;
	int			timeout;
};

enum state_type {
	CLOSED = 0,
	V6_SYN_RCV,
	V4_SYN_RCV,
	FOUR_MIN,
	ESTABLISHED,
	V6_FIN_RCV,
	V4_FIN_RCV,
	V6_FIN_V4_FIN,
};

enum expiry_type {
	UDP_DEFAULT = 0,
	TCP_TRANS,
	TCP_EST,
	TCP_INCOMING_SYN,
	ICMP_DEFAULT
};

struct bib_entry
{
	struct hlist_node	byremote;
	struct hlist_node	bylocal;

	int			type;
	struct in6_addr		remote6_addr;
	__be32			local4_addr;

	__be16			remote6_port;
	__be16			local4_port;

	struct list_head	sessions;
};

struct session_entry
{
	struct list_head	list;
	struct list_head	byexpiry;
	unsigned long		expires;
	int			state;
	__be32			remote4_addr;
	__be16			remote4_port;
};

struct nat64_state {
	struct kmem_cache *session_cache;
	struct kmem_cache *bib_cache;

	struct expiry_q	   expiry_base[NUM_EXPIRY_QUEUES];

	unsigned int       hash_size;
	struct hlist_head *hash6;
	struct hlist_head *hash4;

	struct net_device *nat64_dev;

	__be32             ipv4_addr;
	__be32             ipv4_netmask;
	int                ipv4_prefixlen;

	int                prefix_len;
	struct in6_addr    prefix_base;
};

extern struct nat64_state state;

int nat64_netdev_ipv6_input(struct sk_buff *old_skb);
int nat64_netdev_ipv4_input(struct sk_buff *old_skb);

int nat64_netdev_create(struct net_device **dev, const char *name);
void nat64_netdev_destroy(struct net_device *dev);

static inline __be16 nat64_hash4(__be32 addr, __be16 port)
{
	//return (addr >> 16) ^ addr ^ port;
	return port;
}

static inline __be16 nat64_hash6(struct in6_addr addr6, __be16 port)
{
	__be32 addr4 = addr6.s6_addr32[0] ^ addr6.s6_addr32[1] ^ addr6.s6_addr32[2] ^ addr6.s6_addr32[3];
	return (addr4 >> 16) ^ addr4 ^ port;
}

static inline __be32 map_6to4(struct in6_addr *addr6)
{
	__be32 addr_hash = addr6->s6_addr32[0] ^ addr6->s6_addr32[1] ^ addr6->s6_addr32[2] ^ addr6->s6_addr32[3];
	__be32 addr4 = htonl(ntohl(state.ipv4_addr) + (addr_hash % (1<<(32 - state.ipv4_prefixlen))));

//	printk("nat64: [inline] map_6to4 %pI6c mod %pI4/%d -> %pI4 + %d -> %pI4\n", addr6, &state.ipv4_addr, state.ipv4_prefixlen, &state.ipv4_addr, (addr_hash % (1<<(32 - state.ipv4_prefixlen))), &addr4);
	return addr4;
}

static inline __be32 extract_ipv4(struct in6_addr addr, int prefix)
{
	switch(prefix) {
	case 32:
		return addr.s6_addr32[1];
	case 40:
		return 0;	//FIXME
	case 48:
		return 0;	//FIXME
	case 56:
		return 0;	//FIXME
	case 64:
		return 0;	//FIXME
	case 96:
		return addr.s6_addr32[3];
	default:
		return 0;
	}
}

static inline void assemble_ipv6(struct in6_addr *dest, __be32 addr)
{
	memcpy(dest, &state.prefix_base, sizeof(state.prefix_base));
	switch(state.prefix_len) {
	case 96:
		dest->s6_addr32[3] = addr;
		break;
	}
}
