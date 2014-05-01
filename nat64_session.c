#include "nat64_session.h"

int tcp_timeout_fsm(struct session_entry *session)
{
	if(session->state == ESTABLISHED) {
		session_renew(session, TCP_TRANS);
		session->state = FOUR_MIN;
		return 1;
	}

	return 0;
}

void tcp4_fsm(struct session_entry *session, const struct tcphdr *tcph)
{
//	printk("nat64: [fsm4] Got packet state %d.\n", session->state);

	switch(session->state) {
	case CLOSED:
		break;
	case V6_SYN_RCV:
		if(tcph->syn) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case V4_SYN_RCV:
		//if(tcph->syn)
		//	session_renew(session, TCP_TRANS);
		break;
	case FOUR_MIN:
		if(!tcph->rst) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case ESTABLISHED:
		if(tcph->fin) {
			//session_renew(session, TCP_EST);
			session->state = V4_FIN_RCV;
		} else if(tcph->rst) {
			session_renew(session, TCP_TRANS);
			session->state = FOUR_MIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_RCV:
		if(tcph->fin) {
			session_renew(session, TCP_TRANS);
			session->state = V6_FIN_V4_FIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V4_FIN_RCV:
		session_renew(session, TCP_EST);
		break;
	case V6_FIN_V4_FIN:
		break;
	}
}

void tcp6_fsm(struct session_entry *session, const struct tcphdr *tcph)
{
//	printk("nat64: [fsm6] Got packet state %d.\n", session->state);

	switch(session->state) {
	case CLOSED:
		if(tcph->syn) {
			session_renew(session, TCP_TRANS);
			session->state = V6_SYN_RCV;
		}
		break;
	case V6_SYN_RCV:
		if(tcph->syn)
			session_renew(session, TCP_TRANS);
		break;
	case V4_SYN_RCV:
		if(tcph->syn) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case FOUR_MIN:
		if(!tcph->rst) {
			session_renew(session, TCP_EST);
			session->state = ESTABLISHED;
		}
		break;
	case ESTABLISHED:
		if(tcph->fin) {
			//session_renew(session, TCP_EST);
			session->state = V6_FIN_RCV;
		} else if(tcph->rst) {
			session_renew(session, TCP_TRANS);
			session->state = FOUR_MIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_RCV:
		session_renew(session, TCP_EST);
		break;
	case V4_FIN_RCV:
		if(tcph->fin) {
			session_renew(session, TCP_TRANS);
			session->state = V6_FIN_V4_FIN;
		} else {
			session_renew(session, TCP_EST);
		}
		break;
	case V6_FIN_V4_FIN:
		break;
	}
}




static inline int bib_allocate_local4_port(__be32 addr, __be16 port, int type)
{
	struct hlist_node	*node;
	struct bib_entry	*entry;
	int min, max, i;
	int flag = 0;
	port = ntohs(port);
	min = port < 1024 ? 0 : 1024;
	max = port < 1024 ? 1023 : 65535;


	for (i = port; i <= max; i += 2, flag = 0) {
		hlist_for_each(node, &state.hash4[htons(i)]) {
			entry = hlist_entry(node, struct bib_entry, bylocal);
			if(entry->type == type && entry->local4_addr == addr) {
				flag = 1;
				break;
			}
		}
		if(!flag)
			return htons(i);
	}

	flag = 0;
	for (i = port - 2; i >= min; i -=2, flag = 0) {
		hlist_for_each(node, &state.hash4[htons(i)]) {
			entry = hlist_entry(node, struct bib_entry, bylocal);
			if(entry->type == type && entry->local4_addr == addr) {
				flag = 1;
				break;
			}
		}
		if(!flag)
			return htons(i);
	}

	return -1;
}
















struct bib_entry *bib_ipv6_lookup(struct in6_addr *remote_addr, __be16 remote_port, int type)
{
	struct hlist_node	*pos;
	struct bib_entry	*bib;
	__be16 			h = nat64_hash6(*remote_addr, remote_port);
	struct hlist_head	*hlist = &state.hash6[h];

	hlist_for_each(pos, hlist) {
		bib = hlist_entry(pos, struct bib_entry, byremote);
		if(bib->type == type && bib->remote6_port == remote_port && memcmp(&bib->remote6_addr, remote_addr, sizeof(*remote_addr)) == 0)
			return bib;
	}

	//return (pos ? bib : NULL);
	return NULL;
}

struct bib_entry *bib_ipv4_lookup(__be32 local_addr, __be16 local_port, int type)
{
	struct hlist_node	*pos;
	struct bib_entry	*bib;
	__be16			h = nat64_hash4(local_addr, local_port);
	struct hlist_head	*hlist = &state.hash4[h];


	hlist_for_each(pos, hlist) {
		bib = hlist_entry(pos, struct bib_entry, bylocal);
		if(bib->type == type && bib->local4_addr == local_addr && bib->local4_port == local_port)
			return bib;
	}

	//return (pos ? bib : NULL);
	return NULL;
}

struct bib_entry *bib_create(struct in6_addr *remote6_addr, __be16 remote6_port,
			     __be32 local4_addr, __be16 local4_port, int type)
{
	struct bib_entry	*bib;

	bib = kmem_cache_zalloc(state.bib_cache, GFP_ATOMIC);
	if (!bib) {
		printk("nat64: [bib] Unable to allocate memory for new bib entry X(.\n");
		return NULL;
	}

	bib->type = type;
	memcpy(&bib->remote6_addr, remote6_addr, sizeof(struct in6_addr));
	bib->local4_addr = local4_addr;
	bib->remote6_port = remote6_port;
	bib->local4_port = local4_port;
	INIT_LIST_HEAD(&bib->sessions);
	//printk("nat64: [bib] New bib %pI6c,%hu <--> %pI4:%hu.\n", remote6_addr, ntohs(remote6_port), &local4_addr, ntohs(local4_port));

	return bib;
}

struct bib_entry *bib_session_create(struct in6_addr *saddr, __be32 daddr, __be16 sport, __be16 dport, int protocol, enum expiry_type type)
{
	struct bib_entry	*bib;
	struct session_entry	*session;
	int			local4_port;
	__be32			local4_ip = map_6to4(saddr);

	//map_6to4(saddr);
	local4_port = bib_allocate_local4_port(local4_ip, sport, protocol);
	if (local4_port < 0) {
		printk("nat64: [bib] Unable to allocate new local IPv4 port. Dropping connection.\n");
		return NULL;
	}

	bib = bib_create(saddr, sport, local4_ip, local4_port, protocol);
	if (!bib)
		return NULL;

	hlist_add_head(&bib->byremote, &state.hash6[nat64_hash6(*saddr, sport)]);
	hlist_add_head(&bib->bylocal, &state.hash4[local4_port]);

	session = session_create(bib, daddr, dport, type);
	if(!session) {
		kmem_cache_free(state.bib_cache, bib);
		return NULL;
	}

	return bib;
}

struct session_entry *session_ipv4_lookup(struct bib_entry *bib, __be32 remote4_addr, __be16 remote4_port)
{
	struct session_entry	*session;
	struct list_head	*pos;

	list_for_each(pos, &bib->sessions) {
		session = list_entry(pos, struct session_entry, list);
		if(session->remote4_addr == remote4_addr && session->remote4_port == remote4_port)
			return session;
	}

	return NULL;
}

void session_renew(struct session_entry *session, enum expiry_type type)
{
	list_del(&session->byexpiry);
	session->expires = jiffies + state.expiry_base[type].timeout*HZ;
	list_add_tail(&session->byexpiry, &state.expiry_base[type].queue);
	//printk("nat64: [session] Renewing session %pI4:%hu (timeout %u sec).\n", &session->remote4_addr, ntohs(session->remote4_port), state.expiry_base[type].timeout);
}

struct session_entry *session_create(struct bib_entry *bib, __be32 addr, __be16 port, enum expiry_type type)
{
	struct session_entry *s;

	s = kmem_cache_zalloc(state.session_cache, GFP_ATOMIC);
	if(!s) {
		printk("nat64: [session] Unable to allocate memory for new session entry X(.\n");
		return NULL;
	}
	s->state = CLOSED;
	s->remote4_addr = addr;
	s->remote4_port = port;
	list_add(&s->list, &bib->sessions);

	s->expires = jiffies + state.expiry_base[type].timeout*HZ;
	list_add_tail(&s->byexpiry, &state.expiry_base[type].queue);

//	printk("nat64: [session] New session %pI4:%hu (timeout %u sec).\n", &addr, ntohs(port), state.expiry_base[type].timeout);

	return s;
}
