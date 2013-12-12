#pragma once

#include <net/tcp.h>

#include "nat64.h"

int tcp_timeout_fsm(struct session_entry *session);
void tcp4_fsm(struct session_entry *session, const struct tcphdr *tcph);
void tcp6_fsm(struct session_entry *session, const struct tcphdr *tcph);

struct bib_entry *bib_ipv6_lookup(struct in6_addr *remote_addr, __be16 remote_port, int type);
struct bib_entry *bib_ipv4_lookup(__be32 local_addr, __be16 local_port, int type);
struct bib_entry *bib_create(struct in6_addr *remote6_addr, __be16 remote6_port,
			     __be32 local4_addr, __be16 local4_port, int type);
struct bib_entry *bib_session_create(struct in6_addr *saddr, __be32 daddr, __be16 sport, __be16 dport, int protocol, enum expiry_type type);

struct session_entry *session_ipv4_lookup(struct bib_entry *bib, __be32 saddr, __be16 sport);
struct session_entry *session_create(struct bib_entry *bib, __be32 addr, __be16 port, enum expiry_type type);
void session_renew(struct session_entry *session, enum expiry_type type);
