/*
 * nat64_netdev.c : code to crate virtual network iface
 *
 */

#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>

int nat64_netdev_ipv4_input(struct sk_buff *skb);
int nat64_netdev_ipv6_input(struct sk_buff *skb);

static int nat64_netdev_up(struct net_device *dev);
static int nat64_netdev_down(struct net_device *dev);
static netdev_tx_t nat64_netdev_xmit(struct sk_buff *skb, struct net_device *dev);

static const struct net_device_ops nat64_netdev_ops = {
//	.ndo_init	= ,	// Called at register_netdev
//	.ndo_uninit	= ,	// Called at unregister_netdev
	.ndo_open	= nat64_netdev_up,	// Called at ifconfig nat64 up
	.ndo_stop	= nat64_netdev_down,	// Called at ifconfig nat64 down
	.ndo_start_xmit	= nat64_netdev_xmit,	// REQUIRED, must return NETDEV_TX_OK
//	.ndo_change_rx_flags = ,	// Called when setting promisc or multicast flags.
//	.ndo_change_mtu = ,
//	.net_device_stats = ,	// Called for usage statictics, if NULL dev->stats will be used.
};

static int nat64_netdev_up(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int nat64_netdev_down(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t nat64_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	switch(ntohs(skb->protocol)) {
	case ETH_P_IP:
		nat64_netdev_ipv4_input(skb);
		break;
	case ETH_P_IPV6:
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
		nat64_netdev_ipv6_input(skb);
		break;
	}

	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void nat64_netdev_setup(struct net_device *dev)
{
	dev->netdev_ops = &nat64_netdev_ops;

	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN;
	dev->features = NETIF_F_NETNS_LOCAL;
	dev->flags = IFF_NOARP | IFF_POINTOPOINT;
}

int nat64_netdev_create(struct net_device **dev, const char *name)
{
	int ret = 0;

	*dev = alloc_netdev(0, name, NET_NAME_UNKNOWN, nat64_netdev_setup);

	if (!*dev)
		return -ENOMEM;

	ret = register_netdev(*dev);
	if(ret) {
		free_netdev(*dev);
		return ret;
	}

	return ret;
}

void nat64_netdev_destroy(struct net_device *dev)
{
	unregister_netdev(dev);
}

