/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/neighbour.h>
#include <net/arp.h>
#include <linux/export.h>
#include <linux/rculist.h>
#include "br_private.h"

/* Hook for brouter */
br_should_route_hook_t __rcu *br_should_route_hook __read_mostly;
EXPORT_SYMBOL(br_should_route_hook);


/*******************************************************************
 * 重入协议栈
 * *****************************************************************/
static int
br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	br_drop_fake_rtable(skb);
	return netif_receive_skb(skb);
}


/******************************************************************
 * 处理向上层传递的 skb
 * ****************************************************************/
static int br_pass_frame_up(struct sk_buff *skb)
{
	struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
	struct net_bridge *br = netdev_priv(brdev);
	struct net_bridge_vlan_group *vg;
	struct pcpu_sw_netstats *brstats = this_cpu_ptr(br->stats);

	/**************************************************
	 * 更新统计数据
	 * ************************************************/
	u64_stats_update_begin(&brstats->syncp);
	brstats->rx_packets++;
	brstats->rx_bytes += skb->len;
	u64_stats_update_end(&brstats->syncp);

	vg = br_vlan_group_rcu(br);
	/* Bridge is just like any other port.  Make sure the
	 * packet is allowed except in promisc modue when someone
	 * may be running packet capture.
	 */
	if (!(brdev->flags & IFF_PROMISC) &&
	    !br_allowed_egress(vg, skb)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	indev = skb->dev;
	skb->dev = brdev;
	skb = br_handle_vlan(br, vg, skb);
	if (!skb)
		return NET_RX_DROP;

	/**************************************************
	 * 修改 skb->dev 然后重新走网络协议栈
	 * ************************************************/
	return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
		       dev_net(indev), NULL, skb, indev, NULL,
		       br_netif_receive_skb);
}

static void br_do_proxy_arp(struct sk_buff *skb, struct net_bridge *br,
			    u16 vid, struct net_bridge_port *p)
{
	struct net_device *dev = br->dev;
	struct neighbour *n;
	struct arphdr *parp;
	u8 *arpptr, *sha;
	__be32 sip, tip;

	BR_INPUT_SKB_CB(skb)->proxyarp_replied = false;

	if (dev->flags & IFF_NOARP)
		return;

	if (!pskb_may_pull(skb, arp_hdr_len(dev))) {
		dev->stats.tx_dropped++;
		return;
	}
	parp = arp_hdr(skb);

	if (parp->ar_pro != htons(ETH_P_IP) ||
	    parp->ar_op != htons(ARPOP_REQUEST) ||
	    parp->ar_hln != dev->addr_len ||
	    parp->ar_pln != 4)
		return;

	arpptr = (u8 *)parp + sizeof(struct arphdr);
	sha = arpptr;
	arpptr += dev->addr_len;	/* sha */
	memcpy(&sip, arpptr, sizeof(sip));
	arpptr += sizeof(sip);
	arpptr += dev->addr_len;	/* tha */
	memcpy(&tip, arpptr, sizeof(tip));

	if (ipv4_is_loopback(tip) ||
	    ipv4_is_multicast(tip))
		return;

	n = neigh_lookup(&arp_tbl, &tip, dev);
	if (n) {
		struct net_bridge_fdb_entry *f;

		if (!(n->nud_state & NUD_VALID)) {
			neigh_release(n);
			return;
		}

		f = __br_fdb_get(br, n->ha, vid);
		if (f && ((p->flags & BR_PROXYARP) ||
			  (f->dst && (f->dst->flags & BR_PROXYARP_WIFI)))) {
			arp_send(ARPOP_REPLY, ETH_P_ARP, sip, skb->dev, tip,
				 sha, n->ha, sha);
			BR_INPUT_SKB_CB(skb)->proxyarp_replied = true;
		}

		neigh_release(n);
	}
}

/* note: already called with rcu_read_lock */
int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_mdb_entry *mdst;
	struct sk_buff *skb2;
	bool unicast = true;
	u16 vid = 0;
    
    /*************************************
     * 如果当前 brport 是 DISABLED 状态
     * 则没有必要再进行处理了，反正上层
     * 也不会收，直接丢弃就行了
	 *
	 * 其实之前已经判断了brport的状态，
	 * 要么是 FORWARDING 要么就是 LEARNING
	 *
	 * 这地方还加上判断是为了以后添加
	 * 新功能时有其他改动
     * ***********************************/
	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

    /*************************************
     *
	 * vlan group 是一个 hash 表，存放了
	 * 当前 bridge port 的 VLAN ID，
	 * 如果进入的包符合 Port 的VLAN才
	 * 允许进入，否则就丢弃
	 *
	 * 还有就是如果 bridge port 禁用了
	 * VLAN 过滤，则所有包都会被接收
	 *
	 * VLAN filtering 可以通过 sysfs 配置
     * ***********************************/
	if (!br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid))
		goto out;

	/* insert into forwarding database after filtering to avoid spoofing */

	/***********************************************************************
	 *
	 * 在经过上面的检查后，就将 source MAC 加入到转发表
	 *
	 * insert into forwarding database after filtering to avoid spoofing 
	 *
	 * 创建Bridge的时候，默认会设置 BR_LEARNING|BR_FLOOD，以支持学习和洪泛,
	 *
	 * 这些设置都可以在 sysfs 中的配置，这些配置是针对brport的
	 *
	 * *********************************************************************/
	br = p->br;
	if (p->flags & BR_LEARNING)
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, false);

	/*******************************************************************
	 * FIXME
	 * 多播相关的判断，稍后详解
	 * *****************************************************************/
	if (!is_broadcast_ether_addr(dest) && is_multicast_ether_addr(dest) &&
	    br_multicast_rcv(br, p, skb, vid))
		goto drop;
    
	/**********************************************************************
	 * 如果当前brport是处于 LEARNING 状态，则在更新fdb之后直接丢弃
	 * ********************************************************************/
	if (p->state == BR_STATE_LEARNING)
		goto drop;


	/**********************************************************************
	 * 将当前的设置SKB的BR Control Buffer中brdev设为当前bridge设备，
	 * 
	 * 其实这个地方也没必要，因为包走到哪儿，只要在bridge中，就知道
	 * 当前是那个bridge
	 * ********************************************************************/
	BR_INPUT_SKB_CB(skb)->brdev = br->dev;

	/* The packet skb2 goes to the local host (NULL to skip). */
	skb2 = NULL;

	if (br->dev->flags & IFF_PROMISC)
		skb2 = skb;

	dst = NULL;


	/***********************************************************************
	 * FIXME
	 * 对 ARP 桥接的处理
	 * *********************************************************************/
	if (IS_ENABLED(CONFIG_INET) && skb->protocol == htons(ETH_P_ARP))
		br_do_proxy_arp(skb, br, vid, p);

	if (is_broadcast_ether_addr(dest)) {
		skb2 = skb;
		unicast = false;
	} else if (is_multicast_ether_addr(dest)) {
		/*****************************************************
		 * 如果是多播包，则更新mdb，并转发
		 * **************************************************/
		mdst = br_mdb_get(br, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(br, eth_hdr(skb))) {
			if ((mdst && mdst->mglist) ||
			    br_multicast_is_router(br))
				skb2 = skb;
			br_multicast_forward(mdst, skb, skb2);
			skb = NULL;
			if (!skb2)
				goto out;
		} else
			skb2 = skb;

		unicast = false;
		br->dev->stats.multicast++;
	} else if ((dst = __br_fdb_get(br, dest, vid)) &&
			dst->is_local) {
		/**************************************************
		 * 如果当前有 local fdb，则说明这个包是发给本机的，
		 * 则不走 forward，则是直接调用
		 *			br_frame_pass_up
		 * 向上传递
		 * ************************************************/
		skb2 = skb;
		/* Do not forward the packet since it's local. */
		skb = NULL;
	}

    /**********************************************************
     * skb != NULL 表示这个包不是local的并且不是multicast，
	 * 则调用 br_forward进行转发
     * ********************************************************/
	if (skb) {
		if (dst) {
			/**************************************************
			 * 如果有转发表项，则直接调用 br_forward 转发出去
			 * ************************************************/
			dst->used = jiffies;
            /**************************************************
             * br_forward 不会将包送到L3，这届 dev_xmit_skb 就
             * 把包转发出去了
             * ***********************************************/
			br_forward(dst->dst, skb, skb2);
		} else {

			/*************************************************
			 * 如果没有转发表项，则洪泛转发出去
			 * ***********************************************/
			br_flood_forward(br, skb, skb2, unicast);
		}
	}

    /***********************************************************
     * 如果 skb2 != NULL, 表示这个包是 local 的或是 multicast的
     * 需要向协议栈上层传递
     * ********************************************************/
	if (skb2)
        /**************************************************
         * 向上传送的过程其实非常简单，就是重新走一遍协议栈
         *
         * 重新向上传递前会把  skb->dev 改当前 bridge
         * 表示这个包是bridge收上来的
         *
         *
         * 需要注意的是，向上传递前还会经过 NF_BRIDGE table
         * 如果当前 br_netfilter 模块加载了，则包会经过
         * NF_BRIDGE 表中的规则
         *
         * ************************************************/
		return br_pass_frame_up(skb2);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}
EXPORT_SYMBOL_GPL(br_handle_frame_finish);

/* note: already called with rcu_read_lock */
static int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	u16 vid = 0;

	/* check if vlan is allowed, to avoid spoofing */
	if (p->flags & BR_LEARNING && br_should_learn(p, skb, &vid))
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid, false);
	return 0;	 /* process further */
}

/*
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock
 */
rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	br_should_route_hook_t *rhook;

	/*************************************************
	 * RX_HANDLER_PASS 在 __netif_receive_skb_core
	 * 中会使用
	 *
	 * 当返回这个值的时候，这个skb 就不会再进行处理
	 * 而是直接跳出，去处理下一个包了
	 * ***********************************************/
	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	/***************************************************
	 * 没有有效的source ethernet地址，那么就直接丢弃该包
	 * ************************************************/
	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	/***************************************************
	 * 如果不是共享skb，则返回，
	 * 如果是共享 skb，则返回一个clone
	 * ************************************************/
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

	/***************************************************
	 * 根据 skb->dev 获取到对应的 bridge port
	 **************************************************/
	p = br_port_get_rcu(skb->dev);

    /****************************************************
     * 使用 unlikely 在Router场景中可能是不太好
     * 因为 Router 的LAN端发的包的目的地址都是
     * bridge的地址，毕竟是网关嘛
     *
     * xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
     * Update:
     *
     * 上面的叙述是错误的，这是由于不理解什么是 
     * link locl地址导致的
     *      link local reserved addr (01:80:c2:00:00:0X)
     * 
     * 这才是link local 地址
     *
     * *************************************************/
	if (unlikely(is_link_local_ether_addr(dest))) {
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5]))
				goto forward;
			break;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		default:
			/* Allow selective forwarding for most other protocols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* Deliver packet to local host only */
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
			    dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			    br_handle_local_finish)) {
			return RX_HANDLER_CONSUMED; /* consumed by filter */
		} else {
			*pskb = skb;
			return RX_HANDLER_PASS;	/* continue processing */
		}
	}

forward:
	switch (p->state) {
    /********************************************
     * 看看当前的 Bridge Port 是不是 Forwarding
     * 
     * *****************************************/
	case BR_STATE_FORWARDING:
        /**************************************
         * FIXME
         * BROUTE 功能，暂时不关心
         * ************************************/
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook) {
			if ((*rhook)(skb)) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:
		/*****************************************************
		 * 看来 BR_STATE_LEARNING 状态也可以收包 ??
		 *
		 * QA: 根据 br_handle_frame_finish 中的实现来看，当
		 * brport 处于 Learning 状态时收到的包会更新fdb，但是
		 * 不会向上递送，而是会被丢弃，就在更新完fdb后。
		 * ***************************************************/

        /**************************************
         * 如果目的地址是当前port，则设置
         * pkt_type == PACKET_HOST
         * ************************************/
		if (ether_addr_equal(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

        /******************************************************
         * 如果 br_netfilter 被插入，则可能会有规则
         * 在走过 netfilter 后， 调用 
         *          br_handle_fram_finish
         * 做进一步的处理
         * ****************************************************/
		NF_HOOK(NFPROTO_BRIDGE, NF_BR_PRE_ROUTING,
			dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			br_handle_frame_finish);
		break;
	default:
drop:
		kfree_skb(skb);
	}

    /********************************************
     * 原来的skb不会再从协议栈L2往上继续送，
     * bridge 会接手这个包
     * ******************************************/
	return RX_HANDLER_CONSUMED;
}
