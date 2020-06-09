/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <net/dst_metadata.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);

	for (ra = rcu_dereference(ip_ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), net)) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(net, skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}


static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	__skb_pull(skb, skb_network_header_len(skb));

	rcu_read_lock();
	{
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		/******************************************
		 * 如果当前存在RAWsocket，则交给 RAW socket
		 * 一份进行处理 (此处会clone skb)
		 *
		 * ***************************************/
		raw = raw_local_deliver(skb, protocol);

		/**********************************************
		 * 通过协议号找到相应的协议，然后调用其handler
		 * 将skb交给他处理
         *
         * 协议的添加通过函数
         *      inet_add_protocol 
         * 来完成，目前添加的协议有
         * ICMP/TCP/UDP/IPIP/....   等等
         *
         * 其handler通常是如下:
         *      icmp_rcv, udp_rcv, tcp_v4_rcv
		 * *******************************************/
		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot) {
			int ret;

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			ret = ipprot->handler(skb);
			if (ret < 0) {
				/*******************************************
				 * Q: 为什么上层处理失败要 resubmit ？？？？
				 *
				 *
				 * A: 此处的返回值是有特殊意义的, 返回
				 * 负值不是表示处理失败，而是表示这个
				 * 包是封装用的，封装的负载还是一个L4
				 * 的协议，所以返回 （-protocol），通知
				 * 当前函数再次递送当前包到相对应的
				 * L4协议进行处理。
				 *
				 * ****************************************/
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			/**************************************************
			 * 如果没有相对应的L4协议处理，则看看RAW有没有处理，
			 * 如果 RAW 也没有处理，然返回协议不可达ICMP报文
			 * ************************************************/
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
				/************************************************
				 * 如果这个SKB被 RAW消费了，则更新统计信息
				 * 然后 kfree_skb
				 * **********************************************/
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 *
 * 收到的包在经过路由查询后会将output函数指针设定为
 * ip_local_deliver, 也就会走到这个地方
 *
 */
int ip_local_deliver(struct sk_buff *skb)
{
	/****************************************************\
	 * 发往本机的包会走到此处，然后送到上层协议去处理
	 *
	 * **************************************************/
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);
         
	/*****************************************************
	 * 如果包是分片包则进行分片重组，如果分片还没有收完，
	 * 则 ip_defrag 会将分片包放入分片队列，等待全部的
	 * 分片到达
	 * ***************************************************/
	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}
	

	/*****************************************************\
	 * 在此处的包都是完整包，不存在分片的情况，
	 * 现在开始过 INPUT chain，
	 * 如果在 INPUT 中没有被 DROP 或 REJECT，
	 * 则调用 ip_local_deliver_finish 交给上层协议
	 * (这些协议是通过 inet_add_protocol 注册的)
	 * ***************************************************/
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
    /*************************************************
     * 所有 options 头的长度
     * ***********************************************/
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

int sysctl_ip_early_demux __read_mostly = 1;
EXPORT_SYMBOL(sysctl_ip_early_demux);

static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
    
    /***************************************************************
     *  ipv4: Early TCP socket demux.
     *  
     *  Input packet processing for local sockets involves two major demuxes.
     *  One for the route and one for the socket.
     *
     *  But we can optimize this down to one demux for certain kinds of local
     *  sockets.
     *
     *  Currently we only do this for established TCP sockets, but it could
     *  at least in theory be expanded to other kinds of connections.
     *
     *  If a TCP socket is established then it's identity is fully specified.
     *
     *  This means that whatever input route was used during the three-way
     *  handshake must work equally well for the rest of the connection since
     *  the keys will not change.
     *
     *  Once we move to established state, we cache the receive packet's input
     *  route to use later.
     *
     *  Like the existing cached route in sk->sk_dst_cache used for output
     *  packets, we have to check for route invalidations using dst->obsolete
     *  and dst->ops->check().
     *
     *  Early demux occurs outside of a socket locked section, so when a route
     *  invalidation occurs we defer the fixup of sk->sk_rx_dst until we are
     *  actually inside of established state packet processing and thus have
     *  the socket locked.
     * *********************************************************************/
	if (sysctl_ip_early_demux && !skb_dst(skb) && !skb->sk) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && ipprot->early_demux) {
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/******************************************************************
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 *
	 *  根据前述的 __netif_receive_skb_core 中的实现，一个包
	 *  可能会被多次deliver到上层，所以之前可能已经做过
	 *  ip_route_input_noref 这个查找的动作，此处直接使用缓存就可以了，
	 *  也算是一种优化方式。
	 *
	 *  对于 skb_valid_dst 和 skb_dst, 其使用的是 sk_buff 中的一个
	 *  叫 _skb_refdst 的成员, 这个成员在 sk_buff 中定义为一个整形
	 *  但其实他是一个指向 dst_entry 的指针。
	 *
	 *  在skb_clone的时候，其实这个指针是被直接赋值给clone的skb的
	 *  也就是说，dst_entry 不会被复制，而是直接被引用了。
	 *****************************************************************/
	if (!skb_valid_dst(skb)) {

		/***********************************************************
		 * 如果当前没有dst，说明是第一次上到协议栈，那就进行dst查找
		 * 来确定这个skb的走向， 可能是 多播/广播/本机/转发
		 * dst_entry 中的 input（xxx）函数也会在这里进行初始化，
		 * 以此来让相应的模块或协议来处理相应的包
		 * *********************************************************/
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);

		/* 如果查不到相应的dst_entry，则简单的丢弃这个包好了 */
		if (unlikely(err)) {
			if (err == -EXDEV)
				NET_INC_STATS_BH(net, LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	/**************************************************
	 * 检查和处理ip包的 options，如果有问题则丢弃这个包
	 *
	 * ***********************************************/
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;


	/*********************************************************
	 * 获取路由缓存项，其实就是之前的 dst_entry, 前面已经进行了
	 * skb dst的查找，查找不到的已经被丢弃了，能走到这儿的说明
	 * 一定存在相对应的表项
	 *
	 * 此处用于更新路由表的状态（统计信息？？？）
	 * ******************************************************/
	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_INMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_INBCAST, skb->len);


	/*********************************************************
	 * 将包送给相应的 input 函数去处理：
	 *   ip_forward ?
	 *   ip_local_input ?
	 *   .......        ?
	 *
	 *   如上述所说，由那个处理是由
	 *   ip_route_input_noref 这个函数来选择的。
	 * ******************************************************/
	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	net = dev_net(dev);
	IP_UPD_PO_STATS_BH(net, IPSTATS_MIB_IN, skb->len);
	
	/*************************************************
	 * 如果当前的skb的users成员大于1, 则调用skb_clone
	 * 来clone一份skb
	 * （deliver_skb的时候会先做 atomic_inc(&skb->users) 然后再调用ip_rcv）
	 * 
	 * */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

    /******************************************************
     * 处理存在分片的情况，如果包存在分片，那么此处会确保
     * ip头在单独的skb中，如果不在，则做调整，确保其处于
     * 线性缓冲中，以便后续进行解析操作
     * ****************************************************/
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

    /******************************************************
     * 基本的检查：
     *      如果头部长度小于20 或者版本号不是 IPv4，则丢弃
     * ****************************************************/
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	IP_ADD_STATS_BH(net,
			IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
			max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = ip_hdr(skb);


    /**********************************************************
     * 检查校验和，不正确则丢弃
     * ********************************************************/
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

    /**********************************************************
     * tot_len ： 表示 total length，指整个IP包的长度,
     *
     * 如果长度 大于 skb->len 或 小于 iphdr 长度，则可确认
     * 是非法值，丢弃掉.
     * ********************************************************/
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means ***skb->len holds ntohs(iph->tot_len).***
     *
     * 到此处，二层头便被抹除了
	 */
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/*******************************************************
	 * 计算出 transport_header 的位置
	 * *****************************************************/
	skb->transport_header = skb->network_header + iph->ihl*4;

	/* 
     * Remove any debris in the socket control block 
     *
     * 清空二层遗留下来的control buffer block, 
     *
     * 为之后存放三层的 contorl buffer block 做准备
     *
     * */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* 
     * Must drop socket now because of tproxy. 
     *
     * 如果skb被其他人持有，则调用skb_orphan, 使skb成为孤儿，
     *
     * 相当于把所有权抢过来了
     *
     * */
	skb_orphan(skb);

	/*******************************************************
	 * 做完IP包的基础性检查后，开始过 netfilter，
	 *
	 * 如果过了netfilter, 则调用 ip_rcv_finish 
	 *
	 * 将包传递到上层协议处理,
	 *
	 * 此时走的是 PREROUTING 表，路由选择还没有进行，
	 *
	 * 等到 ip_rcv_finish 中进行路由选择后，会确定包的走向，
	 * 设定 input 调用，如果是本地收包，就会在 ip_local_input中
	 * 走 INPUT chain，如果是转发包，则会在 ip_forward 中
	 * 走 FORWARD chain
	 * *****************************************************/
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}
