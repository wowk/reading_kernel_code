/*
 * This is the 1999 rewrite of IP Firewalling, aiming for kernel 2.3.x.
 *
 * Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 * Copyright (C) 2000-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables filter table");

#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
			    (1 << NF_INET_FORWARD) | \
			    (1 << NF_INET_LOCAL_OUT))

/*********************************************************************
 *
 * Q: 既然这是一个表的描述，那么entry存在什么地方 ？？？
 *    存在 net.nf.hooks[proto][chain] 这个二维数组中 ？？？
 *
 *
 * ******************************************************************/

static const struct xt_table packet_filter = {
	.name		= "filter",
    /*****************************************************************
     * 此处的valid_hooks是一个bit集合，用于存放当前表支持
     * 的标准CHAIN的集合，如 FILTER_VALID_HOOKS 定义如下：
     *  
     *   #define FILTER_VALID_HOOKS ((1 << NF_BR_LOCAL_IN) | (1 << NF_BR_FORWARD) | (1 << NF_BR_LOCAL_OUT))
     *
     * 可以看出，filter 表支持 INPUT/FORWARD/OUTPUT 三个 CHAIN
     * **************************************************************/
	.valid_hooks	= FILTER_VALID_HOOKS,

	.me		= THIS_MODULE,

    /*****************************************************************
     * 该表的L3协议类型
     * **************************************************************/
	.af		= NFPROTO_IPV4,

    /****************************************************************
     * 当前表的优先级，对于不同表中（如mangle/nat）的同名CHAIN，
     * 使用这个优先级进行比较，值越小优先级越大
     * *************************************************************/
	.priority	= NF_IP_PRI_FILTER,
};

static unsigned int
iptable_filter_hook(void *priv, struct sk_buff *skb,
		    const struct nf_hook_state *state)
{
    /*****************************************
     * 如果是出口包，且不是ip包
     * 或者当前是非法的ip包，
     * 则直接放过，不进入iptable
     * ***************************************/
	if (state->hook == NF_INET_LOCAL_OUT &&
	    (skb->len < sizeof(struct iphdr) ||
	     ip_hdrlen(skb) < sizeof(struct iphdr)))
		/* root is playing with raw sockets. */
		return NF_ACCEPT;

	return ipt_do_table(skb, state, state->net->ipv4.iptable_filter);
}

static struct nf_hook_ops *filter_ops __read_mostly;

/* Default to forward because I got too much mail already. */
static bool forward = true;
module_param(forward, bool, 0000);

static int __net_init iptable_filter_net_init(struct net *net)
{
	struct ipt_replace *repl;

	repl = ipt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	/* Entry 1 is the FORWARD hook */
	((struct ipt_standard *)repl->entries)[1].target.verdict =
		forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;

	net->ipv4.iptable_filter =
		ipt_register_table(net, &packet_filter, repl);
	kfree(repl);
	return PTR_ERR_OR_ZERO(net->ipv4.iptable_filter);
}

static void __net_exit iptable_filter_net_exit(struct net *net)
{
	ipt_unregister_table(net, net->ipv4.iptable_filter);
}

static struct pernet_operations iptable_filter_net_ops = {
	.init = iptable_filter_net_init,
	.exit = iptable_filter_net_exit,
};

static int __init iptable_filter_init(void)
{
	int ret;

	ret = register_pernet_subsys(&iptable_filter_net_ops);
	if (ret < 0)
		return ret;

	/* Register hooks */
	filter_ops = xt_hook_link(&packet_filter, iptable_filter_hook);
	if (IS_ERR(filter_ops)) {
		ret = PTR_ERR(filter_ops);
		unregister_pernet_subsys(&iptable_filter_net_ops);
	}

	return ret;
}

static void __exit iptable_filter_fini(void)
{
	xt_hook_unlink(&packet_filter, filter_ops);
	unregister_pernet_subsys(&iptable_filter_net_ops);
}

module_init(iptable_filter_init);
module_exit(iptable_filter_fini);
