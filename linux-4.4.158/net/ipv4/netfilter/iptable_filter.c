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


/*********************************************************************
 * 该宏用于表示当前tables中的存在的标准CHAINs, 相当与一个BITMAP
 * *******************************************************************/
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
     * 该表的L3协议类型, 当前是 IPv4
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

    /*******************************************
     * 遍历所有的rule
     * ****************************************/
	return ipt_do_table(skb, state, state->net->ipv4.iptable_filter);
}

static struct nf_hook_ops *filter_ops __read_mostly;

/* Default to forward because I got too much mail already. */
static bool forward = true;
module_param(forward, bool, 0000);

static int __net_init iptable_filter_net_init(struct net *net)
{
    /*************************************************************
     * 关于为什么这个结构叫 ipt_replace, 解释如下:
     *
     *      ipt_replace这个名称和用户程序iptables有关系，
     *      iptables添加删除rules的时候，其做法不是一次
     *      添加或者删除一条，而是每次先获取所有的rules，
     *      然后对这些rules进行添加或者附加或者删除，
     *      在用户空间处理完后，生成了一个新的列表。
     *      生成后的列表会通过 IPT_SO_SET_REPLACE 传递给
     *      用户空间，替换掉用户空间的所有rules，这样
     *      就完成了iptables rules的添加/删除操作.
     *
     *      也就是说，整个过程可以总结为三步：
     *          1. 获取
     *          2. 修改
     *          3. 替换(名称的由来)
     *
     * ===========================================================
     * 此处是在内核中添加初始化entries，但是其动作其实和用户空间
     * 添加是相似的，也是一个替换的过程，只不过这些entries不是从
     * 内核中过去的，而是直接创建了几条entries，然后直接设置到
     * tables中，其实也算是一个替换空表的过程了
     *
     * ===========================================================
     * 另外，需要注意的是，关于 ipt_replace，其实rules并不是存放在
     * ipt_replace这个结构中，其只是作为一个header，在内存中的布局
     * 大概如下:
     *      ipt_replace
     *      ipt_standard
     *      ......
     *      ipt_standard
     *      ipt_error
     * ***********************************************************/
	struct ipt_replace *repl;
    
    /*************************************************************
     * 申请一个ipt_replace 对象空间
     * 基本上就是 kalloc 一个如下对象：
     *   struct {
	 *      struct type##_replace repl;
	 *      struct type##_standard entries[];
     *   };
     * valid_hooks 这类的成员赋值而已，没什么很重要的实际内容
     *
     * 当前packet_filter 这个参数在 ipt_alloc_initial_table 函数中
     * 似乎是暂时没有用到的，所以不管他先
     *
     * 如上类型的对象，但是返回的数据被强制转换为了 
     *          ipt_replace* 类型
     *
     * ===========================================================
     * 2020/06/22
     *  解释下动作具体做了啥:
     *      1. 通过 hweight32(valid_hooks) 获取valid_hooks中的个数，
     *      也就是filter表中的标准CHAINS(INPUT/FORWARD/OUTPUT)的个数(此处也就是3)
     *      再加上一个 opt_error, 就是4个了。如此以来，申请的对象的布局如下：
     *          ipt_replace
     *          ipt_standard    INPUT chain
     *          ipt_standard    FORWARD chain (此处也解释了下面(struct ipt_standard*)repl->entries)[1]的由来，其指向的正好是FORWARD对象)
     *          ipt_standard    OUTPUT chain
     *          ipt_error       ERROR target
     * ***********************************************************/
	repl = ipt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;

	/****************************************************************** 
     * Entry 1 is the FORWARD hook 
     *
     * ipt_replace 的最后一个成员恰好是 ipt_entry entries[0],
     * 所以 repl->entries 恰好指向了 上述结构的 ip_standard entries[];
     *
     * 这样以来，此处的 (struct ipt_standard*) 强制转换就合理了
     *
     *
     * 但是为什么当前要访问 entries[1] ？ 这地方的初始化是什么意思
     *
     * 2020/06/21
     *      此处的意思是根据模块参数forward（默认是true）来决定
     *      FORWARD chain 的默认策略
     *          true:   表示默认策略是 ACCEPT
     *          false:  表示默认策略是 DROP
     *
     *
     * 为什么 verdict 要设置为 -NF_ACCEPT-1 而不是 NF_ACCEPT（NF_DROP同） ？？？
     * ***************************************************************/
	((struct ipt_standard *)repl->entries)[1].target.verdict =
		forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;

    /*****************************************************************
     * 将初始化好的 packet filter 表 设置到 net_ns 中
     * ***************************************************************/
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
    /******************************************************
     *
     * ***************************************************/
	.init = iptable_filter_net_init,
	.exit = iptable_filter_net_exit,
};

static int __init iptable_filter_init(void)
{
	int ret;

    /******************************************************
     * 调用 iptable_filter_net_init 来初始化，把
     *  filter 表的标准CHAIN 注册到 hook_list 上
     *  ***************************************************/
	ret = register_pernet_subsys(&iptable_filter_net_ops);
	if (ret < 0)
		return ret;

	/* Register hooks 
     * 对filter表的遍历与hook函数 iptable_filter_hook 关联，
     * 遍历filter表的每个entry都会调用该hook
     * 
     * */
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
