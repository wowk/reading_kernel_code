#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/static_key.h>
#include <linux/netfilter_defs.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>

#ifdef CONFIG_NETFILTER
static inline int NF_DROP_GETERR(int verdict)
{
	return -(verdict >> NF_VERDICT_QBITS);
}

static inline int nf_inet_addr_cmp(const union nf_inet_addr *a1,
				   const union nf_inet_addr *a2)
{
	return a1->all[0] == a2->all[0] &&
	       a1->all[1] == a2->all[1] &&
	       a1->all[2] == a2->all[2] &&
	       a1->all[3] == a2->all[3];
}

static inline void nf_inet_addr_mask(const union nf_inet_addr *a1,
				     union nf_inet_addr *result,
				     const union nf_inet_addr *mask)
{
	result->all[0] = a1->all[0] & mask->all[0];
	result->all[1] = a1->all[1] & mask->all[1];
	result->all[2] = a1->all[2] & mask->all[2];
	result->all[3] = a1->all[3] & mask->all[3];
}

int netfilter_init(void);

struct sk_buff;

struct nf_hook_ops;

struct sock;

struct nf_hook_state {
	unsigned int hook;
	int thresh;
	u_int8_t pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	struct net *net;
	struct list_head *hook_list;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};

static inline void nf_hook_state_init(struct nf_hook_state *p,
				      struct list_head *hook_list,
				      unsigned int hook,
				      int thresh, u_int8_t pf,
				      struct net_device *indev,
				      struct net_device *outdev,
				      struct sock *sk,
				      struct net *net,
				      int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	p->hook = hook;
	p->thresh = thresh;
	p->pf = pf;
	p->in = indev;
	p->out = outdev;
	p->sk = sk;
	p->net = net;
	p->hook_list = hook_list;
	p->okfn = okfn;
}

typedef unsigned int nf_hookfn(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state);

struct nf_hook_ops {
	struct list_head 	list;

	/* User fills in from here down. */
	nf_hookfn		*hook;
	struct net_device	*dev;
	void			*priv;
	u_int8_t		pf;
	unsigned int		hooknum;
	/* Hooks are ordered in ascending priority. */
	int			priority;
};

struct nf_sockopt_ops {
	struct list_head list;

	u_int8_t pf;

	/* Non-inclusive ranges: use 0/0/NULL to never get called. */
	int set_optmin;
	int set_optmax;
	int (*set)(struct sock *sk, int optval, void __user *user, unsigned int len);
#ifdef CONFIG_COMPAT
	int (*compat_set)(struct sock *sk, int optval,
			void __user *user, unsigned int len);
#endif
	int get_optmin;
	int get_optmax;
	int (*get)(struct sock *sk, int optval, void __user *user, int *len);
#ifdef CONFIG_COMPAT
	int (*compat_get)(struct sock *sk, int optval,
			void __user *user, int *len);
#endif
	/* Use the module struct to lock set/get code in place */
	struct module *owner;
};

/* Function to register/unregister hook points. */
int nf_register_net_hook(struct net *net, const struct nf_hook_ops *ops);
void nf_unregister_net_hook(struct net *net, const struct nf_hook_ops *ops);
int nf_register_net_hooks(struct net *net, const struct nf_hook_ops *reg,
			  unsigned int n);
void nf_unregister_net_hooks(struct net *net, const struct nf_hook_ops *reg,
			     unsigned int n);

int nf_register_hook(struct nf_hook_ops *reg);
void nf_unregister_hook(struct nf_hook_ops *reg);
int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n);
void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n);

/* Functions to register get/setsockopt ranges (non-inclusive).  You
   need to check permissions yourself! */
int nf_register_sockopt(struct nf_sockopt_ops *reg);
void nf_unregister_sockopt(struct nf_sockopt_ops *reg);

#ifdef HAVE_JUMP_LABEL
extern struct static_key nf_hooks_needed[NFPROTO_NUMPROTO][NF_MAX_HOOKS];

static inline bool nf_hook_list_active(struct list_head *hook_list,
				       u_int8_t pf, unsigned int hook)
{
	if (__builtin_constant_p(pf) &&
	    __builtin_constant_p(hook))
		return static_key_false(&nf_hooks_needed[pf][hook]);

	return !list_empty(hook_list);
}
#else
static inline bool nf_hook_list_active(struct list_head *hook_list,
				       u_int8_t pf, unsigned int hook)
{
	return !list_empty(hook_list);
}
#endif

int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);

/**
 *	nf_hook_thresh - call a netfilter hook
 *
 *	Returns 1 if the hook has allowed the packet to pass.  The function
 *	okfn must be invoked by the caller in this case.  Any other return
 *	value indicates the packet has been consumed by the hook.
 */
static inline int nf_hook_thresh(u_int8_t pf, unsigned int hook,
				 struct net *net,
				 struct sock *sk,
				 struct sk_buff *skb,
				 struct net_device *indev,
				 struct net_device *outdev,
				 int (*okfn)(struct net *, struct sock *, struct sk_buff *),
				 int thresh)
{
    /*****************************************************************************
	 * 要看懂这个函数，必须先解释一下 netfilter hook list 的组织结构
	 * 这个 hooks 定义的位置为
	 *   struct net
	 *       nf: struct netns_nf
	 *           hooks: struct list_head[NFPROTO_NUMPROTO][NF_MAX_HOOKS]
	 * 
	 *   显示的定义如下
	 *       struct list_head hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
	 * 
	 * 从定义可以看出，其就是一个二维链表数组，其每一个元素都是一个链表头
	 *
	 * 第一维为 L3 协议类型，如 NFPROTO_ARP, NFPROTO_IPV4, NFPROTO_IPV6,
	 * (令人意外的是，还存在 NFPROTO_BRIDGE, 应该是为 br_netfilter 准备的 ？？)
	 *
	 * 第二维是 CHAIN 类型，如: 
	 *         NF_INET_POST_ROUTING,
	 *         NF_INET_PRE_ROUTING,
	 *         NF_INET_LOCAL_IN,
	 *         NF_INET_FORWARD,
	 *         .........
	 *         NF_BR_FORWARD,
	 *         .........
	 * 
	 *
	 * 现在举个例子：
	 *      我们想要找到 iptables 的 PREROUTING chain，
	 *      则应该这样写：
	 *           hook_list = &net->nf.hooks[NFPROTO_IPV4][NF_INET_PRE_ROUTING]
	 * 
	 *
	 * 需要注意的是， iptables 中的不同表（nat，mangle，filter）的
	 * PRETOUING，INPUT，OUTPUT 等 CHAIN 都是在同一个链表中的，怎么区分
	 * 在 nf_hook_slow 中讲述
	 *
     *
     * tips:
     * 对于 hook_list 链表，其每个元素的类型都是 struct nf_hook_entry
     * 这一点需要注意，
     * 相关的数据结构 nf_hook_ops, 通过这个类型结构可以新增 nf_hook_entry
	 * ***************************************************************************/
	struct list_head *hook_list = &net->nf.hooks[pf][hook];






	if (nf_hook_list_active(hook_list, pf, hook)) { // check if hook list is empty
        /* hook list is not empty, go through it */
		struct nf_hook_state state;
        
        /* put all arguments into nf_hook_state for benifit*/
		/*****************************************************
		 * 将所有参数放在 state 中，然后传给
		 * nf_hook_slow, 有点脱裤子放屁的意味,
		 * 不过。。。。。咩。。。。。
		 * **************************************************/
		nf_hook_state_init(&state, hook_list, hook, thresh,
				   pf, indev, outdev, sk, net, okfn);

        /* go through this list */
		return nf_hook_slow(skb, &state);
	}
	return 1;
}

static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return nf_hook_thresh(pf, hook, net, sk, skb, indev, outdev, okfn, INT_MIN);
}
                   
/* Activate hook; either okfn or kfree_skb called, unless a hook
   returns NF_STOLEN (in which case, it's up to the hook to deal with
   the consequences).

   Returns -ERRNO if packet dropped.  Zero means queued, stolen or
   accepted.
*/

/* RR:
   > I don't want nf_hook to return anything because people might forget
   > about async and trust the return value to mean "packet was ok".

   >>> 但是你还是返回了，不得不返回，不这样的话谁知道这包是什么情况


   AK:
   Just document it clearly, then you can expect some sense from kernel
   coders :)
*/

static inline int
NF_HOOK_THRESH(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	       struct sk_buff *skb, struct net_device *in,
	       struct net_device *out,
	       int (*okfn)(struct net *, struct sock *, struct sk_buff *),
	       int thresh)
{
	/**********************************************************************
	 * 这儿开始走 iptables 规则, 其基本上就是遍历链表的过程
	 * *******************************************************************/
	int ret = nf_hook_thresh(pf, hook, net, sk, skb, in, out, okfn, thresh);

	/**********************************************************************
	 * 如果包被 ACCEPT 了，则调用相应的处理函数，如：
	 *       ip_input_finish, ip_finish_output, ip_forward_finish .........
	 *       ip6_input_finish, ip6_finish_output, ip6_forward_finish ........
	 *       等等等等
	 *       （函数名字可能不一定对，但是大差不离，稍后会修正）
	 * *******************************************************************/
	if (ret == NF_ACCEPT) /* 1 means NF_ACCEPT */
		ret = okfn(net, sk, skb);
	return ret;
}

static inline int
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	     struct sk_buff *skb, struct net_device *in, struct net_device *out,
	     int (*okfn)(struct net *, struct sock *, struct sk_buff *),
	     bool cond)
{
	int ret;

	if (!cond ||
	    ((ret = nf_hook_thresh(pf, hook, net, sk, skb, in, out, okfn, INT_MIN)) == 1))
		ret = okfn(net, sk, skb);
	return ret;
}

/****************************************************************************************
 * 这个NF_HOOK不得了，他是整个 netfilter 框架的入口点
 * 现在看看他是怎么处理流经的包的
 * *************************************************************************************/
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return NF_HOOK_THRESH(pf, hook, net, sk, skb, in, out, okfn, INT_MIN);
}

/* Call setsockopt() */
int nf_setsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  unsigned int len);
int nf_getsockopt(struct sock *sk, u_int8_t pf, int optval, char __user *opt,
		  int *len);
#ifdef CONFIG_COMPAT
int compat_nf_setsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, unsigned int len);
int compat_nf_getsockopt(struct sock *sk, u_int8_t pf, int optval,
		char __user *opt, int *len);
#endif

/* Call this before modifying an existing packet: ensures it is
   modifiable and linear to the point you care about (writable_len).
   Returns true or false. */
int skb_make_writable(struct sk_buff *skb, unsigned int writable_len);

struct flowi;
struct nf_queue_entry;

struct nf_afinfo {
	unsigned short	family;
	__sum16		(*checksum)(struct sk_buff *skb, unsigned int hook,
				    unsigned int dataoff, u_int8_t protocol);
	__sum16		(*checksum_partial)(struct sk_buff *skb,
					    unsigned int hook,
					    unsigned int dataoff,
					    unsigned int len,
					    u_int8_t protocol);
	int		(*route)(struct net *net, struct dst_entry **dst,
				 struct flowi *fl, bool strict);
	void		(*saveroute)(const struct sk_buff *skb,
				     struct nf_queue_entry *entry);
	int		(*reroute)(struct net *net, struct sk_buff *skb,
				   const struct nf_queue_entry *entry);
	int		route_key_size;
};

extern const struct nf_afinfo __rcu *nf_afinfo[NFPROTO_NUMPROTO];
static inline const struct nf_afinfo *nf_get_afinfo(unsigned short family)
{
	return rcu_dereference(nf_afinfo[family]);
}

static inline __sum16
nf_checksum(struct sk_buff *skb, unsigned int hook, unsigned int dataoff,
	    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum(skb, hook, dataoff, protocol);
	rcu_read_unlock();
	return csum;
}

static inline __sum16
nf_checksum_partial(struct sk_buff *skb, unsigned int hook,
		    unsigned int dataoff, unsigned int len,
		    u_int8_t protocol, unsigned short family)
{
	const struct nf_afinfo *afinfo;
	__sum16 csum = 0;

	rcu_read_lock();
	afinfo = nf_get_afinfo(family);
	if (afinfo)
		csum = afinfo->checksum_partial(skb, hook, dataoff, len,
						protocol);
	rcu_read_unlock();
	return csum;
}

int nf_register_afinfo(const struct nf_afinfo *afinfo);
void nf_unregister_afinfo(const struct nf_afinfo *afinfo);

#include <net/flow.h>
extern void (*nf_nat_decode_session_hook)(struct sk_buff *, struct flowi *);

static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
#ifdef CONFIG_NF_NAT_NEEDED
	void (*decodefn)(struct sk_buff *, struct flowi *);

	rcu_read_lock();
	decodefn = rcu_dereference(nf_nat_decode_session_hook);
	if (decodefn)
		decodefn(skb, fl);
	rcu_read_unlock();
#endif
}

#else /* !CONFIG_NETFILTER */
static inline int
NF_HOOK_COND(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	     struct sk_buff *skb, struct net_device *in, struct net_device *out,
	     int (*okfn)(struct net *, struct sock *, struct sk_buff *),
	     bool cond)
{
	return okfn(net, sk, skb);
}

static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk,
	struct sk_buff *skb, struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return okfn(net, sk, skb);
}

static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	return 1;
}
struct flowi;
static inline void
nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl, u_int8_t family)
{
}
#endif /*CONFIG_NETFILTER*/

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <linux/netfilter/nf_conntrack_zones_common.h>

extern void (*ip_ct_attach)(struct sk_buff *, const struct sk_buff *) __rcu;
void nf_ct_attach(struct sk_buff *, const struct sk_buff *);
extern void (*nf_ct_destroy)(struct nf_conntrack *) __rcu;
#else
static inline void nf_ct_attach(struct sk_buff *new, struct sk_buff *skb) {}
#endif

struct nf_conn;
enum ip_conntrack_info;
struct nlattr;

struct nfnl_ct_hook {
	struct nf_conn *(*get_ct)(const struct sk_buff *skb,
				  enum ip_conntrack_info *ctinfo);
	size_t (*build_size)(const struct nf_conn *ct);
	int (*build)(struct sk_buff *skb, struct nf_conn *ct,
		     enum ip_conntrack_info ctinfo,
		     u_int16_t ct_attr, u_int16_t ct_info_attr);
	int (*parse)(const struct nlattr *attr, struct nf_conn *ct);
	int (*attach_expect)(const struct nlattr *attr, struct nf_conn *ct,
			     u32 portid, u32 report);
	void (*seq_adjust)(struct sk_buff *skb, struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo, s32 off);
};
extern struct nfnl_ct_hook __rcu *nfnl_ct_hook;

/**
 * nf_skb_duplicated - TEE target has sent a packet
 *
 * When a xtables target sends a packet, the OUTPUT and POSTROUTING
 * hooks are traversed again, i.e. nft and xtables are invoked recursively.
 *
 * This is used by xtables TEE target to prevent the duplicated skb from
 * being duplicated again.
 */
DECLARE_PER_CPU(bool, nf_skb_duplicated);

#endif /*__LINUX_NETFILTER_H*/
