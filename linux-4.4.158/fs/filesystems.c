/*
 *  linux/fs/filesystems.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  table of configured filesystems
 */

#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/*
 * Handling of filesystem drivers list.
 * Rules:
 *	Inclusion to/removals from/scanning of list are protected by spinlock.
 *	During the unload module must call unregister_filesystem().
 *	We can access the fields of list element if:
 *		1) spinlock is held or
 *		2) we hold the reference to the module.
 *	The latter can be guaranteed by call of try_module_get(); if it
 *	returned 0 we must skip the element, otherwise we got the reference.
 *	Once the reference is obtained we can drop the spinlock.
 */

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);

/* WARNING: This can be used only if we _already_ own a reference 
 * 增加注册的文件系统的引用计数，使其不能被释放
 * */
void get_filesystem(struct file_system_type *fs)
{
	__module_get(fs->owner);
}

/***********************************************
 * 当我们不再使用这个文件系统的时候，就减少其引用
 *
 * *********************************************/
void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}


/*****************************************************************
 * 根据名称 name 查找全局系统链表 file_systems 上是否有对应的
 * 文件系统项
 *
 * 如果有，则返回该项
 *
 * 如果没有，则返回链表尾部可以插入新项的位置的指针
 *
 * ***************************************************************/
static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
	struct file_system_type **p;
	for (p=&file_systems; *p; p=&(*p)->next)
		if (strlen((*p)->name) == len &&
		    strncmp((*p)->name, name, len) == 0)
			break;
	return p;
}

/**
 *	注册一个新的文件系统
 *
 *	内核维护了一个文件系统链表 
 *	    file_systems
 *  并通过一个读写锁
 *      file_systems_lock
 *  来同步这个链表的访问
 *
 * 注册的动作做的主要的事情就是如下几个步骤：
 *  1. 持有写锁 file_systems_lock
 *  2. 调用 find_filesystem 根据名称查找链表 file_systems 上是否已经注册了对应的
 *     文件系统
 *  3. 如果有，则注册失败，释放写锁返回EBUSY
 *  4. 否则 find_systems 返回指向链表中最后一个node的next成员的指针，然后将我们
 *     传递进来的 fs 赋给这个指针指向的位置，这样的话，我们的新的文件系统就注册
 *     到文件系统链表 file_systems 上了 ( 从此处也可以看出 file_systems 就是一个
 *     单向链表，他并没有使用 list_head 这样的通用双向链表结构，而是直接定义了
 *     一个 next 指针)
 *  5. 释放写锁并且返回成功
 *
 * Tips:
 *      /proc/filesystems 这个接口应该就是通过遍历这个文件系统链表得到的
 *
 *	register_filesystem - register a new filesystem
 *	@fs: the file system structure
 *
 *	Adds the file system passed to the list of file systems the kernel
 *	is aware of for mount and other syscalls. Returns 0 on success,
 *	or a negative errno code on an error.
 *
 *	The &struct file_system_type that is passed is linked into the kernel 
 *	structures and must not be freed until the file system has been
 *	unregistered.
 */
 
int register_filesystem(struct file_system_type * fs)
{
	int res = 0;
	struct file_system_type ** p;
    
    /* 首先检查文件系统名称是否合法, 不能包含 '.' 字符 */
	BUG_ON(strchr(fs->name, '.'));

    /* ************************************************************************
     * 检查传进来的参数的 next 指针，如果不为空就认为它已经加入文件系统链表了
     * 这是个简单粗暴的检查，但是有效，所以当我们定义 file_system_type 的时候，
     * 一定要先将 next 成员初始化为 NULL
     * ***********************************************************************/
	if (fs->next)
		return -EBUSY;

    /*************************************************************************
     * file_systems_lock 是个全局的读写锁，用于同步对 file_systems 这个链表的
     * 读和修改
     * ***********************************************************************/
	write_lock(&file_systems_lock);

    /*************************************************************************
     * 首先查找当时是否有同名的文件系统注册了，如果有，则返回指向以存在的文件
     * 系统项的指针的指针，否则，指向最后一个文件系统项的 next 成员指针, 因为
     * 这个next处于文件尾, 其值一定是 NULL，所以恰好是一个可以插入的位置，所以
     * 此时恰好就找到了可以插入的位置, 直接通过赋值将新文件系统注册到链表上
     * ***********************************************************************/
	p = find_filesystem(fs->name, strlen(fs->name));
	if (*p)
		res = -EBUSY;
	else
		*p = fs;

    /* 当一切处理完成后释放锁 */
	write_unlock(&file_systems_lock);
	return res;
}

EXPORT_SYMBOL(register_filesystem);

/**
 *	
 *  反注册文件系统，其主要的工作就是从链表上找到并移除对应名称的
 *  文件系统项
 *	unregister_filesystem - unregister a file system
 *	@fs: filesystem to unregister
 *
 *	Remove a file system that was previously successfully registered
 *	with the kernel. An error is returned if the file system is not found.
 *	Zero is returned on a success.
 *	
 *	Once this function has returned the &struct file_system_type structure
 *	may be freed or reused.
 */
 
int unregister_filesystem(struct file_system_type * fs)
{
	struct file_system_type ** tmp;

	write_lock(&file_systems_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (fs == *tmp) {
			*tmp = fs->next;
			fs->next = NULL;
			write_unlock(&file_systems_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&file_systems_lock);

	return -EINVAL;
}

EXPORT_SYMBOL(unregister_filesystem);

/*****************************************************
 * 根据名称查找文件系统项在链表中的索引
 * ***************************************************/
#ifdef CONFIG_SYSFS_SYSCALL
static int fs_index(const char __user * __name)
{
	struct file_system_type * tmp;
	struct filename *name;
	int err, index;

	name = getname(__name);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return err;

	err = -EINVAL;
	read_lock(&file_systems_lock);
	for (tmp=file_systems, index=0 ; tmp ; tmp=tmp->next, index++) {
		if (strcmp(tmp->name, name->name) == 0) {
			err = index;
			break;
		}
	}
	read_unlock(&file_systems_lock);
	putname(name);
	return err;
}

/********************************************************
 * 获取文件系统链表中第 index 个 node 的，名称
 * ******************************************************/
static int fs_name(unsigned int index, char __user * buf)
{
	struct file_system_type * tmp;
	int len, res;

	read_lock(&file_systems_lock);
	for (tmp = file_systems; tmp; tmp = tmp->next, index--)
		if (index <= 0 && try_module_get(tmp->owner))
			break;
	read_unlock(&file_systems_lock);
	if (!tmp)
		return -EINVAL;

	/* OK, we got the reference, so we can safely block */
	len = strlen(tmp->name) + 1;
	res = copy_to_user(buf, tmp->name, len) ? -EFAULT : 0;
	put_filesystem(tmp);
	return res;
}

/* *******************************************************
 * 获取文件系统链表中 node 的个数 ，也就是系统中注册的
 * 文件系统的数量
 * *******************************************************/
static int fs_maxindex(void)
{
	struct file_system_type * tmp;
	int index;

	read_lock(&file_systems_lock);
	for (tmp = file_systems, index = 0 ; tmp ; tmp = tmp->next, index++)
		;
	read_unlock(&file_systems_lock);
	return index;
}

/*
 * Whee.. Weird sysv syscall. 
 * 这个系统调用就是用于获取当前系统中注册的文件系统的信息，但是
 * 貌似对我们来说没什么用处
 */
SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
{
	int retval = -EINVAL;

	switch (option) {
		case 1:
			retval = fs_index((const char __user *) arg1);
			break;

		case 2:
			retval = fs_name(arg1, (char __user *) arg2);
			break;

		case 3:
			retval = fs_maxindex();
			break;
	}
	return retval;
}
#endif

/*************************************************************
 *
 * dump 当前系统中文件系统列表到 buf 中
 *
 * ***********************************************************/
int __init get_filesystem_list(char *buf)
{
	int len = 0;
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp && len < PAGE_SIZE - 80) {
		len += sprintf(buf+len, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return len;
}


/****************************************************************
 *
 * 用于实现 /proc/filesystems，其实就是简单的遍历链表并通过proc导出
 *
 * **************************************************************/
#ifdef CONFIG_PROC_FS
static int filesystems_proc_show(struct seq_file *m, void *v)
{
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp) {
		seq_printf(m, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return 0;
}

static int filesystems_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, filesystems_proc_show, NULL);
}

static const struct file_operations filesystems_proc_fops = {
	.open		= filesystems_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_filesystems_init(void)
{
	proc_create("filesystems", 0, NULL, &filesystems_proc_fops);
	return 0;
}
module_init(proc_filesystems_init);
#endif


/****************************************************************
 *  获取指定名称文件系统的文件系统项
 *  *************************************************************/
static struct file_system_type *__get_fs_type(const char *name, int len)
{
	struct file_system_type *fs;

	read_lock(&file_systems_lock);
	fs = *(find_filesystem(name, len));
	if (fs && !try_module_get(fs->owner))
		fs = NULL;
	read_unlock(&file_systems_lock);
	return fs;
}

/****************************************************************
 * 尝试根据名称获取一个文件系统的系统项
 *
 * 如果这个文件系统并没有注册，则尝试通过request_module去加载这个文件系统的模块
 *
 * 假定文件系统模块的名称为 fs-<name>.ko 
 *
 * 如果加载成功了，对应的文件系统就应该被注册上了，那么此时再去查找一次
 */
struct file_system_type *get_fs_type(const char *name)
{
	struct file_system_type *fs;
	const char *dot = strchr(name, '.');
	int len = dot ? dot - name : strlen(name);

	fs = __get_fs_type(name, len);
	if (!fs && (request_module("fs-%.*s", len, name) == 0))
		fs = __get_fs_type(name, len);

	if (dot && fs && !(fs->fs_flags & FS_HAS_SUBTYPE)) {
		put_filesystem(fs);
		fs = NULL;
	}
	return fs;
}

EXPORT_SYMBOL(get_fs_type);
