/* pid_maps POC module */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h> /* seq_read, seq_lseek, single_release */
#include <uapi/linux/stat.h> /* S_IRUSR etc */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h> /* kzalloc */
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/uaccess.h> /* copy_from_user */

MODULE_LICENSE("GPL");

static struct dentry *debugfs_root_dir = NULL;
static struct dentry *debugfs_pid_add_file = NULL;
static struct dentry *debugfs_pid_del_file = NULL;
static LIST_HEAD(priv_list_head);
pid_t last_pid_nr_added = 0;

struct pid_maps_private {
	pid_t pid_nr;
	struct pid *pid_struct;
	struct dentry *debugfs_pid_dir;
	struct inode *inode;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *tail_vma;
	void *addr;
	struct list_head priv_list_node;
} __randomize_layout;

static struct pid_maps_private *pid_maps_private_data_alloc(
	pid_t pid_nr,
	struct pid *pid_struct)
{
	struct pid_maps_private *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL_ACCOUNT);
	priv->pid_nr = pid_nr;
	priv->pid_struct = pid_struct;
	list_add_tail(&priv->priv_list_node, &priv_list_head);

	return priv;
}

static void pid_maps_private_data_free(struct pid_maps_private *priv)
{
	if (priv->debugfs_pid_dir) {
		printk(KERN_ERR "[pid_maps] debugfs_remove_recursive entry  pid: %d\n", priv->pid_nr);
		debugfs_remove_recursive(priv->debugfs_pid_dir);
		printk(KERN_ERR "[pid_maps] debugfs_remove_recursive exit  pid: %d\n", priv->pid_nr);
	}

	list_del(&priv->priv_list_node);
	memset(priv, 0, sizeof(*priv));
	kfree(priv);
}

static struct pid_maps_private *pid_maps_private_data_search(pid_t pid_nr)
{
	struct pid_maps_private *priv;

	list_for_each_entry(priv, &priv_list_head, priv_list_node) {
		if (priv->pid_nr == pid_nr)
			return priv;
	}
	return NULL;
}

static struct mm_struct *_mm_access_start(struct pid_maps_private *priv)
{
	struct mm_struct *mm = priv->mm;

	if (mm) {
		down_read(&mm->mmap_sem);
		priv->tail_vma = NULL; //get_gate_vma(mm);
	}
	return mm;
}

static void _mm_access_stop(struct pid_maps_private *priv)
{
	struct mm_struct *mm = priv->mm;

	up_read(&mm->mmap_sem);
}

static struct vm_area_struct *m_next_vma(struct pid_maps_private *priv,
	struct vm_area_struct *vma)
{
	if (vma == priv->tail_vma)
		return NULL;
	return vma->vm_next ?: priv->tail_vma;
}

static void m_cache_vma(struct seq_file *m, struct vm_area_struct *vma)
{
	if (m->count < m->size)	/* vma is copied successfully */
		m->version = m_next_vma(m->private, vma) ? vma->vm_end : -1UL;
}

static void *m_start(struct seq_file *m, loff_t *ppos)
{
	struct pid_maps_private *priv = m->private;
	unsigned long last_addr = m->version;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned int pos = *ppos;

	/* See m_cache_vma(). Zero at the start or after lseek. */
	if (last_addr == -1UL)
		return NULL;

	mm = _mm_access_start(priv);
	if (IS_ERR(mm))
		return NULL;

	if (last_addr) {
		vma = find_vma(mm, last_addr - 1);
		if (vma && vma->vm_start <= last_addr)
			vma = m_next_vma(priv, vma);
		if (vma)
			return vma;
	}

	m->version = 0;
	if (pos < mm->map_count) {
		for (vma = mm->mmap; pos; pos--) {
			m->version = vma->vm_start;
			vma = vma->vm_next;
		}
		return vma;
	}

	/* we do not bother to update m->version in this case */
	if (pos == mm->map_count && priv->tail_vma)
		return priv->tail_vma;

	_mm_access_stop(priv);
	return NULL;
}

static void *m_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct pid_maps_private *priv = m->private;
	struct vm_area_struct *next;

	(*pos)++;
	next = m_next_vma(priv, v);
	if (!next)
		_mm_access_stop(priv);
	return next;
}

static void m_stop(struct seq_file *m, void *v)
{
	struct pid_maps_private *priv = m->private;

	if (!IS_ERR_OR_NULL(v))
		_mm_access_stop(priv);
}

/*
 * Indicate if the VMA is a stack for the given task; for
 * /proc/PID/maps that is the stack of the main task.
 */
static int is_stack(struct vm_area_struct *vma)
{
	/*
	 * We make no effort to guess what a given thread considers to be
	 * its "stack".  It's not even well-defined for programs written
	 * languages like Go.
	 */
	return vma->vm_start <= vma->vm_mm->start_stack &&
		vma->vm_end >= vma->vm_mm->start_stack;
}

static void show_vma_header_prefix(struct seq_file *m,
	unsigned long start, unsigned long end,
	vm_flags_t flags, unsigned long long pgoff,
	dev_t dev, unsigned long ino)
{
	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m, "%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu ",
		   start,
		   end,
		   flags & VM_READ ? 'r' : '-',
		   flags & VM_WRITE ? 'w' : '-',
		   flags & VM_EXEC ? 'x' : '-',
		   flags & VM_MAYSHARE ? 's' : 'p',
		   pgoff,
		   MAJOR(dev), MINOR(dev), ino);
}

static const char *_arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_MPX)
		return "[mpx]";
	return NULL;
}

static void show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;

	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}

	start = vma->vm_start;
	end = vma->vm_end;
	show_vma_header_prefix(m, start, end, flags, pgoff, dev, ino);

	/*
	 * Print the dentry name for named mappings, and a
	 * special [heap] marker for the heap:
	 */
	if (file) {
		seq_pad(m, ' ');
		seq_file_path(m, file, "\n");
		goto done;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto done;
	}

	name = _arch_vma_name(vma);
	if (!name) {
		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
			vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}

		if (is_stack(vma))
			name = "[stack]";
	}

done:
	if (name) {
		seq_pad(m, ' ');
		seq_puts(m, name);
	}
	seq_putc(m, '\n');
}

static int show_map(struct seq_file *m, void *v)
{
	show_map_vma(m, v);
	m_cache_vma(m, v);
	return 0;
}

static const struct seq_operations pid_maps_seq_ops = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_map
};

static inline void seq_set_private(struct file *file, void *private)
{
	struct seq_file *seq = file->private_data;
	seq->private = private;
}

static inline void *seq_get_private(struct file *file)
{
	struct seq_file *seq = file->private_data;
	return seq->private;
}

static int pid_maps_release(struct inode *inode, struct file *file);

static int pid_maps_fopen(struct inode *inode, struct file *file)
{
	struct pid_maps_private *priv = inode->i_private;
	pid_t pid_nr = priv->pid_nr;
	struct pid *pid_struct;
	struct task_struct *task;
	int rc;

	pid_struct = find_get_pid(pid_nr);
	if (IS_ERR_OR_NULL(pid_struct)) {
		priv->pid_struct = NULL;
		printk(KERN_ERR "[pid_maps] maps_fopen, pid not found: %d\n", pid_nr);
		return -EINVAL;
	}
	if (pid_struct != priv->pid_struct) {
		printk(KERN_ERR "[pid_maps] maps_fopen, pid struct do not match: %d\n", pid_nr);
		return -EINVAL;
	}

	task = pid_task(pid_struct, PIDTYPE_PID);
	if (IS_ERR_OR_NULL(task)) {
		printk(KERN_ERR "[pid_maps] maps_fopen, pid_task failed, pid: m%d\n", pid_nr);
		return PTR_ERR(task);
	}
	printk(KERN_INFO "[pid_maps] map pid: %d cmd: %s\n", pid_nr, task->comm);

	priv->inode = inode;
	priv->task = task;
	priv->mm = get_task_mm(task);
	if (IS_ERR(priv->mm)) {
		int err = PTR_ERR(priv->mm);
		printk(KERN_ERR "[pid_maps] get_task_mm failed, pid: m%d\n", pid_nr);
		pid_maps_release(inode, file);
		return err;
	}

	rc = seq_open(file, &pid_maps_seq_ops);
	if (rc < 0) {
		printk(KERN_ERR "[pid_maps] seq_open failed, pid: m%d\n", pid_nr);
		pid_maps_release(inode, file);
		return rc;
	}
	seq_set_private(file, priv);

	return 0;
}

static int pid_maps_release(struct inode *inode, struct file *file)
{
	struct pid_maps_private *priv = seq_get_private(file);

	if (IS_ERR_OR_NULL(priv->pid_struct)) {
		printk(KERN_ERR "[pid_maps] skip maps release pid: %d\n", priv->pid_nr);
		return 0;
	}

	printk(KERN_INFO "[pid_maps] maps release pid: %d\n", priv->pid_nr);

	if (priv->mm)
		mmput(priv->mm);

	if (priv->pid_struct)
		put_pid(priv->pid_struct);

	return seq_release(inode, file);
}

static const struct file_operations pid_maps_fops = {
	.owner = THIS_MODULE,
	.open = pid_maps_fopen,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = pid_maps_release,
};

static int debugfs_pid_addr_in(void *data, u64 val)
{
	struct pid_maps_private *priv = data;

	if (!IS_ERR_OR_NULL(priv)) {
		priv->addr = (void *)val;
		printk(KERN_INFO "[pid_maps] addr_in, pid: %d addr: 0x%016llx\n", priv->pid_nr, (u64)priv->addr);
	} else {
		printk(KERN_ERR "[pid_maps] addr_in, priv: NULL\n");
	}

	return 0;
}
static int debugfs_pid_addr_out(void *data, u64 *val)
{
	struct pid_maps_private *priv = data;
	if (!IS_ERR_OR_NULL(priv)) {
		printk(KERN_INFO "[pid_maps] addr out, pid: %d addr: 0x%016llx\n", priv->pid_nr, (u64)priv->addr);
		*val = (u64)priv->addr;
	} else {
		*val = 0;
		printk(KERN_ERR "[pid_maps] addr_out, priv: NULL\n");
	}

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pid_addr_fops, debugfs_pid_addr_out, debugfs_pid_addr_in, "0x%016llx\n");

static int debugfs_pid_u64_out(void *data, u64 *val)
{
	struct pid_maps_private *priv = data;
	if (!IS_ERR_OR_NULL(priv)) {
		u64 *p64 = (u64 *)priv->addr;
		if (!IS_ERR_OR_NULL(p64)) {
			copy_from_user(val, p64, sizeof(u64));
			printk(KERN_INFO "[pid_maps] u64_out, pid: %d p64: 0x%016llx val: 0x%016llx\n", priv->pid_nr, (u64)p64, *val);
		} else {
			*val = 0;
			printk(KERN_ERR "[pid_maps] u64_out, pid: %d p64: NULL\n", priv->pid_nr);
		}
	} else {
		*val = 0;
		printk(KERN_ERR "[pid_maps] u64_out, priv: NULL\n");
	}

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pid_u64_fops, debugfs_pid_u64_out, NULL, "0x%016llx\n");

static int debugfs_pid_add_in(void *data, u64 val)
{
	pid_t pid_nr = (pid_t)val;
	int err = 0;
	struct pid *pid_struct;
	struct pid_maps_private *priv;
	struct dentry *debugfs_pid_maps_file;
	struct dentry *debugfs_pid_addr_file;
	struct dentry *debugfs_pid_u64_file;
	char pid_str[8];

	printk(KERN_INFO "[pid_maps] pid: %d\n", pid_nr);

	pid_struct = find_vpid(pid_nr);
	if (!pid_struct) {
		printk(KERN_ERR "[pid_maps] failed to find pid: %d\n", pid_nr);
		err = -EINVAL;
		goto out;
	}

	priv = pid_maps_private_data_alloc(pid_nr, pid_struct);
	if (!priv) {
		printk(KERN_ERR "[pid_maps] failed to alloc private data, pid: %d\n", pid_nr);
		err = -ENOMEM;
		goto out;
	}

	snprintf(pid_str, sizeof(pid_str), "%d", pid_nr);
	priv->debugfs_pid_dir = debugfs_create_dir(pid_str, debugfs_root_dir);
	if (!priv->debugfs_pid_dir) {
		printk(KERN_ERR "[pid_maps] failed to create debugs dir, pid: %d\n", pid_nr);
		err = -EIO;
		goto out_free_priv;
	}

	debugfs_pid_maps_file = debugfs_create_file(
			"maps", /* name */
			S_IRUSR | S_IRGRP | S_IROTH, /* read only */
			priv->debugfs_pid_dir, /* parent entry */
			(void *)priv, /* data */
			&pid_maps_fops);
	if (!debugfs_pid_maps_file) {
		printk(KERN_ERR "[pid_maps] failed to create debugs map entry, pid: %d\n", pid_nr);
		err = -EIO;
		goto out_free_priv;
	}

	debugfs_pid_addr_file = debugfs_create_file(
			"addr", /* name */
			S_IWUSR | S_IWGRP | S_IWOTH, /* write only */
			priv->debugfs_pid_dir, /* parent entry */
			(void *)priv, /* data */
			&pid_addr_fops);
	if (!debugfs_pid_addr_file) {
		printk(KERN_ERR "[pid_maps] failed to create debugs addr entry, pid: %d\n", pid_nr);
		err = -EIO;
		goto out_free_priv;
	}

	debugfs_pid_u64_file = debugfs_create_file(
			"u64", /* name */
			S_IWUSR | S_IWGRP | S_IWOTH, /* write only */
			priv->debugfs_pid_dir, /* parent entry */
			(void *)priv, /* data */
			&pid_u64_fops);
	if (!debugfs_pid_u64_file) {
		printk(KERN_ERR "[pid_maps] failed to create debugs u64 entry, pid: %d\n", pid_nr);
		err = -EIO;
		goto out_free_priv;
	}

	last_pid_nr_added = pid_nr;
	goto out;

out_free_priv:
	pid_maps_private_data_free(priv);
out:
	return err;
}

static int debugfs_pid_add_out_last(void *data, u64 *val)
{
	*val = (u64)last_pid_nr_added;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pid_add_fops, debugfs_pid_add_out_last, debugfs_pid_add_in, "%llu\n");

static int debugfs_pid_del_in(void *data, u64 val)
{
	pid_t pid_nr = (pid_t)val;
	struct pid_maps_private *priv;

	priv = pid_maps_private_data_search(pid_nr);
	if (priv == NULL) {
		printk(KERN_INFO "[pid_maps] pid_del, pid not found: %dn", pid_nr);
		return -EINVAL;
	}

	pid_maps_private_data_free(priv);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pid_del_fops, NULL, debugfs_pid_del_in, "%llu\n");

static int pid_maps_init(void)
{
	debugfs_root_dir = debugfs_create_dir("pid_maps", NULL);
	if (!debugfs_root_dir)
		return -EINVAL;

	debugfs_pid_add_file = debugfs_create_file(
		"pid_add",
		S_IWUSR | S_IWGRP | S_IWOTH, /* write only */
		debugfs_root_dir,
		NULL, /* no data */
		&pid_add_fops);
	if (!debugfs_pid_add_file)
		return -EINVAL;

	debugfs_pid_del_file = debugfs_create_file(
		"pid_del",
		S_IWUSR | S_IWGRP | S_IWOTH, /* write only */
		debugfs_root_dir,
		NULL, /* no data */
		&pid_del_fops);
	if (!debugfs_pid_del_file)
		return -EINVAL;

	printk(KERN_INFO "[pid_maps] entry\n");
	return 0;
}

static void pid_maps_exit(void)
{
	printk(KERN_INFO "[pid_maps] exit\n");

	debugfs_remove_recursive(debugfs_root_dir);
}

module_init(pid_maps_init)
module_exit(pid_maps_exit)
