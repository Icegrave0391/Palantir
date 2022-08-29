#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/mman.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <asm/fpu/internal.h>
#include <asm/msr.h>
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
#include <linux/pt.h>
#include <linux/time.h>

/* we are debugging */
#define DEBUG

#define UNHANDLED(condition) BUG_ON(condition)
#define pt_alert(fmt, ...) printk(KERN_EMERG "pt: " fmt, ## __VA_ARGS__)
#define pt_print(fmt, ...) printk(KERN_INFO "pt: " fmt, ## __VA_ARGS__)

#ifdef DEBUG
#define pt_debug(fmt, ...) pt_print(fmt, ## __VA_ARGS__)
#define NEVER(condition) BUG_ON(condition)
#else
#define pt_debug(fmt, ...)
#define NEVER(condition)
#endif

#define PT_XSTATE_CTL 0
#define PT_XSTATE_OUTPUT_BASE 1
#define PT_XSTATE_OUTPUT_MASK 2
#define PT_XSTATE_STATUS 3

#define TOPA_ENTRY_SIZE_4K 0
#define TOPA_ENTRY_SIZE_8K 1
#define TOPA_ENTRY_SIZE_16K 2
#define TOPA_ENTRY_SIZE_32K 3
#define TOPA_ENTRY_SIZE_64K 4
#define TOPA_ENTRY_SIZE_128K 5
#define TOPA_ENTRY_SIZE_256K 6
#define TOPA_ENTRY_SIZE_512K 7
#define TOPA_ENTRY_SIZE_1M 8
#define TOPA_ENTRY_SIZE_2M 9
#define TOPA_ENTRY_SIZE_4M 10
#define TOPA_ENTRY_SIZE_8M 11
#define TOPA_ENTRY_SIZE_16M 12
#define TOPA_ENTRY_SIZE_32M 13
#define TOPA_ENTRY_SIZE_64M 14
#define TOPA_ENTRY_SIZE_128M 15
#define TOPA_ENTRY_SIZE_CHOICE TOPA_ENTRY_SIZE_2M
#define TOPA_BUFFER_SIZE (1 << (12 + TOPA_ENTRY_SIZE_CHOICE))

#define pt_resume() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) | RTIT_CTL_TRACEEN)

#define pt_pause() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) & ~RTIT_CTL_TRACEEN)

#define pt_topa_base() native_read_msr(MSR_IA32_RTIT_OUTPUT_BASE)

#define pt_topa_index() ((native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) \
			& 0xffffffff) >> 7)

#define pt_topa_offset() (native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) >> 32)

#define pt_status() (native_read_msr(MSR_IA32_RTIT_STATUS))

#define pt_state() pt_debug("[cpu:%d,pid:%d]" \
	" CTL: %llx," \
	" STATUS: %llx," \
	" OUTPUT_BASE: %llx," \
	" OUTPUT_MASK: %llx\n", \
	smp_processor_id(), current->pid, \
	native_read_msr(MSR_IA32_RTIT_CTL), \
	pt_status(), \
	pt_topa_base(), \
	native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) \
)

struct topa_entry {
	u64 end:1;
	u64 rsvd0:1;
	u64 intr:1;
	u64 rsvd1:1;
	u64 stop:1;
	u64 rsvd2:1;
	u64 size:4;
	u64 rsvd3:2;
	u64 base:36;
	u64 rsvd4:16;
};

#define TOPA_ENTRY(_base, _size, _stop, _intr, _end) (struct topa_entry) { \
	.base = (_base) >> 12, \
	.size = (_size), \
	.stop = (_stop), \
	.intr = (_intr), \
	.end = (_end), \
}

struct topa {
	struct topa_entry entries[3];
	char *raw;
	struct task_struct *task;
	u64 sequence;
	u64 n_processed;
	struct list_head buffer_list;
	spinlock_t buffer_list_sl;
	bool failed;
	int index;
};

struct pt_buffer {
	// worker to transfer pt traces from memory to file
	struct work_struct work;
	// tasklet is used to queue up works to be done at a later time.
	struct tasklet_struct tasklet;
	struct list_head entry;
	struct topa *topa;
	struct topa *child_topa;
	u64 sequence;
	char *raw;
	u32 size;
	int index;
};

#define pt_fail_topa(topa, fmt, ...) if (!test_and_set_bit(0, \
			(unsigned long *) &topa->failed)) \
	pt_print("[pid:%d] failed: " fmt "\n", \
			(topa)->task->pid, ## __VA_ARGS__)

static char pt_monitor[PATH_MAX];
static struct dentry *pt_monitor_dentry;

static struct kmem_cache *pt_buffer_cache = NULL;
static struct kmem_cache *pt_trace_cache = NULL;
static struct kmem_cache *pt_image_cache = NULL;

/*
* Example of deferred work:
*
* void my_work_handler(struct work_struct *work);
*
* struct work_struct my_work;
* struct workqueue_struct *my_workqueue;
*
* my_workqueue = alloc_workqueue("my_workqueue");
* INIT_WORK(&my_work, my_work_handler);
*
* queue_work(my_workqueue, &my_work);
*/
static struct workqueue_struct *pt_wq;

static atomic64_t pt_flying_tasks = ATOMIC_INIT(0);

static struct file *pt_logfile = NULL;
static loff_t pt_logfile_off = 0;
static DEFINE_MUTEX(pt_logfile_mtx);

/* store trace in pt.log file */
#define pt_close_logfile() do { \
	if (pt_logfile) { \
		filp_close(pt_logfile, NULL); \
		pt_logfile = NULL; \
		pt_logfile_off = 0; \
	} \
} while (0)

#define pt_log_file(buf, count) do { \
	ssize_t s; \
	NEVER(!pt_logfile); \
	s = kernel_write(pt_logfile, (char *) buf, count, pt_logfile_off); \
	UNHANDLED(s < 0); \
	pt_logfile_off += s; \
} while (0)

/* store trace in pt_buffer memory */
#define SIZE_64B 64
#define SIZE_4K PAGE_SIZE
#define SIZE_64M PAGE_SIZE * 16384
#define SIZE_128M PAGE_SIZE * 32768
#define SIZE_1024M PAGE_SIZE * 262144

#define MEMORY_SIZE SIZE_64B

static struct dentry *pt_memory_dentry = NULL;

static char *pt_memory = NULL;
static loff_t pt_memory_off = 0;
static DEFINE_MUTEX(pt_memory_mtx);

#define pt_close_memory() do { \
	if (pt_memory) { \
		vfree(pt_memory); \
		pt_memory = NULL; \
		pt_memory_off = 0; \
	} \
} while (0)

#define pt_log_memory(buf, count) do { \
	ssize_t s; \
	NEVER(!pt_memory); \
	if (count > MEMORY_SIZE - 1 - pt_memory_off) { \
		pt_alert("the size of pt_memory is too small to store all PT traces"); \
		s = MEMORY_SIZE - 1 - pt_memory_off; \
	} \
	else { \
		s = count; \
	} \
	memcpy(pt_memory + pt_memory_off, buf, s); \
    pt_memory_off += s; \
} while(0)

static ssize_t pt_memory_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *offset) {
    return simple_read_from_buffer(user_buf, count, offset, 
                                   pt_memory, pt_memory_off);
}

static ssize_t pt_buffer_write(struct file *file, const char __user *user_buf,
                               size_t count, loff_t *offset) {
    return simple_write_to_buffer(pt_memory, MEMORY_SIZE - 1, offset,
                                  user_buf, count);
}

static const struct file_operations pt_memory_fops = {
    .read = pt_memory_read,
    .write = pt_buffer_write,
};

static int pt_memory_setup(void) {
    /* create a file in the debugfs filesystem */
    pt_memory_dentry = debugfs_create_file("pt_memory",0600, NULL, NULL, 
                                        &pt_memory_fops);
    if (!pt_memory_dentry)
        return -ENOMEM;

    return 0;
}

static void pt_memory_destroy(void) {
	if (pt_memory_dentry)
        debugfs_remove(pt_memory_dentry);
}


#pragma pack(push)

struct pt_logfile_header {
	u32 magic;
	u32 version;
};

/* defined by Griffin, no particular use */
#define PT_LOGFILE_MAGIC 0x51C0FFEE
#define PT_LOGFILE_VERSION 0x1

/* write intel pt metadata */
static void pt_log_header(void)
{
	struct pt_logfile_header h = {
		.magic = PT_LOGFILE_MAGIC,
		.version = PT_LOGFILE_VERSION,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&h, sizeof(h));
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&h, sizeof(h));
	// mutex_unlock(&pt_memory_mtx);
}

enum pt_logitem_kind {
	PT_LOGITEM_BUFFER,
	PT_LOGITEM_PROCESS,
	PT_LOGITEM_THREAD,
	PT_LOGITEM_IMAGE,
	PT_LOGITEM_XPAGE,
	PT_LOGITEM_UNMAP,
	PT_LOGITEM_FORK,
	PT_LOGITEM_SECTION,
	PT_LOGITEM_THREAD_END,
	PT_LOGITEM_AUDIT,
};

struct pt_logitem_header {
	enum pt_logitem_kind kind;
	u32 size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
	u64 sequence;
	u64 size;
};

/* write trace buffer */
static void pt_log_buffer(struct pt_buffer *buf)
{
	struct pt_logitem_buffer item = {
		.header = {
			.kind = PT_LOGITEM_BUFFER,
			.size = sizeof(struct pt_logitem_buffer) + buf->size
		},
		.tgid = buf->topa->task->tgid,
		.pid = buf->topa->task->pid,
		.sequence = buf->sequence,
		.size = buf->size,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	pt_log_file(buf->raw, buf->size);
	mutex_unlock(&pt_logfile_mtx);
	
	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// pt_log_memory(buf->raw, buf->size);
	// mutex_unlock(&pt_memory_mtx);
}

struct pt_logitem_audit {
	struct pt_logitem_header header;
	u64 sid;
    time_t timestamp;
	int pid;
};

/* write PT_LOGITEM_AUDIT: syscall id */
static void pt_log_audit(u64 sid, time_t timestamp, int pid)
{
	struct pt_logitem_audit item = {
		.header = {
			.kind = PT_LOGITEM_AUDIT,
			.size = sizeof(struct pt_logitem_audit),
		},
		.sid = sid,
        .timestamp = timestamp,
		.pid = pid
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// mutex_unlock(&pt_memory_mtx);
}

struct pt_logitem_process {
	struct pt_logitem_header header;
	u64 tgid;
	u64 cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
	char name[TASK_COMM_LEN];
};

/* write PT_LOGITEM_THREAD: thread's tgid and pid */
static void pt_log_thread(struct task_struct *task)
{
	struct pt_logitem_thread item = {
		.header = {
			.kind = PT_LOGITEM_THREAD,
			.size = sizeof(struct pt_logitem_thread),
		},
		.tgid = task->tgid,
		.pid = task->pid,
	};
	strcpy(item.name, task->comm);

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// mutex_unlock(&pt_memory_mtx);
}

/* write PT_LOGITEM_PROCESS: process tgid, cmd's size, cmd, and pid */
static void pt_log_process(struct task_struct *task)
{
	struct pt_logitem_process item = {
		.header = {
			.kind = PT_LOGITEM_PROCESS,
			.size = sizeof(struct pt_logitem_process)
				+ strlen(pt_monitor) + 1
		},
		.tgid = task->tgid,
		.cmd_size = strlen(pt_monitor),
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	pt_log_file(pt_monitor, item.cmd_size + 1);
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// pt_log_memory(pt_monitor, item.cmd_size + 1);
	// mutex_unlock(&pt_memory_mtx);

	pt_log_thread(task);
}

struct pt_logitem_image {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
	u32 size;
	u32 timestamp;
	u64 image_name_length;
};

/* write PT_LOGITEM_IMAGE: capture metadata of images loaded from disk (not including vdso...)  */
static void pt_log_image(struct task_struct *task, u64 base, u32 size, char *image_name)
{
	struct pt_logitem_image item = {
		.header = {
			.kind = PT_LOGITEM_IMAGE,
			.size = sizeof(struct pt_logitem_image)
				+ strlen(image_name) + 1
		},
		.tgid = task-> tgid,
		.base = base,
		.size = size,
		.timestamp = 0,
		.image_name_length = strlen(image_name),
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	pt_log_file(image_name, item.image_name_length + 1);
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// pt_log_memory(image_name, item.image_name_length + 1);
	// mutex_unlock(&pt_memory_mtx);
}

struct pt_logitem_xpage {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
	u64 size;
};

/* 
* write PT_LOGITEM_XPAGE: capture memory for images
* 
* different from pt_log_image that records metadata, pt_log_xpage store actual images
* (e.g., /bin/ls and vdso ...)
*/
static void pt_log_xpage(struct task_struct *task, u64 base,
		u64 real_size, u64 size)
{
	int ret, i, nr_pages, nr_real_pages;
	void *page = (void *) get_zeroed_page(GFP_KERNEL);
	struct pt_logitem_xpage item = {
		.header = {
			.kind = PT_LOGITEM_XPAGE,
			.size = sizeof(struct pt_logitem_xpage) + size
		},
		.tgid = task->tgid,
		.base = base,
		.size = size,
	};

	UNHANDLED(!page);

	if (!real_size)
		real_size = size;

	NEVER(real_size > size);
	NEVER(base & ~PAGE_MASK);
	NEVER(size & ~PAGE_MASK);

	nr_real_pages = PAGE_ALIGN(real_size) >> PAGE_SHIFT;
	nr_pages = size >> PAGE_SHIFT;

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, sizeof(item));
	for (i = 0; i < nr_real_pages; i++) {
		ret = access_process_vm(task, base + i * PAGE_SIZE,
				page, PAGE_SIZE, 0);
		UNHANDLED(ret != PAGE_SIZE);
		pt_log_file(page, PAGE_SIZE);
	}
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, sizeof(item));
	// for (i = 0; i < nr_real_pages; i++) {
	// 	ret = access_process_vm(task, base + i * PAGE_SIZE,
	// 			page, PAGE_SIZE, 0);
	// 	UNHANDLED(ret != PAGE_SIZE);
	// 	pt_log_memory(page, PAGE_SIZE);
	// }
	// mutex_unlock(&pt_memory_mtx);

	memset(page, 0, PAGE_SIZE);

	mutex_lock(&pt_logfile_mtx);
	for (i = 0; i < nr_pages - nr_real_pages; i++) {
		pt_log_file(page, PAGE_SIZE);
	}
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// for (i = 0; i < nr_pages - nr_real_pages; i++) {
	// 	pt_log_memory(page, PAGE_SIZE);
	// }
	// mutex_unlock(&pt_memory_mtx);

	free_page((unsigned long) page);
}

struct pt_logitem_unmap {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
};

struct pt_logitem_fork {
	struct pt_logitem_header header;
	u64 parent_tgid;
	u64 parent_pid;
	u64 child_tgid;
	u64 child_pid;
};

/* write PT_LOGITEM_FORK: parent and child's pid and tgid */
static void pt_log_fork(struct task_struct *parent,
		struct task_struct *child)
{
	struct pt_logitem_fork item = {
		.header = {
			.kind = PT_LOGITEM_FORK,
			.size = sizeof(struct pt_logitem_fork),
		},
		.parent_tgid = parent->tgid,
		.parent_pid = parent->pid,
		.child_tgid = child->tgid,
		.child_pid = child->pid,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log_file(&item, item.header.size);
	mutex_unlock(&pt_logfile_mtx);

	// mutex_lock(&pt_memory_mtx);
	// pt_log_memory(&item, item.header.size);
	// mutex_unlock(&pt_memory_mtx);
}

#pragma pack(pop)

/* cat /sys/kernel/debug/pt_monitor */
static ssize_t
pt_monitor_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, pt_monitor,
			strlen(pt_monitor));
}

/* echo -n ls > /sys/kernel/debug/pt_monitor */
static ssize_t
pt_monitor_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	if (count >= PATH_MAX)
		return -ENOMEM;
	if (*ppos != 0)
		return -EINVAL;

	if (atomic64_read(&pt_flying_tasks))
		/* pt is in using for tracing */
		return -EBUSY;

	/* store the program to be traced in pt_monitor */
	memset(pt_monitor, 0, PATH_MAX);
	if (copy_from_user(pt_monitor, buf, count))
		return -EINVAL;

	/* init pt_logfile */
	pt_close_logfile();

	pt_logfile = filp_open("/var/log/pt.log", O_WRONLY | O_TRUNC
			| O_CREAT | O_LARGEFILE, 0644);
	if (IS_ERR_OR_NULL(pt_logfile))
		return PTR_ERR(pt_logfile);

	/* init pt_memory */
	pt_close_memory();
    pt_memory = (char *) vmalloc(MEMORY_SIZE);
    if (!pt_memory)
        return -ENOMEM;
    memset(pt_memory, 0xff, MEMORY_SIZE);

	pt_log_header();
	workqueue_set_max_active(pt_wq, 1);

	pt_print("offline: %s registered\n", pt_monitor);

	return count;
}

static const struct file_operations pt_monitor_fops = {
	.write = pt_monitor_write,
	.read = pt_monitor_read,
};

/* 
* /sys/kernel/debug/pt_monitor is used to specify the program to be traced
*
* pt_should_monitor compare execve()'ed processes with the program in pt_monitor
* to decide whether the process should be traced
*
* Example: echo ls > /sys/kernel/debug/pt_monitor
*/
static int pt_monitor_setup(void)
{
	pt_monitor_dentry = debugfs_create_file("pt_monitor",
			0600, NULL, NULL, &pt_monitor_fops);
	if (!pt_monitor_dentry) {
		pt_print("unable to create pt_monitor\n");
		return -ENOMEM;
	}
	else {
		pt_print("create pt_monitor\n");
	}

	return 0;
}

static void pt_monitor_destroy(void)
{
	if (pt_monitor_dentry)
		debugfs_remove(pt_monitor_dentry);
}

static int pt_wq_setup(void)
{
	int err = -ENOMEM;

	pt_wq = alloc_workqueue("pt_wq", WQ_UNBOUND | WQ_HIGHPRI, 1);
	if (!pt_wq)
		goto fail;

	return 0;

fail:
	return err;
}

static void pt_wq_destroy(void)
{
	flush_workqueue(pt_wq);
	destroy_workqueue(pt_wq);
}

static void do_setup_topa(struct topa *topa, void *raw)
{
	/* checking virtual address is fine given 1:1 direct mapping */
#define DIRECT_MAPPING_END 0xffffc7ffffffffff
	NEVER((unsigned long) topa > DIRECT_MAPPING_END);
	NEVER((unsigned long) raw > DIRECT_MAPPING_END);
	NEVER((unsigned long) raw & (TOPA_BUFFER_SIZE - 1));

	/* setup topa entries */
	topa->entries[0] = TOPA_ENTRY(virt_to_phys(raw),
			TOPA_ENTRY_SIZE_CHOICE, 0, 1, 0);
	topa->entries[1] = TOPA_ENTRY(virt_to_phys(raw + TOPA_BUFFER_SIZE),
			TOPA_ENTRY_SIZE_4K, 0, 1, 0);
	topa->entries[2] = TOPA_ENTRY(virt_to_phys(topa), 0, 0, 0, 1);

	topa->raw = raw;
}

static void pt_setup_topa(struct topa *topa, void *raw, struct task_struct *task)
{
	topa->task = task;
	topa->sequence = 0;
	topa->n_processed = 0;
	INIT_LIST_HEAD(&topa->buffer_list);
	spin_lock_init(&topa->buffer_list_sl);
	topa->failed = false;
	topa->index = 0;

	do_setup_topa(topa, raw);
}

/* msr = memory specific register */
static void pt_setup_msr(struct topa *topa)
{
	NEVER(pt_enabled());

	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, virt_to_phys(topa));
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	wrmsrl(MSR_IA32_RTIT_CTL, RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
			| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
			| ((TOPA_ENTRY_SIZE_64K + 1) << 24));
}

/* Intel PT configuration is stored in xsave for context switch */
static void pt_setup_xsave(struct topa *topa, struct xregs_state *xsave)
{
	u64 *xregs = (u64 *) get_xsave_addr(xsave, XSTATE_INTEL_PT);
	NEVER(!xregs);

	xregs[PT_XSTATE_STATUS] = 0;
	xregs[PT_XSTATE_OUTPUT_BASE] = virt_to_phys(topa);
	xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	xregs[PT_XSTATE_CTL] = RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
		| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
		| ((TOPA_ENTRY_SIZE_64K + 1) << 24);
}

/* handler to write pt buffers */
static void pt_work(struct work_struct *work)
{
	struct pt_buffer *buf = (struct pt_buffer *) work;

	// Log the buffer first
	pt_log_buffer(buf);

	kmem_cache_free(pt_trace_cache, buf->raw);
}

static void pt_tasklet(unsigned long data)
{
	struct pt_buffer *buf = (struct pt_buffer *) data;

	queue_work(pt_wq, &buf->work);
}

/* assign the trace tranfer task to a worker */
static int pt_move_trace_to_work(struct topa *topa, u32 size,
		struct topa *child_topa, bool waiting)
{
	struct pt_buffer *buf;

	buf = kmem_cache_alloc(pt_buffer_cache, GFP_ATOMIC);
	if (!buf)
		goto fail;

	INIT_WORK(&buf->work, pt_work);
	tasklet_init(&buf->tasklet, pt_tasklet, (unsigned long) buf);
	INIT_LIST_HEAD(&buf->entry);
	buf->topa = topa;
	buf->child_topa = child_topa;
	buf->size = size;
	buf->index = 0;
	buf->raw = topa->raw;

	buf->sequence = topa->sequence++;

	/* programming tasklets for running is called scheduling. */
	tasklet_schedule(&buf->tasklet);

	return 0;

fail:
	return -ENOMEM;
}

/* flush trace buffer to pt.log */
static void pt_flush_trace(struct topa *child_topa, bool waiting)
{
	u32 size;
	struct topa *topa;
	void *new_buffer;

	NEVER(pt_enabled());

	topa = phys_to_virt(pt_topa_base());
	if (topa->failed && !child_topa && !waiting)
		goto end;

	size = pt_topa_offset() + (pt_topa_index()? TOPA_BUFFER_SIZE: 0);

	new_buffer = (void *) kmem_cache_alloc(pt_trace_cache, GFP_ATOMIC);
	if (!new_buffer)
		goto failed;

	if (pt_move_trace_to_work(topa, size, child_topa, waiting) < 0)
		goto free_new_buffer;

	do_setup_topa(topa, new_buffer);

end:
	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	return;

free_new_buffer:
	kmem_cache_free(pt_trace_cache, new_buffer);
failed:
	UNHANDLED(child_topa || waiting);
	pt_fail_topa(topa, "out of memory");
	goto end;
}

/* 
* Allocate topa (including pt buffer and process info) for pt
*
* pt buffer is mapped to physical memory address to reduce runtime overhead
*/
static struct topa *pt_alloc_topa(struct task_struct *task)
{
	struct topa *topa;
	void *raw;

	topa = (struct topa *) __get_free_pages(GFP_KERNEL, 1);
	if (!topa)
		goto fail;

	raw = (void *) kmem_cache_alloc(pt_trace_cache, GFP_KERNEL);
	if (!raw)
		goto free_topa;

	pt_setup_topa(topa, raw, task);

	return topa;

free_topa:
	free_pages((unsigned long) topa, 1);
fail:
	return NULL;
}

/* decide whether an execve()'ed process should be traced */
static bool pt_should_monitor(struct task_struct *task)
{
	char *path, *buf;
	size_t path_len, monitor_len;
	struct mm_struct *mm;
	bool monitored = false;

	monitor_len = strlen(pt_monitor);
	if (!monitor_len)
		return false;

	mm = task->mm;
	if (!mm)
		return false;

	down_read(&mm->mmap_sem);

	if (!mm->exe_file)
		goto up_read_sem;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto up_read_sem;

	path = d_path(&task->mm->exe_file->f_path, buf, PATH_MAX);
	path_len = strlen(path);

	if (monitor_len > path_len)
		goto free_buf;

	/* 
	If the execve()'ed process is different from the executalbe 
	defined in /sys/kernel/debug/pt_monitor, it will not be traced 
	*/
	monitored = strncmp(path + (path_len - monitor_len),
			pt_monitor, monitor_len) == 0;

free_buf:
	kfree(buf);
up_read_sem:
	up_read(&mm->mmap_sem);

	// Evaluate whole-system PT tracing
	// if (strcmp(pt_monitor, "ALL") == 0)
	// 	return true;

	return monitored;
}

void pt_pre_execve(void)
{
	if (!pt_enabled())
		return;

	pt_pause();
	pt_flush_trace(NULL, true);
	pt_resume();
}

/* init topa for task (process) */
static inline struct topa *pt_attach(struct task_struct *task)
{
	struct topa *topa = pt_alloc_topa(task);
	UNHANDLED(!topa);

	if (task == current)
		/* init for execve */
		pt_setup_msr(topa);
	else
		/* init for clone; topa info is stored in xsave */
		pt_setup_xsave(topa, &task->thread.fpu.state.xsave);

	atomic64_inc(&pt_flying_tasks);

	pt_state();

	return topa;
}

/* pause pt tracing and transfer traces from pt buffer to pt.log */
static inline void pt_detach(void)
{
	struct topa *topa;

	NEVER(!pt_enabled());
	pt_pause();

	topa = phys_to_virt(pt_topa_base());
	NEVER(topa->task != current);

	pt_move_trace_to_work(topa, pt_topa_offset(), NULL, true);

	free_pages((unsigned long) topa, 1);

	atomic64_dec(&pt_flying_tasks);
}

/* 
* hook syscall execve():
*
* load images/metadata of execve()'ed processes; allocate topa for new processes
*/
void pt_on_execve(void)
{	
	unsigned long len;
	struct vm_area_struct *vma;
	struct file *prev_file;
	char *image_name, *path;
	
	/* return if intel pt is disabled */
	if (pt_enabled()) {
		/* execve()'ed from a task under tracing */
		pt_debug("[cpu:%d,pid:%d] execve: stop tracing...\n",
				smp_processor_id(), current->pid);
		pt_detach();
	}

	if (!pt_should_monitor(current))
		return;

	pt_debug("[cpu:%d,pid:%d] execve: %s\n", smp_processor_id(),
			current->pid, current->comm);

	pt_log_process(current);

	/* fine without locking because we are in execve */
	/* log loaded images in execve() */
	prev_file = NULL;
	for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
		len = vma->vm_end - vma->vm_start;
		if (vma->vm_file && vma->vm_file != prev_file) {
			image_name = kmem_cache_alloc(pt_image_cache, GFP_ATOMIC);
			memset(image_name, 0, PATH_MAX);
			path = dentry_path_raw(vma->vm_file->f_path.dentry, image_name, PATH_MAX);
			if (!IS_ERR_OR_NULL(path)) {
				// pt_debug("image_name: %s\n", path);
				pt_log_image(current, vma->vm_start, len, path);
				prev_file = vma->vm_file;
			}
			kmem_cache_free(pt_image_cache, image_name);
		}
		if (!(vma->vm_flags & VM_EXEC))
			continue;
		if (vma->vm_flags & VM_WRITE)
			continue;
		NEVER(!(vma->vm_flags & VM_READ));
		pt_log_xpage(current, vma->vm_start, 0, len);
	}

	pt_attach(current);
}

/* 
* hook syscall exit():
*
* flush traces from pt buffer to pt.log when a process terminates
*/
void pt_on_exit(void)
{
	/* return if intel pt is disabled */
	if (!pt_enabled())
		return;

	pt_debug("[cpu:%d,pid:%d] exit: %s\n", smp_processor_id(),
			current->pid, current->comm);
	pt_detach();
}

/*
* pt_on_interrupt is invoked when the pt buffer is full
*/
int pt_on_interrupt(struct pt_regs *regs)
{
	int pt_on;
	u64 *xregs;

	if (!strlen(pt_monitor))
		return -ENOSYS;

	pt_on = pt_enabled();
	if (pt_on) /* off if triggered upon disabling PT */
		pt_pause();

	NEVER(pt_topa_index() == 0);
	pt_flush_trace(NULL, false);

#define is_xsaves(ip) ((*(unsigned int *)(ip) & 0xffffff) == 0x2fc70f)

	if (pt_on) {
		pt_resume();
	} else if (is_xsaves(regs->ip - 3)) {
		xregs = (u64 *) get_xsave_addr((struct xregs_state *) regs->di,
				XSTATE_INTEL_PT);
		xregs[PT_XSTATE_STATUS] = 0;
		xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	}

	return 0;
}

/*
* hook syscall clone():
*
* 1. create topa for cloned process (child)
* 2. flush parent's trace if creating a new process
*/
void pt_on_clone(struct task_struct *child)
{
	/* return if intel pt is disabled */
	if (!pt_enabled())
		return;

	struct topa *child_topa, *topa;
	child_topa = pt_attach(child);

	pt_debug("[cpu:%d,pid:%d] clone: %d (%llx)\n", smp_processor_id(),
			current->pid, child->pid, virt_to_phys(child_topa));

	/* 
	* if tgid == pid -> a new process is created (fork)
	* if tgid != pid -> a new thread is created (clone)
	* fork and clone are mapped to the same kernel function do_fork
	*/
	if (child->tgid == child->pid) {
		NEVER(!pt_enabled());
		/* setup initial sequence numbers */
		topa = phys_to_virt(pt_topa_base());
		child_topa->sequence = topa->sequence + 1;
		child_topa->n_processed = topa->sequence;
		/* flush the parent's trace */
		pt_pause();
		pt_flush_trace(child_topa, true);
		pt_resume();
	}

	if (child->tgid == child->pid) {
		pt_log_fork(current, child);
		pt_log_process(child);
	} else {
		pt_log_thread(child);
	}
}

/* write images loadded by mmap() */
void pt_on_mmap(struct file *file, unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long pgoff)
{
	unsigned long actual_len;
	char *image_name, *path;

	if (!pt_enabled())
		return;
	if (!(prot & PROT_EXEC))
		return;
	if (IS_ERR_VALUE(addr))
		return;
	if (prot & PROT_WRITE)
		return;

	actual_len = file? file->f_inode->i_size
		- (pgoff << PAGE_SHIFT): len;
	actual_len = len > actual_len? actual_len: len;
	image_name = kmem_cache_alloc(pt_image_cache, GFP_ATOMIC);
	memset(image_name, 0, PATH_MAX);
	path = dentry_path_raw(file->f_path.dentry, image_name, PATH_MAX);
	if (!IS_ERR_OR_NULL(path)) {
		// pt_debug("image_name: %s\n", path);
		pt_log_image(current, addr, actual_len, path);
	}
	kmem_cache_free(pt_image_cache, image_name);
	pt_log_xpage(current, addr, actual_len, PAGE_ALIGN(len));
}

/* flush pt trace when meeting system calls */
void pt_on_syscall(struct pt_regs *regs)
{
	if (!pt_enabled())
		return;

	switch (regs->orig_ax) {
	case __NR_mmap:
	case __NR_mprotect:
		if (!(regs->dx & PROT_EXEC))
			return;
		break;
	case __NR_sendmsg:
	case __NR_sendmmsg:
	case __NR_sendto:
	case __NR_read:
	case __NR_write:
	case __NR_open:
	case __NR_close:
	case __NR_fork:
	case __NR_clone:
	case __NR_execve:
		break;
	default:
		return;
	}

	// get current system time
	// struct timespec ts;
    // getnstimeofday(&ts);

	// current->pid should be 0 since pt_on_syscall runs in the kernel mode
	// pt_log_audit(regs->orig_ax, ts.tv_sec, current->pid);

	pt_pause();
	pt_flush_trace(NULL, true);
	/* Todo: this is the place to track information flows in traces
	to mitigate the dependency explosion problem */
	pt_resume();
}

/*
* Init the PT kernel modeule
*
* PT is not designed as a loadable module because we need to hook system calls
* using PT for multi-thread tracing
*/
static int __init pt_init(void)
{
	int ret = -ENOMEM;

	if (!pt_avail())
		return -ENXIO;

	/* create a cache for buffers to enable dynamic (de)allocation */
	pt_buffer_cache = kmem_cache_create("pt_buffer_cache",
			sizeof(struct pt_buffer), 0, 0, NULL);
	if (!pt_buffer_cache)
		goto fail;
 
	/* create a cache for filled traces */
	pt_trace_cache = kmem_cache_create("pt_trace_cache",
			TOPA_BUFFER_SIZE + PAGE_SIZE, TOPA_BUFFER_SIZE,
			0, NULL);
	if (!pt_trace_cache)
		goto destroy_buffer_cache;

	/* create a cache for dentry filepaths */
	pt_image_cache = kmem_cache_create("pt_image_cache",
			PATH_MAX, PATH_MAX, 0, NULL);
	if (!pt_image_cache)
		goto destroy_trace_cache;

	/* setup the workqueue for async computation */
	ret = pt_wq_setup();
	if (ret < 0)
		goto destroy_image_cache;

	/* create pt_monitor file */
	ret = pt_monitor_setup();
	if (ret < 0)
		goto destroy_wq;
	
	memset(pt_monitor, 0, PATH_MAX);

	/* create pt_memory (shared memory) */
	ret = pt_memory_setup();
	if (ret < 0)
		goto destroy_pt_memory;

	return ret;

destroy_pt_memory:
	pt_memory_destroy();
destroy_wq:
	pt_wq_destroy();
destroy_image_cache:
	kmem_cache_destroy(pt_image_cache);
destroy_trace_cache:
	kmem_cache_destroy(pt_trace_cache);
destroy_buffer_cache:
	kmem_cache_destroy(pt_buffer_cache);
fail:
	return ret;
}

static void __exit pt_exit(void)
{
	NEVER(pt_enabled());

	pt_close_memory();
	pt_close_logfile();
	pt_memory_destroy();
	pt_monitor_destroy();
	pt_wq_destroy();
	kmem_cache_destroy(pt_image_cache);
	kmem_cache_destroy(pt_trace_cache);
	kmem_cache_destroy(pt_buffer_cache);
}

module_init(pt_init);
module_exit(pt_exit);
MODULE_LICENSE("GPL");
