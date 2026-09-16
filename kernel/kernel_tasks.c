#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/cred.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelGuard Project");
MODULE_DESCRIPTION("Safe kernel task enumerator for cross-view comparison");
MODULE_VERSION("1.0");

#define PROC_NAME "kernel_tasks"

static int kernel_tasks_show(struct seq_file *m, void *v)
{
    struct task_struct *task;
    
    /* Use RCU read lock for safe tasklist traversal */
    rcu_read_lock();
    
    for_each_process(task) {
        pid_t pid = task->pid;
        pid_t ppid = 0;
        char state_char;
        kuid_t uid = KUIDT_INIT(0);
        
        /* Safely get parent PID */
        if (task->real_parent) {
            ppid = task->real_parent->pid;
        }

        /* Get process state character (S, R, Z, etc.) */
        state_char = task_state_to_char(task);
        
        /* Safely get UID using RCU */
        if (rcu_access_pointer(task->cred)) {
            uid = task->cred->uid;
        }
        
        /* Format: pid=1 ppid=0 name=systemd state=S uid=0 */
        seq_printf(m, "pid=%d ppid=%d name=%s state=%c uid=%u\n",
                   pid, ppid, task->comm, state_char, __kuid_val(uid));
    }
    
    rcu_read_unlock();
    return 0;
}

static int kernel_tasks_open(struct inode *inode, struct file *file)
{
    return single_open(file, kernel_tasks_show, NULL);
}

/* In modern kernels (>= 5.6), proc_ops is used instead of file_operations */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops kernel_tasks_fops = {
    .proc_open    = kernel_tasks_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations kernel_tasks_fops = {
    .owner   = THIS_MODULE,
    .open    = kernel_tasks_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
#endif

static int __init kernelguard_init(void)
{
    struct proc_dir_entry *entry;
    
    pr_info("KernelGuard: loading task enumerator module\n");
    
    entry = proc_create(PROC_NAME, 0444, NULL, &kernel_tasks_fops);
    if (!entry) {
        pr_err("KernelGuard: failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    
    pr_info("KernelGuard: successfully created /proc/%s\n", PROC_NAME);
    return 0;
}

static void __exit kernelguard_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("KernelGuard: task enumerator module unloaded\n");
}

module_init(kernelguard_init);
module_exit(kernelguard_exit);
