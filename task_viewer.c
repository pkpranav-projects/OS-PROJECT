#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>

/*
 * Module Load Function
 */
static int __init task_viewer_init(void)
{
    struct task_struct *task;

    printk(KERN_INFO "===== Task Viewer Loaded =====\n");

    /*
     * Traverse every process in the kernel task list
     */
    for_each_process(task)
    {
        printk(KERN_INFO
               "PID: %d | Process: %s | State: %ld\n",
               task->pid,
               task->comm,
               task->__state);
    }

    return 0;
}

/*
 * Module Exit Function
 */
static void __exit task_viewer_exit(void)
{
    printk(KERN_INFO "===== Task Viewer Unloaded =====\n");
}

module_init(task_viewer_init);
module_exit(task_viewer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("P K PRANAV");
MODULE_DESCRIPTION("Linux Kernel Module to Display Running Processes");
MODULE_VERSION("1.0");