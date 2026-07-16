#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>


/*
    Module Load Function
*/
static int __init task_viewer_init(void)
{
    struct task_struct *task;


    printk(KERN_INFO "===== Task Viewer Loaded =====\n");


    /*
        Traverse every process
        in the kernel task list
    */
    for_each_process(task)
    {

        printk(KERN_INFO
               "PID: %d | Name: %s | Parent PID: %d | State: %u\n",
               
               task->pid,
               
               task->comm,
               
               task->parent->pid,
               
               task->__state
        );

    }


    printk(KERN_INFO "===== Process Listing Finished =====\n");


    return 0;
}



/*
    Module Remove Function
*/
static void __exit task_viewer_exit(void)
{

    printk(KERN_INFO "===== Task Viewer Removed =====\n");

}



/*
    Register functions
*/

module_init(task_viewer_init);

module_exit(task_viewer_exit);



/*
    Module Information
*/

MODULE_LICENSE("GPL");

MODULE_AUTHOR("Pranav");

MODULE_DESCRIPTION("Linux Kernel Process Viewer");

MODULE_VERSION("1.0");
