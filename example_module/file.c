#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

static struct hrtimer test_hrtimer;
static long period_ms = 100; // 100ms
static u32 loop = 0;

module_param(period_ms, long, 0600);
MODULE_PARM_DESC(period_ms, "tempo");

struct timespec64 ts;

static enum hrtimer_restart test_hrtimer_handler(struct hrtimer *timer)
{
	ktime_get_real_ts64(&ts);

    pr_info("%u:: [%lld / %ld]\n", ++loop, ts.tv_sec, ts.tv_nsec);
    hrtimer_forward_now(&test_hrtimer, ms_to_ktime(period_ms));
    return HRTIMER_RESTART;
}

static int __init test_hrtimer_init(void)
{
    hrtimer_init(&test_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    test_hrtimer.function = &test_hrtimer_handler;
    hrtimer_start(&test_hrtimer, ms_to_ktime(period_ms), HRTIMER_MODE_REL);
    pr_info("init test_hrtimer.\n");

    return 0;
}

static void __exit test_hrtimer_exit(void)
{
    hrtimer_cancel(&test_hrtimer );
    pr_info("exit test_hrtimer.\n");
    return;
}

module_init(test_hrtimer_init);
module_exit(test_hrtimer_exit);

MODULE_LICENSE("GPL");
