#ifndef OTP_H
#define OTP_H

#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ioctl.h>
#include <linux/crypto.h>
#include <linux/time.h>
#include <crypto/hash.h>

#include <linux/list.h>

#define DEVICE_LIST_NAME "otp_list"
#define DEVICE_TOTP_NAME "otp_totp"
#define CLASS_NAME "otp_class"

#define MAX_PASSWORDS 10
#define MAX_PASSWORD_LEN 32
#define TOTP_KEY_LEN 16
#define TOTP_INTERVAL 30

/* IOCTL commands */
#define IOCTL_ADD_PASSWORD _IOW('o', 1, char *)
#define IOCTL_SET_TOTP_KEY _IOW('o', 2, char *)
#define IOCTL_SET_TOTP_INTERVAL _IOW('o', 3, int)
#define IOCTL_VERIFY_PASSWORD _IOW('o', 4, char *)
#define IOCTL_VERIFY_TOTP _IOW('o', 5, char *)

/**
 * Linked list of password
 */
struct otp_list_data {
	char password[MAX_PASSWORD_LEN];
	SLIST_ENTRY(my_entry) entries;
};

inline struct otp_list_data *new_entry(const char *val)
{
	struct otp_list_data *e = kmalloc(sizeof(struct otp_list_data), GFP_KERNEL);
	if (!e) {
		printk(KERN_ERR "Malloc failed\n");
        return NULL;
	}
	strncpy(e->password, val, MAX_PASSWORD_LEN);
    e->password[MAX_PASSWORD_LEN - 1] = '\0';
	return e;
}

/**
 * struct otp_totp_data - Stores TOTP key and interval.
 * @key: Secret key used for TOTP generation.
 * @interval: Time interval for TOTP validity.
 */
struct otp_totp_data {
	char key[TOTP_KEY_LEN];
	int interval;
};

/* Function prototypes */
static int otp_open(struct inode *inodep, struct file *filep);
static int otp_release(struct inode *inodep, struct file *filep);
static ssize_t otp_list_read(struct file *filep, char *buffer, size_t len,
			     loff_t *offset);
static ssize_t otp_totp_read(struct file *filep, char *buffer, size_t len,
			     loff_t *offset);
static long otp_list_ioctl(struct file *filep, unsigned int cmd,
			   unsigned long arg);
static long otp_totp_ioctl(struct file *filep, unsigned int cmd,
			   unsigned long arg);

/* Helper functions */
static int verify_password(const char *input);
static int verify_totp(const char *input);
static int generate_totp(char *key, int interval, char *output, size_t len);

/* Module initialization and cleanup functions */
static int __init otp_init(void);
static void __exit otp_exit(void);

#endif /* OTP_H */
