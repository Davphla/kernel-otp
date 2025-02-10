#ifndef OTP_H
#define OTP_H

#include <linux/ioctl.h>
#include <linux/module.h>

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
 * struct otp_list_data - Stores OTP passwords.
 * @passwords: Array of passwords.
 * @password_count: Number of stored passwords.
 * @current_password_index: Current read index.
 */
struct otp_list_data {
	char passwords[MAX_PASSWORDS][MAX_PASSWORD_LEN];
	int password_count;
	int current_password_index;
};

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
int verify_password(const char *input);
int verify_totp(const char *input);
int generate_totp(char *key, int interval, char *output, size_t len);

/* Module initialization and cleanup functions */
static int __init otp_init(void);
static void __exit otp_exit(void);

#endif /* OTP_H */
