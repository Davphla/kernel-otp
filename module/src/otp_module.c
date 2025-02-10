#include "otp_module.h"

static int otp_list_major_number;
static int otp_totp_major_number;
static struct class* otp_class = NULL;
static struct device* otp_list_device = NULL;
static struct device* otp_totp_device = NULL;
static struct otp_list_data otp_list;
static struct otp_totp_data otp_totp;

static struct file_operations otp_list_fops = {
    .open = otp_open,
    .release = otp_release,
    .read = otp_list_read,
    .unlocked_ioctl = otp_list_ioctl,
};

static struct file_operations otp_totp_fops = {
    .open = otp_open,
    .release = otp_release,
    .read = otp_totp_read,
    .unlocked_ioctl = otp_totp_ioctl,
};

/******************************************/
/*    Generic file_operations function    */
/******************************************/

static int otp_open(struct inode* inodep, struct file* filep) {
    printk(KERN_INFO "OTP Device Opened\n");
    return 0;
}

static int otp_release(struct inode* inodep, struct file* filep) {
    printk(KERN_INFO "OTP Device Closed\n");
    return 0;
}

/******************************************/
/*    OTP-list file_operation functions   */  
/******************************************/

static ssize_t otp_list_read(struct file* filep, char* buffer, size_t len, loff_t* offset) {
    char otp[MAX_PASSWORD_LEN + 1];

    if (otp_list.current_password_index < otp_list.password_count) {
        snprintf(otp, sizeof(otp), "%s\n", otp_list.passwords[otp_list.current_password_index]);
        otp_list.current_password_index++;
    } else {
        snprintf(otp, sizeof(otp), "No more passwords\n");
        otp_list.current_password_index = 0;
    }

    if (copy_to_user(buffer, otp, strlen(otp) + 1))
        return -EFAULT;

    return strlen(otp);
}

static int verify_password(const char* input) {
    int i;

    for (i = 0; i < otp_list.password_count; i++) {
        if (strncmp(input, otp_list.passwords[i], MAX_PASSWORD_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

static long otp_list_ioctl(struct file* filep, unsigned int cmd, unsigned long arg) {
    char buffer[MAX_PASSWORD_LEN];

    switch (cmd) {
        case IOCTL_ADD_PASSWORD:
            if (otp_list.password_count >= MAX_PASSWORDS)
                return -ENOMEM;

            if (copy_from_user(buffer, (char __user*)arg, sizeof(buffer)))
                return -EFAULT;

            strncpy(otp_list.passwords[otp_list.password_count], buffer, MAX_PASSWORD_LEN);
            otp_list.password_count++;
            printk(KERN_INFO "OTP List: Password added\n");
            break;

        case IOCTL_VERIFY_PASSWORD:
            if (copy_from_user(buffer, (char __user*)arg, MAX_PASSWORD_LEN))
                return -EFAULT;

            if (verify_password(buffer)) {
                printk(KERN_INFO "OTP List: Password verified successfully\n");
                return 1;
            } else {
                printk(KERN_INFO "OTP List: Password verification failed\n");
                return 0;
            }

        default:
            return -EINVAL;
    }

    return 0;
}


/******************************************/
/*    OTP-TOTP file_operation functions   */  
/******************************************/

static int generate_totp(char* key, int interval, char* output, size_t len) {
    struct timespec64 ts;
    unsigned long long counter, timestamp;
    struct crypto_shash* tfm;
    struct shash_desc* shash;
    unsigned char hash[20];
    int otp;

    ktime_get_real_ts64(&ts);
    timestamp = ts.tv_sec;
    counter = timestamp / interval;

    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm))
        return -EINVAL;

    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    shash->tfm = tfm;
    crypto_shash_setkey(tfm, key, TOTP_KEY_LEN);
    crypto_shash_digest(shash, (u8*)&counter, sizeof(counter), hash);

    otp = ((hash[hash[19] & 0xf] & 0x7f) << 24 |
           (hash[(hash[19] & 0xf) + 1] & 0xff) << 16 |
           (hash[(hash[19] & 0xf) + 2] & 0xff) << 8 |
           (hash[(hash[19] & 0xf) + 3] & 0xff)) %
          1000000;

    snprintf(output, len, "%06d\n", otp);
    kfree(shash);
    crypto_free_shash(tfm);
    return 0;
}

static ssize_t otp_totp_read(struct file* filep, char* buffer, size_t len, loff_t* offset) {
    char otp[8];

    if (generate_totp(otp_totp.key, otp_totp.interval, otp, sizeof(otp)) < 0)
        return -EFAULT;

    if (copy_to_user(buffer, otp, strlen(otp) + 1))
        return -EFAULT;

    return strlen(otp);
}

static int verify_totp(const char* input) {
    char expected_totp[7];
    if (generate_totp(otp_totp.key, otp_totp.interval, expected_totp, sizeof(expected_totp)) < 0) {
        return 0;
    }
    if (strncmp(input, expected_totp, 6) == 0)
        return 1;
    return 0;
}

static long otp_totp_ioctl(struct file* filep, unsigned int cmd, unsigned long arg) {
    char buffer[TOTP_KEY_LEN];
    int *interval;

    switch (cmd) {
        case IOCTL_SET_TOTP_KEY:
            if (copy_from_user(buffer, (char __user*)arg, sizeof(buffer)))
                return -EFAULT;

            strncpy(otp_totp.key, buffer, TOTP_KEY_LEN);
            printk(KERN_INFO "OTP TOTP: Key set\n");
            break;

        case IOCTL_SET_TOTP_INTERVAL:
            interval = (int*)arg;
            otp_totp.interval = *interval;
            printk(KERN_INFO "OTP TOTP: Interval set to %d seconds\n", otp_totp.interval);
            break;

        case IOCTL_VERIFY_TOTP:
            if (copy_from_user(buffer, (char __user*)arg, 7))
                return -EFAULT;

            if (verify_totp(buffer)) {
                printk(KERN_INFO "OTP TOTP: TOTP verified successfully\n");
                return 1;
            } else {
                printk(KERN_INFO "OTP TOTP: TOTP verification failed\n");
                return 0;
            }

        default:
            return -EINVAL;
    }

    return 0;
}

/**
 * otp_init - Initializes the OTP kernel module.
 *
 * This function initializes the OTP module by setting up character devices
 * for password-based OTP and TOTP. It registers character devices, creates a
 * device class, and initializes the device structures.
 *
 * @return: 0 on success, negative error code on failure.
 */
static int __init otp_init(void) {
    otp_list.password_count = 0;
    otp_list.current_password_index = 0;

    otp_totp.interval = TOTP_INTERVAL;

    otp_list_major_number = register_chrdev(0, DEVICE_LIST_NAME, &otp_list_fops);
    if (otp_list_major_number < 0) {
        pr_err("Failed to register otp_list device\n");
        return otp_list_major_number;
    }

    otp_totp_major_number = register_chrdev(0, DEVICE_TOTP_NAME, &otp_totp_fops);
    if (otp_totp_major_number < 0) {
        pr_err("Failed to register otp_totp device\n");
        unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
        return otp_totp_major_number;
    }

    otp_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(otp_class)) {
        unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
        unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
        return PTR_ERR(otp_class);
    }

    otp_list_device = device_create(otp_class, NULL, MKDEV(otp_list_major_number, 0), NULL, DEVICE_LIST_NAME);
    otp_totp_device = device_create(otp_class, NULL, MKDEV(otp_totp_major_number, 1), NULL, DEVICE_TOTP_NAME);

    if (IS_ERR(otp_list_device) || IS_ERR(otp_totp_device)) {
        if (!IS_ERR(otp_list_device))
            device_destroy(otp_class, MKDEV(otp_list_major_number, 0));
        if (!IS_ERR(otp_totp_device))
            device_destroy(otp_class, MKDEV(otp_totp_major_number, 1));
        class_destroy(otp_class);
        unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
        unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
        return PTR_ERR(otp_list_device);
    }

    printk(KERN_INFO "OTP Module loaded\n");
    return 0;
}

/**
 * otp_exit - Cleans up and exits the OTP kernel module.
 *
 * This function removes the created devices, destroys the class, and unregisters
 * the character devices for both OTP list and TOTP functionality. It ensures proper
 * cleanup when the module is unloaded.
 */
static void __exit otp_exit(void) {
    device_destroy(otp_class, MKDEV(otp_list_major_number, 0));
    device_destroy(otp_class, MKDEV(otp_totp_major_number, 1));
    class_destroy(otp_class);
    unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
    unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
    printk(KERN_INFO "OTP Module unloaded\n");
}

module_init(otp_init);
module_exit(otp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arthur");
MODULE_DESCRIPTION("OTP Module");
MODULE_VERSION("0.3");
