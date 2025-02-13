#include "otp_module.h"

/******************************************/
/*            Global variables            */
/******************************************/

static int otp_list_major_number;
static int otp_totp_major_number;
static struct class *otp_class = NULL;
static struct device *otp_list_device = NULL;
static struct device *otp_totp_device = NULL;

static struct otp_list_data otp_list;

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
/*           Module Parameters            */
/******************************************/

static int otp_validity_duration = 30; // Default 30 seconds
module_param(otp_validity_duration, int, 0444);
MODULE_PARM_DESC(otp_validity_duration,
		 "Validity duration of OTP code in seconds");

static char otp_key[TOTP_KEY_LEN + 1] = "default_key";
module_param_string(otp_key, otp_key, TOTP_KEY_LEN, 0644);
MODULE_PARM_DESC(otp_key, "OTP secret key");

static int num_passwords = 10; // Default 10 passwords
module_param(num_passwords, int, 0644);
MODULE_PARM_DESC(num_passwords, "Number of default passwords generated");

/******************************************/
/*    Generic file_operations function    */
/******************************************/

static int otp_open(struct inode *inodep, struct file *filep)
{
	pr_info("OTP Device Opened\n");
	return 0;
}

static int otp_release(struct inode *inodep, struct file *filep)
{
	pr_info("OTP Device Closed\n");
	return 0;
}

/******************************************/
/*    OTP-list file_operation functions   */
/******************************************/

static ssize_t otp_list_read(struct file *filep, char __user *buffer,
			     size_t len, loff_t *offset)
{
	char *temp_buffer;
	struct otp_list_node *node = otp_list.head;
	int copied = 0;
	ssize_t ret;

	if (!node) {
		pr_debug("OTP List: No password found\n");
		return simple_read_from_buffer(buffer, len, offset,
					       "No password found\n", 18);
	}
	temp_buffer =
		kmalloc((MAX_PASSWORD_LEN + 1) * num_passwords, GFP_KERNEL);
	if (!temp_buffer)
		return -ENOMEM;

	while (node && copied < num_passwords) {
		strncpy(temp_buffer + copied * (MAX_PASSWORD_LEN + 1),
			node->password, MAX_PASSWORD_LEN);
		temp_buffer[(copied + 1) * (MAX_PASSWORD_LEN + 1) - 1] = '\n';
		node = node->next;
		copied++;
	}

	ret = simple_read_from_buffer(buffer, len, offset, temp_buffer,
				      (MAX_PASSWORD_LEN + 1) * num_passwords);
	kfree(temp_buffer);
	pr_info("OTP List: successfully read\n");
	return ret;
}

static int verify_password(const char *input)
{
	struct otp_list_node *otp = otp_list.head;

	pr_debug("OTP List: Checking password\n");
	while (otp) {
		if (strncmp(input, otp->password, MAX_PASSWORD_LEN) == 0) {
			pr_debug("OTP List: Password verified\n");
			return 1;
		}
		otp = otp->next;
	}
	pr_debug("OTP List: Password verification failed\n");
	return 0;
}

static long otp_list_ioctl(struct file *filep, unsigned int cmd,
			   unsigned long arg)
{
	char buffer[MAX_PASSWORD_LEN];
	struct otp_list_node *new_node;

	pr_debug("OTP List: ioctl command received %u\n", cmd);
	switch (cmd) {
	case IOCTL_ADD_PASSWORD:
		if (copy_from_user(buffer, (char __user *)arg, sizeof(buffer)))
			return -EFAULT;
		new_node = slist_insert_head(&otp_list, buffer);
		if (!new_node)
			return -EFAULT;
		num_passwords++;
		pr_info("OTP List: Password added\n");
		break;

	case IOCTL_VERIFY_PASSWORD:
		if (copy_from_user(buffer, (char __user *)arg,
				   MAX_PASSWORD_LEN))
			return -EFAULT;

		if (verify_password(buffer)) {
			pr_info("OTP List: Password verified successfully\n");
			return 1;
		} else {
			pr_info("OTP List: Password verification failed\n");
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

static int generate_totp(char *key, int interval, char *output, size_t len)
{
	struct timespec64 ts;
	unsigned long long counter, timestamp;
	struct crypto_shash *tfm;
	struct shash_desc *shash;
	unsigned char hash[20];
	int otp;

	ktime_get_real_ts64(&ts);
	timestamp = ts.tv_sec;
	counter = timestamp / interval;

	pr_info("[TOTP] Generating OTP - Timestamp: %llu, Counter: %llu\n",
		timestamp, counter);

	tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("[TOTP] Failed to allocate crypto context\n");

		return -EINVAL;
	}

	shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm),
			GFP_KERNEL);
	if (!shash) {
		pr_err("[TOTP] Failed to allocate shash descriptor\n");
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	shash->tfm = tfm;
	crypto_shash_setkey(tfm, key, TOTP_KEY_LEN);
	crypto_shash_digest(shash, (u8 *)&counter, sizeof(counter), hash);

	otp = ((hash[hash[19] & 0xf] & 0x7f) << 24 |
	       (hash[(hash[19] & 0xf) + 1] & 0xff) << 16 |
	       (hash[(hash[19] & 0xf) + 2] & 0xff) << 8 |
	       (hash[(hash[19] & 0xf) + 3] & 0xff)) %
	      1000000;

	snprintf(output, len, "%06d\n", otp);
	pr_info("[TOTP] Generated OTP: %06d\n", otp);
	kfree(shash);
	crypto_free_shash(tfm);
	return 0;
}

static ssize_t otp_totp_read(struct file *filep, char *buffer, size_t len,
			     loff_t *offset)
{
	char otp[8];
	ssize_t ret;

	if (generate_totp(otp_key, otp_validity_duration, otp, sizeof(otp)) <
	    0) {
		pr_err("[TOTP] Failed to generate OTP\n");
		return -EFAULT;
	}

	ret = simple_read_from_buffer(buffer, len, offset, otp, 8);
	pr_info("[TOTP] OTP successfully read\n");
	return ret;
}

static int verify_totp(const char *input)
{
	char expected_totp[7];
	if (generate_totp(otp_key, otp_validity_duration, expected_totp,
			  sizeof(expected_totp)) < 0) {
		pr_err("[TOTP] Failed to generate expected OTP for verification\n");
		return 0;
	}
	pr_info("[TOTP] Verifying OTP: Input: %s, Expected: %s\n", input,
		expected_totp);
	if (strncmp(input, expected_totp, 6) == 0) {
		pr_info("[TOTP] OTP verification successful\n");
		return 1;
	}
	pr_warn("[TOTP] OTP verification failed\n");
	return 0;
}

static long otp_totp_ioctl(struct file *filep, unsigned int cmd,
			   unsigned long arg)
{
	char buffer_key[TOTP_KEY_LEN + 1];
	char buffer_totp[7];
	int *interval;

	switch (cmd) {
	case IOCTL_SET_TOTP_KEY:
		if (copy_from_user(buffer_key, (char __user *)arg,
				   sizeof(buffer_key)))
			return -EFAULT;

		strncpy(otp_key, buffer_key, TOTP_KEY_LEN);
		pr_info("OTP TOTP: Key set\n");
		break;

	case IOCTL_SET_TOTP_INTERVAL:
		interval = (int *)arg;
		otp_validity_duration = *interval;
		pr_info("OTP TOTP: Interval set to %d seconds\n",
			otp_validity_duration);
		break;

	case IOCTL_VERIFY_TOTP:
		if (copy_from_user(buffer_totp, (char __user *)arg, 7))
			return -EFAULT;

		if (verify_totp(buffer_totp)) {
			pr_info("OTP TOTP: TOTP verified successfully\n");
			return 1;
		} else {
			pr_info("OTP TOTP: TOTP verification failed\n");
			return 0;
		}

	default:
		return -EINVAL;
	}

	return 0;
}

static void generate_random_password(char *password, size_t length)
{
	static const char charset[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	int i;

	for (i = 0; i < length - 1; i++) {
		unsigned char rand_byte;
		get_random_bytes(&rand_byte, 1);
		password[i] = charset[rand_byte % (sizeof(charset) - 1)];
	}
	password[length - 1] = '\0';
}

static void generate_initial_passwords(void)
{
	int i;

	for (i = 0; i < num_passwords; i++) {
		struct otp_list_node *new_node =
			kmalloc(sizeof(struct otp_list_node), GFP_KERNEL);
		if (!new_node)
			return;
		generate_random_password(new_node->password, MAX_PASSWORD_LEN);
		new_node->next = otp_list.head;
		otp_list.head = new_node;
	}
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
static int __init otp_init(void)
{
	pr_debug("OTP Module: Initializing\n");
	otp_list.head = NULL;

	otp_list_major_number =
		register_chrdev(0, DEVICE_LIST_NAME, &otp_list_fops);
	if (otp_list_major_number < 0) {
		pr_err("OTP Module: Failed to register otp_list device\n");
		return otp_list_major_number;
	}

	otp_totp_major_number =
		register_chrdev(0, DEVICE_TOTP_NAME, &otp_totp_fops);
	if (otp_totp_major_number < 0) {
		pr_err("OTP Module: Failed to register otp_totp device\n");
		unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
		return otp_totp_major_number;
	}

	otp_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(otp_class)) {
		pr_err("OTP Module: Failed to create class\n");
		unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
		unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
		return PTR_ERR(otp_class);
	}

	otp_list_device = device_create(otp_class, NULL,
					MKDEV(otp_list_major_number, 0), NULL,
					DEVICE_LIST_NAME);
	otp_totp_device = device_create(otp_class, NULL,
					MKDEV(otp_totp_major_number, 1), NULL,
					DEVICE_TOTP_NAME);

	if (IS_ERR(otp_list_device) || IS_ERR(otp_totp_device)) {
		if (!IS_ERR(otp_list_device))
			device_destroy(otp_class,
				       MKDEV(otp_list_major_number, 0));
		if (!IS_ERR(otp_totp_device))
			device_destroy(otp_class,
				       MKDEV(otp_totp_major_number, 1));
		class_destroy(otp_class);
		unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
		unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
		return PTR_ERR(otp_list_device);
	}

	generate_initial_passwords();

	pr_info("OTP Module loaded\n");
	pr_info("OTP Module Validity Duration: %d seconds\n",
		otp_validity_duration);
	pr_info("OTP Module Number of Default Passwords: %d\n", num_passwords);
	return 0;
}

static void free_passwords(void)
{
	struct otp_list_node *node = otp_list.head;
	while (node) {
		struct otp_list_node *temp = node;
		node = node->next;
		kfree(temp);
	}
	otp_list.head = NULL;
}

/**
 * otp_exit - Cleans up and exits the OTP kernel module.
 *
 * This function removes the created devices, destroys the class, and unregisters
 * the character devices for both OTP list and TOTP functionality. It ensures proper
 * cleanup when the module is unloaded.
 */
static void __exit otp_exit(void)
{
	pr_debug("OTP Module: Exiting\n");
	free_passwords();
	device_destroy(otp_class, MKDEV(otp_list_major_number, 0));
	device_destroy(otp_class, MKDEV(otp_totp_major_number, 1));
	class_destroy(otp_class);
	unregister_chrdev(otp_list_major_number, DEVICE_LIST_NAME);
	unregister_chrdev(otp_totp_major_number, DEVICE_TOTP_NAME);
	pr_info("OTP Module unloaded\n");
}

module_init(otp_init);
module_exit(otp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arthur");
MODULE_DESCRIPTION("OTP Module");
MODULE_VERSION("0.3");
