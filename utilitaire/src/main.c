#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE_LIST "/dev/otp_list"
#define DEVICE_TOTP "/dev/otp_totp"

#define IOCTL_ADD_PASSWORD _IOW('o', 1, char*)
#define IOCTL_SET_TOTP_KEY _IOW('o', 2, char*)
#define IOCTL_SET_TOTP_INTERVAL _IOW('o', 3, int)
#define IOCTL_VERIFY_PASSWORD _IOW('o', 4, char*)
#define IOCTL_VERIFY_TOTP _IOW('o', 5, char*)

static void print_usage(const char* prog_name) {
    printf("Usage: %s [option] [arguments]\n", prog_name);
    printf("Options:\n");
    printf("  --add-password <password>         Add a password to the list\n");
    printf("  --set-totp-key <key>              Set the TOTP key\n");
    printf("  --set-totp-interval <interval>    Set the TOTP interval (in seconds)\n");
    printf("  --verify-password <password>      Verify a password from the list\n");
    printf("  --verify-totp <code>              Verify a TOTP code\n");
    printf("  --help                            Show this message\n");
}

int main(int argc, char **argv) {
    int fd_list;
    int fd_totp;

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    fd_list = open(DEVICE_LIST, O_RDWR);
    fd_totp = open(DEVICE_TOTP, O_RDWR);
    if (fd_list < 0 || fd_totp < 0) {
        perror("Failed to open devices");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "--add-password") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(fd_list);
            close(fd_totp);
            return EXIT_FAILURE;
        }
        if (ioctl(fd_list, IOCTL_ADD_PASSWORD, argv[2]) == 0) {
            printf("Password added successfully.\n");
        } else {
            perror("Failed to add password");
        }
    } else if (strcmp(argv[1], "--set-totp-key") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(fd_list);
            close(fd_totp);
            return EXIT_FAILURE;
        }
        if (ioctl(fd_totp, IOCTL_SET_TOTP_KEY, argv[2]) == 0) {
            printf("TOTP key set successfully.\n");
        } else {
            perror("Failed to set TOTP key");
        }
    } else if (strcmp(argv[1], "--set-totp-interval") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(fd_list);
            close(fd_totp);
            return EXIT_FAILURE;
        }
        int interval = atoi(argv[2]);
        if (ioctl(fd_totp, IOCTL_SET_TOTP_INTERVAL, &interval) == 0) {
            printf("TOTP interval set successfully.\n");
        } else {
            perror("Failed to set TOTP interval");
        }
    } else if (strcmp(argv[1], "--verify-password") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(fd_list);
            close(fd_totp);
            return EXIT_FAILURE;
        }
        int result = ioctl(fd_list, IOCTL_VERIFY_PASSWORD, argv[2]);
        if (result == 1) {
            printf("Password verified successfully.\n");
        } else if (result == 0) {
            printf("Password verification failed.\n");
        } else {
            perror("Error during password verification");
        }
    } else if (strcmp(argv[1], "--verify-totp") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            close(fd_list);
            close(fd_totp);
            return EXIT_FAILURE;
        }
        int result = ioctl(fd_totp, IOCTL_VERIFY_TOTP, argv[2]);
        if (result == 1) {
            printf("TOTP verified successfully.\n");
        } else if (result == 0) {
            printf("TOTP verification failed.\n");
        } else {
            perror("Error during TOTP verification");
        }
    } else {
        print_usage(argv[0]);
    }
    close(fd_list);
    close(fd_totp);
    return EXIT_SUCCESS;
}
