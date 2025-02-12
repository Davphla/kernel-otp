DEBUG = true

CC = gcc

CFLAGS = -Wall -Wextra -Werror -MD

CFLAGS += -I./include/

ifeq ($(DEBUG), true)
	CFLAGS += -g3
endif

LDFLAGS =

SRC_DIR = ./src

SRC =	$(SRC_DIR)/main.c

BUILDDIR = ./obj

OBJ = $(patsubst $(SRC_DIR)/%.c,$(BUILDDIR)/%.o,$(SRC))

$(BUILDDIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) -o $@ -c $< $(CFLAGS)

EXEC = otp_utilitaire

all: $(EXEC)

otp_utilitaire: $(OBJ)
	@echo -e "\033[1;38;5;92mCompile \033[21m$@\033[0m"
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	@echo -e "\033[1;31mCleaning \033[21m$(EXEC)\033[1;24m OBJ\033[0m"
	rm -rf $(BUILDDIR)

fclean:	clean
	@echo -e "\033[1;31mcleaning \033[21m$(EXEC)\033[1;24m binary\033[0m"
	rm -f $(EXEC)

re:	fclean all

-include $(OBJ:.o=.d)

.PHONY:	clean fclean re
