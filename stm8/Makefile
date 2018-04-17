NAME_DISASSEMBLE=stm8_disassemble
NAME_ANALYSE=stm8_analyse
R2_PLUGIN_PATH=$(shell r2 -hh|grep USER_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_asm)
LDFLAGS=-shared $(shell pkg-config --libs r_asm)
OBJS_DISASSEMBLE=stm8_disassemble.o stm8_optable.o
OBJS_ANALYSE=stm8_analyse.o stm8_optable.o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB_DISASSEMBLE=$(NAME_DISASSEMBLE).$(SO_EXT)
LIB_ANALYSE=$(NAME_ANALYSE).$(SO_EXT)

all: $(LIB_DISASSEMBLE) $(LIB_ANALYSE)

clean:
	rm -f $(LIB_DISASSEMBLE) $(OBJS_DISASSEMBLE)
	rm -f $(LIB_ANALYSE) $(OBJS_ANALYSE)

$(LIB_DISASSEMBLE): $(OBJS_DISASSEMBLE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_DISASSEMBLE) -o $(LIB_DISASSEMBLE)

$(LIB_ANALYSE): $(OBJS_ANALYSE)
		$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_ANALYSE) -o $(LIB_ANALYSE)

install:
	cp -f $(NAME_DISASSEMBLE).$(SO_EXT) $(R2_PLUGIN_PATH)
	cp -f $(NAME_ANALYSE).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(NAME_DISASSEMBLE).$(SO_EXT)
	rm -f $(R2_PLUGIN_PATH)/$(NAME_ANALYSE).$(SO_EXT)
