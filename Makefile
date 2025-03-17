DIR = build
TARGET = $(DIR)/main
OBJS = $(DIR)/main.o $(DIR)/server.o

all: $(TARGET)

$(TARGET): $(OBJS)
	gcc -o $@ $(OBJS) -lm

$(DIR)/main.o: main.c server.h
	gcc -c main.c -o $@

$(DIR)/server.o: server.c server.h
	gcc -c server.c -o $@

$(DIR):
	mkdir -p $(DIR)

$(OBJS): | $(DIR)
