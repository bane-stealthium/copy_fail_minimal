CC      = gcc
CFLAGS  = -Os -Wall -Wextra -static
TARGET  = copy_fail_exp

$(TARGET): copy_fail_exp.c payload.h
	$(CC) -nostdlib $(CFLAGS) -o $@ copy_fail_exp.c
	strip --strip-all $@

payload.h: payload.elf
	xxd -i $< | sed 's/unsigned char/static const unsigned char/;s/unsigned int/static const unsigned int/;s/payload_elf/payload/g' > $@

payload.elf: payload.c
	$(CC) -nostdlib -static -Os -Wl,--gc-sections -Wl,--build-id=none -Wl,-z,noseparate-code -o $@ $<
	strip --strip-all $@

run: $(TARGET)
	@./$(TARGET)

fmt:
	clang-format -i copy_fail_exp.c payload.c

clean:
	rm -f $(TARGET) payload.elf payload.h

drop_caches:
	echo 3 | sudo tee /proc/sys/vm/drop_caches

.PHONY: run clean drop_caches fmt
