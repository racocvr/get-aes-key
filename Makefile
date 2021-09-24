CROSS_COMPILE?=/root/armv7l-tizen/bin/armv7l-tizen-linux-gnueabi-

.PHONY: getaeskey

getaeskey:
	$(CROSS_COMPILE)gcc -DFILENAME=\"$(@)\" -Os -Wl,--section-start=.text=0x00000000 -Wl,--build-id=none -fPIC -nostdlib -nostartfiles -e main -std=c99 $(@).c -o $(@) 
	$(CROSS_COMPILE)objcopy -O binary -j .text -j .rodata $(@) $(@).bin