MAN = pcapdump.1 pcapip.1 pcappick.1 pcapuc.1

all: $(MAN)

clean:
	rm -f $(MAN)

%.1: %.docbook
	docbook2x-man --xinclude $<

.PHONY: all clean
