CC ?= clang
CC_BPF ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -std=c2x -Wall -Wextra -Werror -ggdb
CFLAGS_BPF ?= -Wall -Wextra -Werror -ggdb

sockmap-redir-matrix: sockmap_redir_matrix.o
	$(CC) $(CFLAGS) -o $@ $^ -lbpf

sockmap_redir_matrix.o: redir_bpf.skel.h

redir_bpf.skel.h: redir.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

%.bpf.o: %.bpf.c
	$(CC_BPF) $(CFLAGS_BPF) -O2 -target bpf -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
