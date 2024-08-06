#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include <linux/bpf.h>
#include <linux/vm_sockets.h>

#include <bpf/bpf.h>
#include <errno.h>
#include <error.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "redir_bpf.skel.h"

enum {
	MAP_IDX_TARGET,
	MAP_IDX_TCP_IN,
	MAP_IDX_TCP_OUT,
};

typedef uint32_t u32;
typedef uint64_t u64;

#define u32(v) ((u32){(v)})
#define u64(v) ((u64){(v)})

#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int socket_autobind_inet(int sock_fd)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(0);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return bind(sock_fd, (void *)&sin, sizeof(sin));
}

static int socket_autobind_inet6(int sock_fd)
{
	struct sockaddr_in6 sin6;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(0);
	sin6.sin6_addr = in6addr_loopback;

	return bind(sock_fd, (void *)&sin6, sizeof(sin6));
}

static int socket_autobind_vsock(int sock_fd)
{
	struct sockaddr_vm svm;

	memset(&svm, 0, sizeof(svm));
	svm.svm_family = AF_VSOCK;
	svm.svm_port = VMADDR_PORT_ANY;
	svm.svm_cid = VMADDR_CID_LOCAL;

	return bind(sock_fd, (void *)&svm, sizeof(svm));
}

static int socket_autobind(int family, int sock_fd)
{
	switch (family) {
	case AF_INET:
		return socket_autobind_inet(sock_fd);
	case AF_INET6:
		return socket_autobind_inet6(sock_fd);
	case AF_VSOCK:
		return socket_autobind_vsock(sock_fd);
	}

	errno = EPFNOSUPPORT;
	return -1;
}

static int socket_pair_dgram(int family, int fds[2])
{
	struct sockaddr_storage ss;
	struct sockaddr *addr = (void *)&ss;
	socklen_t addr_len = sizeof(ss);
	int s1;
	int s2;
	int err;

	s1 = socket(family, SOCK_DGRAM, 0);
	error(s1 == -1, errno, "socket(DGRAM)");

	err = socket_autobind(family, s1);
	error(err, errno, "bind");

	err = getsockname(s1, addr, &addr_len);
	error(err, errno, "getsockname");

	s2 = socket(family, SOCK_DGRAM, 0);
	error(s2 == -1, errno, "socket(DGRAM)");

	err = connect(s2, addr, addr_len);
	error(err, errno, "connect");

	err = getsockname(s2, addr, &addr_len);
	error(err, errno, "getsockname");

	err = connect(s1, addr, addr_len);
	error(err, errno, "connect");

	fds[0] = s1;
	fds[1] = s2;
	return 0;
}


static int socket_pair_stream(int family, int type, int fds[2])
{
	struct sockaddr_storage ss;
	struct sockaddr *addr = (void *)&ss;
	socklen_t addr_len = sizeof(ss);
	int ln;
	int s1;
	int s2;
	int err;

	ln = socket(family, type, 0);
	error(ln == -1, errno, "socket(family=%d, type=%d)", family, type);

	err = socket_autobind(family, ln);
	error(err, errno, "bind");

	err = listen(ln, 1);
	error(err, errno, "listen");

	err = getsockname(ln, addr, &addr_len);
	error(err, errno, "getsockname");

	s1 = socket(family, type, 0);
	error(s1 == -1, errno, "socket(family=%d, type=%d)", family, type);

	err = connect(s1, addr, addr_len);
	error(err, errno, "connect");

	s2 = accept(ln, NULL, NULL);
	error(s2 == -1, errno, "accept");

	err = close(ln);
	error(err, errno, "close");

	fds[0] = s1;
	fds[1] = s2;
	return 0;
}

static int socket_pair(int family, int type, int fds[2])
{
	switch (family) {
	case AF_INET:
		[[fallthrough]];
	case AF_INET6:
		switch (type) {
		case SOCK_DGRAM:
			return socket_pair_dgram(family, fds);
		case SOCK_STREAM:
			return socket_pair_stream(family, type, fds);
		}
		goto fail;
	case AF_UNIX:
		return socketpair(AF_UNIX, type, 0, fds);
	case AF_VSOCK:
		switch (type) {
		case SOCK_DGRAM:
			return socket_pair_dgram(family, fds);
		case SOCK_STREAM:
			[[fallthrough]];
		case SOCK_SEQPACKET:
			return socket_pair_stream(family, type, fds);
		}
		goto fail;
	}
fail:
	errno = ESOCKTNOSUPPORT;
	return -1;
}

__attribute__((unused))
static void dump_map(int map)
{
	union bpf_attr attr;
	struct bpf_map_info info;
	int err;
	char *cmd;

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = map;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uint64_t) &info;

	err = bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	error(err, errno, "bpf(OBJ_GET_INFO_BY_FD)");

	err = asprintf(&cmd, "bpftool map dump id %u", info.id);
	error(err < 0, errno, "asprintf");

	err = system(cmd);
	error(err, errno, "system");

	free(cmd);
}

static int poll_read(int fd, unsigned int timeout_msec)
{
	struct timeval timeout = {
		.tv_sec = 0,
		.tv_usec = timeout_msec * 1000,
	};
	fd_set rfds;
	int r;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	r = select(fd + 1, &rfds, NULL, NULL, &timeout);
	if (r == 0)
		errno = ETIME;

	return r == 1 ? 0 : -1;
}

static int recv_timeout(int fd, void *buf, size_t len, int flags,
			unsigned int timeout_msec)
{
	if (poll_read(fd, timeout_msec))
		return -1;

	return recv(fd, buf, len, flags);
}

static bool test_send_redir_recv(int sd_send, int sd_in,
				 int sd_out, int sd_recv,
				 int map_in, int map_out)
{
	char send_buf = 'x';
	char recv_buf = '\0';
	ssize_t n;
	int err;
	bool ok = false;

	err = bpf_map_update_elem(map_in, &u32(0), &u64(sd_in), BPF_NOEXIST);
	error(err, errno, "map_update(map_in)");

	err = bpf_map_update_elem(map_out, &u32(0), &u64(sd_out), BPF_NOEXIST);
	error(err, errno, "map_update(map_out)");

	/* dump_map(map_in); */
	/* dump_map(map_out); */

	n = send(sd_send, &send_buf, 1, 0);
	error(n != 1 && errno != EACCES, errno, "send");

	/* sk_msg redirect combo not supported */
	if (errno == EACCES)
		goto out;

	n = recv_timeout(sd_recv, &recv_buf, 1, 0, 10 /* msec */);
	error(n != 1 && errno != ETIME, errno, "recv");
	error(n == 1 && recv_buf != send_buf, 0, "recv: payload check");

	ok = (n == 1);
out:
	errno = 0;

	err = bpf_map_delete_elem(map_in, &u32(0));
	error(err, errno, "map_delete(map_in)");

	err = bpf_map_delete_elem(map_out, &u32(0));
	error(err, errno, "map_delete(map_out)");

	return ok;
}

enum {
	INET_STREAM = 0,
	INET6_STREAM,
	INET_DGRAM,
	INET6_DGRAM,
	UNIX_STREAM,
	// UNIX_SEQPACKET,	   /* not supported */
	UNIX_DGRAM,
	VSOCK_STREAM,
	VSOCK_SEQPACKET,
	// VSOCK_DGRAM,		   /* not supported */
	MAX_SOCKS
};

static const char *socket_kind_to_str(int sock_fd)
{
	socklen_t opt_len;
	int domain;
	int type;
	int err;

	opt_len = sizeof(domain);
	err = getsockopt(sock_fd, SOL_SOCKET, SO_DOMAIN, &domain, &opt_len);
	error(err, errno, "%s: getsockopt(SO_DOMAIN)", __func__);

	opt_len = sizeof(type);
	err = getsockopt(sock_fd, SOL_SOCKET, SO_TYPE, &type, &opt_len);
	error(err, errno, "getsockopt(SO_TYPE)");

	switch (domain) {
	case AF_INET:
		switch (type) {
		case SOCK_STREAM:
			return "tcp4";
		case SOCK_DGRAM:
			return "udp4";
		}
		break;
	case AF_INET6:
		switch (type) {
		case SOCK_STREAM:
			return "tcp6";
		case SOCK_DGRAM:
			return "udp6";
		}
		break;
	case AF_UNIX:
		switch (type) {
		case SOCK_STREAM:
			return "u_str";
		case SOCK_DGRAM:
			return "u_dgr";
		case SOCK_SEQPACKET:
			return "u_seq";
		}
		break;
	case AF_VSOCK:
		switch (type) {
		case SOCK_STREAM:
			return "v_str";
		case SOCK_DGRAM:
			return "v_dgr";
		case SOCK_SEQPACKET:
			return "v_seq";
		}
		break;
	}

	return "???";
}

static void test_redir(const char *name,
		       int idx_send, int idx_recv,
		       int map_in, int map_out)
{
	int in[MAX_SOCKS][2];
	int out[MAX_SOCKS][2];
	int err;
	bool ok;

	const struct {
		int family;
		int type;
	} socket_kind[] = {
		[INET_STREAM]	= { AF_INET, SOCK_STREAM },
		[INET6_STREAM]	= { AF_INET6, SOCK_STREAM },
		[INET_DGRAM]	= { AF_INET, SOCK_DGRAM },
		[INET6_DGRAM]	= { AF_INET6, SOCK_DGRAM },
		[UNIX_STREAM]	= { AF_UNIX, SOCK_STREAM },
		[UNIX_DGRAM]	= { AF_UNIX, SOCK_DGRAM },
		[VSOCK_STREAM]	= { AF_VSOCK, SOCK_STREAM },
		[VSOCK_SEQPACKET] = { AF_VSOCK, SOCK_SEQPACKET },
	};

	memset(in, -1, sizeof(in));
	memset(out, -1, sizeof(out));

	for (int i = 0; i < ARRAY_SIZE(socket_kind); i++) {
		int family = socket_kind[i].family;
		int type = socket_kind[i].type;

		if (family == AF_UNSPEC)
			continue;

		socket_pair(family, type, in[i]);
		socket_pair(family, type, out[i]);
	}

	printf("%s:\n", name);
	for (int i = 0; i < ARRAY_SIZE(socket_kind); i++) {
		int fd_send = in[i][idx_send];
		int fd_in = in[i][0];
		int fd_out = out[i][0];
		int fd_recv = out[i][idx_recv];

		if (socket_kind[i].family == AF_UNSPEC)
			continue;

		printf("  %5s → %5s: ",
		       socket_kind_to_str(fd_in),
		       socket_kind_to_str(fd_out));

		ok = test_send_redir_recv(fd_send, fd_in, fd_out, fd_recv, map_in, map_out);

		printf("%s\n",
		       ok ? "OK" : "FAIL");
	}

	printf("%s (cross-proto):\n", name);
	for (int i = 0; i < ARRAY_SIZE(socket_kind); i++) {
		int fd_send = in[i][idx_send];
		int fd_in = in[i][0];

		if (socket_kind[i].family == AF_UNSPEC)
			continue;

		for (int j = 0; j < ARRAY_SIZE(socket_kind); j++) {
			int fd_out = out[j][0];
			int fd_recv = out[j][idx_recv];

			if (i == j)
				continue;
			if (socket_kind[j].family == AF_UNSPEC)
				continue;

			printf("  %5s → %5s: ",
			       socket_kind_to_str(fd_in),
			       socket_kind_to_str(fd_out));

			ok = test_send_redir_recv(fd_send, fd_in, fd_out, fd_recv, map_in, map_out);

			printf("%s\n",
			       ok ? "OK" : "FAIL");
		}
	}

	for (int i = 0; i < ARRAY_SIZE(out); i++) {
		if (out[i][0] == -1 && out[i][1] == -1)
			continue;

		err = close(out[i][0]);
		error(err, errno, "close(out[%d][0])", i);

		err = close(out[i][1]);
		error(err, errno, "close(out[%d][1])", i);
	}

	for (int i = 0; i < ARRAY_SIZE(in); i++) {
		if (in[i][0] == -1 && in[i][1] == -1)
			continue;

		err = close(in[i][0]);
		error(err, errno, "close(in[%d][0])", i);

		err = close(in[i][1]);
		error(err, errno, "close(in[%d][1])", i);
	}
}

enum {
	SEND_INNER = 0,
	SEND_OUTER,
};

enum {
	RECV_INNER = 0,
	RECV_OUTER,
};

enum prog_kind {
	PROG_SK_MSG_EGRESS,
	PROG_SK_MSG_INGRESS,
	PROG_SK_SKB_EGRESS,
	PROG_SK_SKB_INGRESS,
};

struct bpf_program *get_prog(struct redir_bpf *skel, enum prog_kind kind)
{
	switch (kind) {
	case PROG_SK_MSG_EGRESS:
		return skel->progs.sk_msg_redir_egress;
	case PROG_SK_MSG_INGRESS:
		return skel->progs.sk_msg_redir_ingress;
	case PROG_SK_SKB_EGRESS:
		return skel->progs.sk_skb_redir_egress;
	case PROG_SK_SKB_INGRESS:
		return skel->progs.sk_skb_redir_ingress;
	}

	return NULL;
}

int main(void)
{
	struct redir_bpf *skel;
	int map_in;
	int map_out;
	int prog;
	int err;


	const struct {
		const char *name;
		int idx_send;
		int idx_recv;
		enum prog_kind prog_kind;
		enum bpf_attach_type attach_type;
	} tests[] = {
		{ "sk_msg-to-egress", SEND_INNER, RECV_OUTER,
		  PROG_SK_MSG_EGRESS, BPF_SK_MSG_VERDICT },
		{ "sk_msg-to-ingress", SEND_INNER, RECV_INNER,
		  PROG_SK_MSG_INGRESS, BPF_SK_MSG_VERDICT },
		{ "sk_skb-to-egress", SEND_OUTER, RECV_OUTER,
		  PROG_SK_SKB_EGRESS, BPF_SK_SKB_VERDICT },
		{ "sk_skb-to-ingress", SEND_OUTER, RECV_INNER,
		  PROG_SK_SKB_INGRESS, BPF_SK_SKB_VERDICT },
	};

	for (auto t = tests; t < tests + ARRAY_SIZE(tests); t++) {
		skel = redir_bpf__open_and_load();
		error(!skel, errno, "skeleton open_and_load");
		errno = 0;

		map_in = bpf_map__fd(skel->maps.input);
		map_out = bpf_map__fd(skel->maps.output);
		prog = bpf_program__fd(get_prog(skel, t->prog_kind));

		err = bpf_prog_attach(prog, map_in, t->attach_type, 0);
		error(err, errno, "prog_attach");

		test_redir(t->name, t->idx_send, t->idx_recv, map_in, map_out);

		err = bpf_prog_detach2(prog, map_in, t->attach_type);
		error(err, errno, "prog_detach");

		redir_bpf__destroy(skel);
	}

	return 0;
}
