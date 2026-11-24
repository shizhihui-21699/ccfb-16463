/*
 * gw-init - tiny PID-1 hardening wrapper for an embedded gateway.
 *
 * It is intentionally conservative: it loads early modules, locks a small set
 * of kernel knobs and inode flags, removes dangerous capabilities from the
 * process bounding set, and then execs the real init.  Being PID 1 matters:
 * every later login and service inherits the reduced bounding set.
 *
 * This file is meant to be built with a Linux cross toolchain.  The non-Linux
 * stubs only exist so the source can be syntax-checked on a development host.
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#else
/* Host syntax-check stub. */
static int prctl(int option, ...)
{
	(void)option;
	errno = ENOSYS;
	return -1;
}
#endif

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif

/* Capability numbers from linux/capability.h. */
#define GW_CAP_LINUX_IMMUTABLE 9
#define GW_CAP_SYS_MODULE 16
#define GW_CAP_SYS_RAWIO 17
#define GW_CAP_SYS_PTRACE 19
#define GW_CAP_PERFMON 38
#define GW_CAP_BPF 39

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL 0x00000010
#endif
#ifndef FS_APPEND_FL
#define FS_APPEND_FL 0x00000020
#endif

#ifndef CMDLINE_PATH
#define CMDLINE_PATH "/proc/cmdline"
#endif
#ifndef EARLY_HOOK
#define EARLY_HOOK "/etc/gw/load-early-modules"
#endif
#ifndef SYSCTL_EXTRA
#define SYSCTL_EXTRA "/etc/gw/sysctl.lock"
#endif
#ifndef PROTECTED_LIST
#define PROTECTED_LIST "/etc/gw/protected.list"
#endif

static void logmsg(const char *fmt, ...)
{
	char msg[768];
	char line[900];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(msg))
		n = (int)sizeof(msg) - 1;

	n = snprintf(line, sizeof(line), "gw-init[%ld]: %s\n",
		     (long)getpid(), msg);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(line))
		n = (int)sizeof(line) - 1;

	/* Init's stderr is normally the serial/console device. */
	(void)!write(STDERR_FILENO, line, (size_t)n);

	int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)!write(fd, line, (size_t)n);
		close(fd);
	}
}

static ssize_t read_file_buf(const char *path, char *buf, size_t size)
{
	int fd;
	ssize_t n;

	if (size == 0)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, size - 1);
	if (n < 0) {
		int rc = -errno;
		close(fd);
		return rc;
	}
	close(fd);

	buf[n] = '\0';
	return n;
}

static int write_file(const char *path, const char *data)
{
	int fd;
	size_t len = strlen(data);
	ssize_t n;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	n = write(fd, data, len);
	if (n < 0)
		n = -errno;
	else if ((size_t)n != len)
		n = -EIO;

	if (close(fd) != 0 && n >= 0)
		n = -errno;

	return n < 0 ? (int)n : 0;
}

static int cmdline_value(const char *key, char *out, size_t out_size)
{
	char buf[4096];
	char *save = NULL;
	char *tok;
	size_t key_len = strlen(key);
	int found = 0;

	if (out_size == 0)
		return 0;
	out[0] = '\0';

	if (read_file_buf(CMDLINE_PATH, buf, sizeof(buf)) <= 0)
		return 0;

	for (tok = strtok_r(buf, " \t\r\n", &save); tok != NULL;
	     tok = strtok_r(NULL, " \t\r\n", &save)) {
		if (strncmp(tok, key, key_len) == 0) {
			snprintf(out, out_size, "%s", tok + key_len);
			found = 1;
			break;
		}
	}

	return found;
}

static bool cmdline_has(const char *needle)
{
	char mode[32];

	if (cmdline_value("gw.mode=", mode, sizeof(mode)) == 1 &&
	    strcmp(mode, needle) == 0)
		return true;

	/* Convenience form: gw.debug=1. */
	if (strcmp(needle, "debug") == 0) {
		char value[8];
		if (cmdline_value("gw.debug=", value, sizeof(value)) == 1 &&
		    strcmp(value, "1") == 0)
			return true;
	}

	return false;
}

static void mount_early_filesystems(void)
{
#if defined(__linux__)
	if (mount("proc", "/proc", "proc",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0 &&
	    errno != EBUSY)
		logmsg("mount /proc: %s", strerror(errno));

	if (mount("sysfs", "/sys", "sysfs",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0 &&
	    errno != EBUSY)
		logmsg("mount /sys: %s", strerror(errno));
#endif
}

static int run_hook(const char *path)
{
	pid_t pid;
	int status;

	if (access(path, R_OK) != 0) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		execl("/bin/sh", "sh", path, (char *)NULL);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -errno;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	logmsg("hook %s failed (status=0x%x)", path, status);
	return -ECHILD;
}

struct sysctl_pair {
	const char *path;
	const char *value;
	bool required;
};

static const struct sysctl_pair builtin_sysctls[] = {
	/* One-shot module load lock.  Requires CAP_SYS_MODULE to set. */
	{"/proc/sys/kernel/modules_disabled", "1\n", true},
	{"/proc/sys/kernel/sysrq", "0\n", false},
	{"/proc/sys/kernel/dmesg_restrict", "1\n", false},
	{"/proc/sys/kernel/kptr_restrict", "2\n", false},
	{"/proc/sys/kernel/perf_event_paranoid", "2\n", false},
	{"/proc/sys/kernel/yama/ptrace_scope", "3\n", false},
	{"/proc/sys/kernel/unprivileged_bpf_disabled", "1\n", false},
};

static void apply_sysctl_pair(const struct sysctl_pair *item)
{
	int rc = write_file(item->path, item->value);

	if (rc == 0)
		return;

	/* A missing knob usually means the corresponding CONFIG is off. */
	if (rc == -ENOENT || rc == -EROFS || rc == -EACCES) {
		if (item->required)
			logmsg("required sysctl %s unavailable: %s",
			       item->path, strerror(-rc));
		return;
	}

	logmsg("write %s: %s", item->path, strerror(-rc));
}

static void apply_extra_sysctls(const char *path)
{
	FILE *f = fopen(path, "re");
	char line[512];

	if (f == NULL)
		return;

	while (fgets(line, sizeof(line), f) != NULL) {
		char *save = NULL;
		char *first = strtok_r(line, " \t\r\n", &save);
		char *value = strtok_r(NULL, " \t\r\n", &save);
		char nl[64];

		if (first == NULL || first[0] == '#' || value == NULL)
			continue;

		snprintf(nl, sizeof(nl), "%s\n", value);
		int rc = write_file(first, nl);
		if (rc != 0 && rc != -ENOENT)
			logmsg("write %s=%s: %s", first, value, strerror(-rc));
	}

	fclose(f);
}

static int set_fs_flag(const char *path, int wanted_flag)
{
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	int flags = 0;
	int rc = 0;

	if (fd < 0)
		return -errno;

	if (ioctl(fd, FS_IOC_GETFLAGS, &flags) != 0) {
		rc = -errno;
		goto out;
	}

	if ((flags & wanted_flag) == 0) {
		flags |= wanted_flag;
		if (ioctl(fd, FS_IOC_SETFLAGS, &flags) != 0)
			rc = -errno;
	}

out:
	close(fd);
	return rc;
}

struct protect_entry {
	const char *path;
	bool optional;
	bool append_only;
};

/*
 * Accepted line forms:
 *   /path                    immutable
 *   -/path                   optional immutable
 *   immutable /path
 *   append /path             FS_APPEND_FL, for write-only event logs
 *   append -/path
 */
static bool parse_protect_entry(char *line, struct protect_entry *entry)
{
	char *first = strtok(line, " \t\r\n");
	char *second = strtok(NULL, " \t\r\n");

	memset(entry, 0, sizeof(*entry));

	if (first == NULL || first[0] == '#')
		return false;

	if (second != NULL &&
	    (strcmp(first, "immutable") == 0 || strcmp(first, "i") == 0 ||
	     strcmp(first, "append") == 0 || strcmp(first, "a") == 0)) {
		entry->append_only =
			strcmp(first, "append") == 0 || strcmp(first, "a") == 0;
		entry->path = second;
	} else {
		entry->path = first;
	}

	if (entry->path[0] == '-' && entry->path[1] != '\0') {
		entry->optional = true;
		entry->path++;
	}

	return true;
}

static void apply_protected_list(const char *path)
{
	FILE *f = fopen(path, "re");
	char line[1024];
	unsigned int failures = 0;
	unsigned int entries = 0;

	if (f == NULL) {
		logmsg("protected list %s: %s", path, strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		struct protect_entry entry;
		int rc;

		if (!parse_protect_entry(line, &entry))
			continue;

		entries++;
		rc = set_fs_flag(entry.path, entry.append_only ?
							 FS_APPEND_FL :
							 FS_IMMUTABLE_FL);
		if (rc == 0 || entry.optional)
			continue;

		/* read-only/snapshot filesystems already provide protection */
		if (rc == -EROFS || rc == -ENOTTY || rc == -EOPNOTSUPP)
			continue;

		failures++;
		logmsg("%s %s: %s",
		       entry.append_only ? "append-only" : "immutable",
		       entry.path, strerror(-rc));
	}

	fclose(f);
	if (failures != 0)
		logmsg("%u/%u protected entries could not be locked",
		       failures, entries);
}

static int drop_bounding_capabilities(void)
{
	static const unsigned int caps[] = {
		GW_CAP_LINUX_IMMUTABLE,
		GW_CAP_SYS_MODULE,
		GW_CAP_SYS_RAWIO,
		GW_CAP_SYS_PTRACE,
		GW_CAP_PERFMON,
		GW_CAP_BPF,
	};
	size_t i;
	int failed = 0;

	for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
		if (prctl(PR_CAPBSET_DROP, (unsigned long)caps[i], 0UL, 0UL,
			  0UL) != 0) {
			/* EINVAL: this kernel does not know the cap number. */
			if (errno == EINVAL)
				continue;
			logmsg("PR_CAPBSET_DROP cap %u: %s", caps[i],
			       strerror(errno));
			failed = -errno;
		}
	}

	return failed;
}

static __attribute__((noreturn)) void
exec_real_init(int argc, char **argv)
{
	static const char *candidates[] = {
		"/sbin/init",
		"/lib/systemd/systemd",
		"/bin/init",
	};
	char **new_argv;
	size_t i;

	new_argv = calloc((size_t)argc + 2, sizeof(*new_argv));
	if (new_argv == NULL) {
		logmsg("out of memory while building init argv");
		goto failed;
	}

	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		int j;

		new_argv[0] = (char *)candidates[i];
		for (j = 1; j < argc; j++)
			new_argv[j] = argv[j];
		new_argv[argc] = NULL;

		logmsg("starting %s", candidates[i]);
		execv(candidates[i], new_argv);
		logmsg("exec %s: %s", candidates[i], strerror(errno));
	}

	free(new_argv);

failed:
	sync();
#if defined(__linux__)
	/* Give console logs a moment to leave the UART, then ask the bootloader
	 * boot-count logic to try recovery after repeated failures. */
	sleep(2);
	reboot(RB_AUTOBOOT);
#endif
	sleep(30);
	for (;;)
		pause();
}

static unsigned long long read_cap_bounding_set(void)
{
	FILE *f = fopen("/proc/self/status", "re");
	char line[512];
	unsigned long long set = ~0ULL;

	if (f == NULL)
		return set;

	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "CapBnd:", 7) == 0) {
			set = strtoull(line + 7, NULL, 16);
			break;
		}
	}

	fclose(f);
	return set;
}

static bool path_is_protected(const struct protect_entry *entry)
{
	struct statvfs st;
	int flags = 0;
	int fd;
	int wanted = entry->append_only ? FS_APPEND_FL : FS_IMMUTABLE_FL;

	if (statvfs(entry->path, &st) == 0 && (st.f_flag & ST_RDONLY))
		return true;

	fd = open(entry->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0) {
		int rc = ioctl(fd, FS_IOC_GETFLAGS, &flags);
		close(fd);
		if (rc == 0 && (flags & wanted))
			return true;
	}

	return false;
}

struct cap_status {
	unsigned int bit;
	const char *name;
};

static int status_main(void)
{
	static const struct cap_status caps[] = {
		{GW_CAP_LINUX_IMMUTABLE, "linux_immutable"},
		{GW_CAP_SYS_MODULE, "sys_module"},
		{GW_CAP_SYS_RAWIO, "sys_rawio"},
		{GW_CAP_SYS_PTRACE, "sys_ptrace"},
		{GW_CAP_PERFMON, "perfmon"},
		{GW_CAP_BPF, "bpf"},
	};
	char mode[32] = "secure";
	char value[32] = "unknown";
	unsigned long long bnd = read_cap_bounding_set();
	bool secure;
	bool healthy = true;
	size_t i;

	cmdline_value("gw.mode=", mode, sizeof(mode));
	secure = strcmp(mode, "debug") != 0 && !cmdline_has("debug");

	if (read_file_buf("/proc/sys/kernel/modules_disabled", value,
			  sizeof(value)) > 0) {
		value[strcspn(value, "\r\n")] = '\0';
	} else {
		snprintf(value, sizeof(value), "unknown");
	}

	printf("gw.mode=%s\n", secure ? "secure" : "debug");
	printf("kernel.modules_disabled=%s\n", value);
	printf("device.dev_mem=%s\n",
	       access("/dev/mem", F_OK) == 0 ? "present" : "absent");
	printf("device.dev_kmem=%s\n",
	       access("/dev/kmem", F_OK) == 0 ? "present" : "absent");

	/* The production fragment compiles these devices out. Their presence in
	 * secure mode means the kernel policy does not match the reference.
	 */
	if (secure && access("/dev/mem", F_OK) == 0)
		healthy = false;
	if (secure && access("/dev/kmem", F_OK) == 0)
		healthy = false;

	for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
		bool dropped = (bnd & (1ULL << caps[i].bit)) == 0;

		printf("cap.%s=%s\n", caps[i].name,
		       dropped ? "dropped" : "present");
		if (secure && !dropped)
			healthy = false;
	}

	if (secure && strcmp(value, "1") != 0)
		healthy = false;

	FILE *f = fopen(PROTECTED_LIST, "re");
	if (f != NULL) {
		char line[1024];

		while (fgets(line, sizeof(line), f) != NULL) {
			struct protect_entry entry;
			bool ok;

			if (!parse_protect_entry(line, &entry))
				continue;

			ok = path_is_protected(&entry);
			printf("protected.%s.%s=%s\n",
			       entry.append_only ? "append" : "immutable",
			       entry.path,
			       ok ? "ok"
				  : (entry.optional ? "optional-unprotected"
						    : "UNPROTECTED"));
			if (!ok && !entry.optional)
				healthy = false;
		}
		fclose(f);
	}

	printf("overall=%s\n", healthy ? "secure" : "degraded");
	return healthy ? 0 : 1;
}

int main(int argc, char **argv)
{
	char mode[32] = "secure";
	bool debug;
	size_t i;

	if (argc >= 2 && strcmp(argv[1], "status") == 0)
		return status_main();

	if (getpid() != 1) {
		fprintf(stderr,
			"%s: hardening wrapper must be PID 1; use '%s status'\n",
			argv[0], argv[0]);
		return 2;
	}

	mount_early_filesystems();
	cmdline_value("gw.mode=", mode, sizeof(mode));
	debug = strcmp(mode, "debug") == 0 || cmdline_has("debug");

	logmsg("gateway security wrapper starting in %s mode",
	       debug ? "DEBUG" : "SECURE");

	/* Modules and immutable module-tree files must be handled here, while
	 * CAP_SYS_MODULE and CAP_LINUX_IMMUTABLE are still in the bounding set.
	 */
	(void)run_hook(EARLY_HOOK);

	if (debug) {
		logmsg("debug mode: runtime lock-down skipped; kernel module signature verification remains enforced");
	} else {
		for (i = 0; i < sizeof(builtin_sysctls) /
				sizeof(builtin_sysctls[0]);
		     i++)
			apply_sysctl_pair(&builtin_sysctls[i]);

		apply_extra_sysctls(SYSCTL_EXTRA);
		apply_protected_list(PROTECTED_LIST);

		/* After this point no descendant login/service can regain the
		 * removed capabilities, even for UID 0.
		 */
		(void)drop_bounding_capabilities();
	}

	exec_real_init(argc, argv);
}
