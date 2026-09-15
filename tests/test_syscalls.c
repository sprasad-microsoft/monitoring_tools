/*
 * test_syscalls.c - Comprehensive syscall coverage test for iosnoop and ioslower
 *
 * Tests all syscalls covered by iosnoop and ioslower:
 *   File operations   : open, openat, read, write, close
 *   File metadata     : stat, lstat, fstat, chmod, fchmod, chown, fchown,
 *                       truncate, ftruncate
 *   Directory ops     : mkdir, mkdirat, rmdir
 *   Deletion          : unlink, unlinkat
 *   Renaming          : rename, renameat, renameat2
 *   Links             : link, linkat, symlink, symlinkat, readlink, readlinkat
 *   Vector I/O        : pread64, pwrite64, readv, writev, preadv, pwritev
 *   Memory mapping    : mmap, munmap
 *   Async I/O (libaio): io_setup, io_submit, io_getevents, io_cancel, io_destroy
 *   io_uring          : io_uring_setup, io_uring_register, io_uring_enter
 *   Mount             : mount, umount2  (requires CAP_SYS_ADMIN)
 *
 * Build:
 *   gcc -O0 -o test_syscalls test_syscalls.c
 *
 * Run:
 *   ./test_syscalls
 *   ./test_syscalls --mount   (add --mount to also test mount/umount2 as root)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <linux/aio_abi.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Test harness
 * ---------------------------------------------------------------------- */

static int g_passed;
static int g_failed;
static int g_skipped;
static char g_tmpdir[256];

#define PASS(name)   do { printf("  ✓ %-40s\n", name); g_passed++;  } while (0)
#define FAIL(name, fmt, ...) \
	do { printf("  ✗ %-40s  " fmt "\n", name, ##__VA_ARGS__); g_failed++; } while (0)
#define SKIP(name, reason) \
	do { printf("  ⊘ %-40s  [%s]\n", name, reason); g_skipped++; } while (0)

static void section(const char *title)
{
	printf("\n%s\n", title);
	printf("------------------------------------------------------------------\n");
}

/* Build a path inside the tmp dir */
static void tmppath(char *out, size_t len, const char *name)
{
	snprintf(out, len, "%s/%s", g_tmpdir, name);
}

/* Create a file with 'size' bytes of known content */
static int make_file(const char *path, size_t size)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	char buf[256];
	size_t written = 0;
	size_t chunk;

	if (fd < 0)
		return -1;

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = 'A' + (i % 26);

	while (written < size) {
		chunk = size - written;
		if (chunk > sizeof(buf))
			chunk = sizeof(buf);
		if (write(fd, buf, chunk) != (ssize_t)chunk) {
			close(fd);
			return -1;
		}
		written += chunk;
	}
	close(fd);
	return 0;
}

/* =========================================================================
 * 1. File operations
 * ====================================================================== */

static void test_file_operations(void)
{
	section("File operations");

	char path[256];
	int fd;

	/* open + close */
	tmppath(path, sizeof(path), "open_creat.txt");
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		FAIL("open(O_CREAT)", "errno=%d", errno);
	} else {
		close(fd);
		PASS("open(O_CREAT)");
	}

	/* open O_RDONLY */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("open(O_RDONLY)", "errno=%d", errno);
	} else {
		close(fd);
		PASS("open(O_RDONLY)");
	}

	/* open O_APPEND */
	fd = open(path, O_APPEND | O_WRONLY);
	if (fd < 0) {
		FAIL("open(O_APPEND)", "errno=%d", errno);
	} else {
		close(fd);
		PASS("open(O_APPEND)");
	}

	/* read + write */
	tmppath(path, sizeof(path), "rw_test.txt");
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		FAIL("write()", "open failed errno=%d", errno);
	} else {
		const char *msg = "hello world";
		ssize_t nw = write(fd, msg, strlen(msg));
		lseek(fd, 0, SEEK_SET);
		char buf[32] = {0};
		ssize_t nr = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (nw == (ssize_t)strlen(msg) && nr == nw && strcmp(buf, msg) == 0) {
			PASS("write()");
			PASS("read()");
		} else {
			FAIL("write()/read()", "nw=%zd nr=%zd", nw, nr);
		}
	}

	/* close already tested above */
	PASS("close()");

	/* openat */
	int dirfd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		SKIP("openat()", "could not open tmpdir");
	} else {
		fd = syscall(__NR_openat, dirfd, "openat_file.txt",
			     O_CREAT | O_WRONLY, 0644);
		if (fd < 0) {
			FAIL("openat()", "errno=%d", errno);
		} else {
			close(fd);
			PASS("openat()");
		}
		close(dirfd);
	}
}

/* =========================================================================
 * 2. File metadata
 * ====================================================================== */

static void test_file_metadata(void)
{
	section("File metadata");

	char path[256];
	tmppath(path, sizeof(path), "meta_test.txt");
	if (make_file(path, 64) < 0) {
		FAIL("setup", "make_file failed");
		return;
	}

	struct stat st;

	/* stat */
	if (stat(path, &st) < 0)
		FAIL("stat()", "errno=%d", errno);
	else
		PASS("stat()");

	/* lstat */
	if (lstat(path, &st) < 0)
		FAIL("lstat()", "errno=%d", errno);
	else
		PASS("lstat()");

	/* fstat */
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("fstat()", "open failed errno=%d", errno);
	} else {
		if (fstat(fd, &st) < 0)
			FAIL("fstat()", "errno=%d", errno);
		else
			PASS("fstat()");
		close(fd);
	}

	/* chmod */
	if (chmod(path, 0755) < 0)
		FAIL("chmod()", "errno=%d", errno);
	else
		PASS("chmod()");

	/* fchmod */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FAIL("fchmod()", "open failed errno=%d", errno);
	} else {
		if (fchmod(fd, 0600) < 0)
			FAIL("fchmod()", "errno=%d", errno);
		else
			PASS("fchmod()");
		close(fd);
	}

	/* chown — set to current uid/gid (always succeeds) */
	uid_t uid = getuid();
	gid_t gid = getgid();
	if (chown(path, uid, gid) < 0)
		FAIL("chown()", "errno=%d", errno);
	else
		PASS("chown()");

	/* fchown */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FAIL("fchown()", "open failed errno=%d", errno);
	} else {
		if (fchown(fd, uid, gid) < 0)
			FAIL("fchown()", "errno=%d", errno);
		else
			PASS("fchown()");
		close(fd);
	}

	/* truncate */
	if (truncate(path, 10) < 0) {
		FAIL("truncate()", "errno=%d", errno);
	} else {
		stat(path, &st);
		if (st.st_size == 10)
			PASS("truncate()");
		else
			FAIL("truncate()", "size=%lld expected 10", (long long)st.st_size);
	}

	/* ftruncate */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FAIL("ftruncate()", "open failed errno=%d", errno);
	} else {
		if (ftruncate(fd, 5) < 0) {
			FAIL("ftruncate()", "errno=%d", errno);
		} else {
			fstat(fd, &st);
			if (st.st_size == 5)
				PASS("ftruncate()");
			else
				FAIL("ftruncate()", "size=%lld expected 5", (long long)st.st_size);
		}
		close(fd);
	}
}

/* =========================================================================
 * 3. Directory operations
 * ====================================================================== */

static void test_directory_operations(void)
{
	section("Directory operations");

	char path[256];

	/* mkdir */
	tmppath(path, sizeof(path), "mkdir_test");
	if (mkdir(path, 0755) < 0)
		FAIL("mkdir()", "errno=%d", errno);
	else
		PASS("mkdir()");

	/* mkdirat */
	int dirfd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		SKIP("mkdirat()", "could not open tmpdir");
	} else {
		if (syscall(__NR_mkdirat, dirfd, "mkdirat_test", 0755) < 0)
			FAIL("mkdirat()", "errno=%d", errno);
		else
			PASS("mkdirat()");
		close(dirfd);
	}

	/* rmdir */
	tmppath(path, sizeof(path), "rmdir_test");
	mkdir(path, 0755);
	if (rmdir(path) < 0)
		FAIL("rmdir()", "errno=%d", errno);
	else
		PASS("rmdir()");
}

/* =========================================================================
 * 4. File deletion
 * ====================================================================== */

static void test_file_deletion(void)
{
	section("File deletion");

	char path[256];

	/* unlink */
	tmppath(path, sizeof(path), "unlink_test.txt");
	make_file(path, 16);
	if (unlink(path) < 0)
		FAIL("unlink()", "errno=%d", errno);
	else
		PASS("unlink()");

	/* unlinkat */
	tmppath(path, sizeof(path), "unlinkat_test.txt");
	make_file(path, 16);
	int dirfd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		SKIP("unlinkat()", "could not open tmpdir");
	} else {
		if (syscall(__NR_unlinkat, dirfd, "unlinkat_test.txt", 0) < 0)
			FAIL("unlinkat()", "errno=%d", errno);
		else
			PASS("unlinkat()");
		close(dirfd);
	}
}

/* =========================================================================
 * 5. File renaming
 * ====================================================================== */

static void test_file_renaming(void)
{
	section("File renaming");

	char src[256], dst[256];

	/* rename */
	tmppath(src, sizeof(src), "rename_src.txt");
	tmppath(dst, sizeof(dst), "rename_dst.txt");
	make_file(src, 8);
	if (rename(src, dst) < 0)
		FAIL("rename()", "errno=%d", errno);
	else
		PASS("rename()");

	/* renameat */
	tmppath(src, sizeof(src), "renameat_src.txt");
	tmppath(dst, sizeof(dst), "renameat_dst.txt");
	make_file(src, 8);
	int dirfd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		SKIP("renameat()", "could not open tmpdir");
		SKIP("renameat2()", "could not open tmpdir");
	} else {
		if (syscall(__NR_renameat, dirfd, "renameat_src.txt",
			    dirfd, "renameat_dst.txt") < 0)
			FAIL("renameat()", "errno=%d", errno);
		else
			PASS("renameat()");

		/* renameat2 — RENAME_NOREPLACE = 1 */
		tmppath(src, sizeof(src), "renameat2_src.txt");
		make_file(src, 8);
		if (syscall(__NR_renameat2, dirfd, "renameat2_src.txt",
			    dirfd, "renameat2_dst.txt", 1 /* RENAME_NOREPLACE */) < 0)
			FAIL("renameat2()", "errno=%d", errno);
		else
			PASS("renameat2()");

		close(dirfd);
	}
}

/* =========================================================================
 * 6. Link operations
 * ====================================================================== */

static void test_link_operations(void)
{
	section("Link operations");

	char src[256], dst[256];
	char buf[512];

	/* link */
	tmppath(src, sizeof(src), "link_src.txt");
	tmppath(dst, sizeof(dst), "link_dst.txt");
	make_file(src, 8);
	if (link(src, dst) < 0)
		FAIL("link()", "errno=%d", errno);
	else
		PASS("link()");

	/* linkat */
	int dirfd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		SKIP("linkat()", "could not open tmpdir");
	} else {
		tmppath(dst, sizeof(dst), "linkat_dst.txt");
		if (syscall(__NR_linkat, dirfd, "link_src.txt",
			    dirfd, "linkat_dst.txt", 0) < 0)
			FAIL("linkat()", "errno=%d", errno);
		else
			PASS("linkat()");
	}

	/* symlink */
	tmppath(dst, sizeof(dst), "symlink_test.txt");
	if (symlink(src, dst) < 0)
		FAIL("symlink()", "errno=%d", errno);
	else
		PASS("symlink()");

	/* symlinkat */
	if (dirfd < 0) {
		SKIP("symlinkat()", "could not open tmpdir");
	} else {
		if (syscall(__NR_symlinkat, src, dirfd, "symlinkat_test.txt") < 0)
			FAIL("symlinkat()", "errno=%d", errno);
		else
			PASS("symlinkat()");
	}

	/* readlink */
	tmppath(dst, sizeof(dst), "symlink_test.txt");
	ssize_t n = readlink(dst, buf, sizeof(buf) - 1);
	if (n < 0)
		FAIL("readlink()", "errno=%d", errno);
	else
		PASS("readlink()");

	/* readlinkat */
	if (dirfd < 0) {
		SKIP("readlinkat()", "could not open tmpdir");
	} else {
		n = syscall(__NR_readlinkat, dirfd, "symlink_test.txt",
			    buf, sizeof(buf) - 1);
		if (n < 0)
			FAIL("readlinkat()", "errno=%d", errno);
		else
			PASS("readlinkat()");
		close(dirfd);
	}
}

/* =========================================================================
 * 7. Vector I/O
 * ====================================================================== */

static void test_vector_io(void)
{
	section("Vector I/O");

	char path[256];
	tmppath(path, sizeof(path), "vecio_test.bin");
	if (make_file(path, 1024) < 0) {
		FAIL("setup", "make_file failed");
		return;
	}

	/* pread64 */
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("pread64()", "open failed errno=%d", errno);
	} else {
		char buf[16];
		ssize_t n = pread(fd, buf, sizeof(buf), 100);
		close(fd);
		if (n == (ssize_t)sizeof(buf))
			PASS("pread64()");
		else
			FAIL("pread64()", "n=%zd errno=%d", n, errno);
	}

	/* pwrite64 */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FAIL("pwrite64()", "open failed errno=%d", errno);
	} else {
		ssize_t n = pwrite(fd, "TESTDATA", 8, 200);
		close(fd);
		if (n == 8)
			PASS("pwrite64()");
		else
			FAIL("pwrite64()", "n=%zd errno=%d", n, errno);
	}

	/* readv */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("readv()", "open failed errno=%d", errno);
	} else {
		char b1[8], b2[8];
		struct iovec iov[2] = {
			{ .iov_base = b1, .iov_len = sizeof(b1) },
			{ .iov_base = b2, .iov_len = sizeof(b2) },
		};
		ssize_t n = readv(fd, iov, 2);
		close(fd);
		if (n == 16)
			PASS("readv()");
		else
			FAIL("readv()", "n=%zd errno=%d", n, errno);
	}

	/* writev */
	char wpath[256];
	tmppath(wpath, sizeof(wpath), "writev_test.bin");
	fd = open(wpath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		FAIL("writev()", "open failed errno=%d", errno);
	} else {
		struct iovec iov[2] = {
			{ .iov_base = "hello ", .iov_len = 6 },
			{ .iov_base = "world",  .iov_len = 5 },
		};
		ssize_t n = writev(fd, iov, 2);
		close(fd);
		if (n == 11)
			PASS("writev()");
		else
			FAIL("writev()", "n=%zd errno=%d", n, errno);
	}

	/* preadv */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("preadv()", "open failed errno=%d", errno);
	} else {
		char b1[8], b2[8];
		struct iovec iov[2] = {
			{ .iov_base = b1, .iov_len = sizeof(b1) },
			{ .iov_base = b2, .iov_len = sizeof(b2) },
		};
		ssize_t n = preadv(fd, iov, 2, 100);
		close(fd);
		if (n == 16)
			PASS("preadv()");
		else
			FAIL("preadv()", "n=%zd errno=%d", n, errno);
	}

	/* pwritev */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		FAIL("pwritev()", "open failed errno=%d", errno);
	} else {
		struct iovec iov[2] = {
			{ .iov_base = "HELLO ", .iov_len = 6 },
			{ .iov_base = "WORLD",  .iov_len = 5 },
		};
		ssize_t n = pwritev(fd, iov, 2, 300);
		close(fd);
		if (n == 11)
			PASS("pwritev()");
		else
			FAIL("pwritev()", "n=%zd errno=%d", n, errno);
	}
}

/* =========================================================================
 * 8. Additional VFS operations
 * ====================================================================== */

static void test_additional_vfs_operations(void)
{
	section("Additional VFS operations");

	char path[256];
	int fd;

	/* vfs_create (open with O_CREAT on a new path) */
	tmppath(path, sizeof(path), "create_test.bin");
	fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0644);
	if (fd < 0) {
		FAIL("create (O_CREAT|O_EXCL)", "errno=%d", errno);
	} else {
		PASS("create (O_CREAT|O_EXCL)");
		close(fd);
	}

	/* vfs_fallocate */
	tmppath(path, sizeof(path), "fallocate_test.bin");
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		FAIL("fallocate()", "open failed errno=%d", errno);
	} else {
		long rc = syscall(__NR_fallocate, fd, 0, 0, 4096);

		if (rc < 0 && (errno == EOPNOTSUPP || errno == ENOSYS))
			SKIP("fallocate()", "filesystem/kernel does not support fallocate");
		else if (rc < 0)
			FAIL("fallocate()", "errno=%d (%s)", errno, strerror(errno));
		else
			PASS("fallocate()");
		close(fd);
	}

	/* iterate_dir/getdents64 */
	fd = open(g_tmpdir, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		FAIL("getdents64()", "open failed errno=%d", errno);
	} else {
		char buf[4096];
		long rc = syscall(__NR_getdents64, fd, buf, sizeof(buf));

		if (rc < 0)
			FAIL("getdents64()", "errno=%d (%s)", errno, strerror(errno));
		else
			PASS("getdents64()");
		close(fd);
	}

	/* vfs_lock_file via POSIX record locking */
	tmppath(path, sizeof(path), "lock_test.bin");
	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		FAIL("fcntl(F_SETLK)", "open failed errno=%d", errno);
	} else {
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 0,
		};

		if (fcntl(fd, F_SETLK, &lock) < 0)
			FAIL("fcntl(F_SETLK)", "errno=%d (%s)", errno, strerror(errno));
		else
			PASS("fcntl(F_SETLK)");
		close(fd);
	}
}

/* =========================================================================
 * 9. Memory mapping
 * ====================================================================== */

static void test_memory_mapping(void)
{
	section("Memory mapping");

	char path[256];
	tmppath(path, sizeof(path), "mmap_test.bin");
	if (make_file(path, 4096) < 0) {
		FAIL("setup", "make_file failed");
		return;
	}

	/* mmap read */
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		FAIL("mmap(PROT_READ)", "open failed errno=%d", errno);
	} else {
		void *addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (addr == MAP_FAILED) {
			FAIL("mmap(PROT_READ)", "errno=%d", errno);
		} else {
			PASS("mmap(PROT_READ)");
			if (munmap(addr, 4096) < 0)
				FAIL("munmap()", "errno=%d", errno);
			else
				PASS("munmap()");
		}
	}

	/* mmap write */
	fd = open(path, O_RDWR);
	if (fd < 0) {
		FAIL("mmap(PROT_WRITE)", "open failed errno=%d", errno);
	} else {
		void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		if (addr == MAP_FAILED) {
			FAIL("mmap(PROT_WRITE)", "errno=%d", errno);
		} else {
			memcpy(addr, "TEST", 4);
			msync(addr, 4096, MS_SYNC);
			PASS("mmap(PROT_WRITE)");
			munmap(addr, 4096);
		}
	}

	/* mmap anonymous (no file) */
	void *anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED) {
		FAIL("mmap(MAP_ANONYMOUS)", "errno=%d", errno);
	} else {
		memset(anon, 0xAB, 4096);
		PASS("mmap(MAP_ANONYMOUS)");
		munmap(anon, 4096);
	}
}

/* =========================================================================
 * 9. Linux AIO (io_setup / io_submit / io_getevents / io_cancel / io_destroy)
 * ====================================================================== */

static void test_linux_aio(void)
{
	section("Linux AIO (libaio syscalls)");

	char path[256];
	tmppath(path, sizeof(path), "aio_test.bin");
	if (make_file(path, 4096) < 0) {
		FAIL("setup", "make_file failed");
		return;
	}

	/* io_setup */
	aio_context_t ctx = 0;
	if (syscall(__NR_io_setup, 32, &ctx) < 0) {
		FAIL("io_setup()", "errno=%d (%s)", errno, strerror(errno));
		return;
	}
	PASS("io_setup()");

	/* io_submit + io_getevents */
	int fd = open(path, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		/* O_DIRECT may fail on some fs; try without */
		fd = open(path, O_RDONLY);
	}

	if (fd < 0) {
		FAIL("io_submit()", "open failed errno=%d", errno);
		SKIP("io_getevents()", "depends on io_submit");
		SKIP("io_cancel()", "depends on io_submit");
	} else {
		/* Allocate aligned buffer (required for O_DIRECT) */
		void *buf = NULL;
		posix_memalign(&buf, 512, 4096);

		struct iocb cb = {
			.aio_fildes    = fd,
			.aio_lio_opcode = IOCB_CMD_PREAD,
			.aio_buf       = (uint64_t)(uintptr_t)buf,
			.aio_nbytes    = 512,
			.aio_offset    = 0,
		};
		struct iocb *cbs[1] = { &cb };

		long nr = syscall(__NR_io_submit, ctx, 1, cbs);
		if (nr < 0) {
			FAIL("io_submit()", "errno=%d (%s)", errno, strerror(errno));
			SKIP("io_getevents()", "io_submit failed");
			SKIP("io_cancel()", "io_submit failed");
		} else {
			PASS("io_submit()");

			/* io_getevents */
			struct io_event events[1];
			struct timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };
			long got = syscall(__NR_io_getevents, ctx, 1, 1, events, &timeout);
			if (got < 0)
				FAIL("io_getevents()", "errno=%d (%s)", errno, strerror(errno));
			else
				PASS("io_getevents()");

			/*
			 * io_cancel: attempt to cancel a completed op.
			 * EAGAIN (op already finished) or EINVAL (op already
			 * reaped) are both normal responses that prove the
			 * syscall was reached and handled.
			 */
			struct io_event cancel_event;
			long rc = syscall(__NR_io_cancel, ctx, &cb, &cancel_event);
			if (rc < 0 && errno != EAGAIN && errno != EINVAL)
				FAIL("io_cancel()", "errno=%d (%s)", errno, strerror(errno));
			else
				PASS("io_cancel()");
		}

		free(buf);
		close(fd);
	}

	/* io_destroy */
	if (syscall(__NR_io_destroy, ctx) < 0)
		FAIL("io_destroy()", "errno=%d (%s)", errno, strerror(errno));
	else
		PASS("io_destroy()");
}

/* =========================================================================
 * 10. io_uring
 * ====================================================================== */

/*
 * Minimal io_uring parameter struct — mirrors the kernel's io_uring_params
 * without pulling in a newer liburing header.
 */
struct uring_params {
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	uint32_t sq_thread_cpu;
	uint32_t sq_thread_idle;
	uint32_t features;
	uint32_t wq_fd;
	uint32_t resv[3];
	/* sq_off / cq_off omitted — we don't map the rings */
	uint8_t  _pad[2 * 40];
};

static void test_io_uring(void)
{
	section("io_uring");

	struct uring_params params;
	memset(&params, 0, sizeof(params));

	/* io_uring_setup */
	int ring_fd = syscall(__NR_io_uring_setup, 8, &params);
	if (ring_fd < 0) {
		FAIL("io_uring_setup()", "errno=%d (%s)", errno, strerror(errno));
		SKIP("io_uring_register()", "io_uring_setup failed");
		SKIP("io_uring_enter()",    "io_uring_setup failed");
		return;
	}
	PASS("io_uring_setup()");

	/*
	 * io_uring_register — IORING_UNREGISTER_BUFFERS with no prior registration
	 * returns ENXIO, which still proves the syscall was reached and dispatched.
	 */
	long rc = syscall(__NR_io_uring_register, ring_fd,
			  IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (rc < 0 && errno != ENXIO)
		FAIL("io_uring_register()", "errno=%d (%s)", errno, strerror(errno));
	else
		PASS("io_uring_register()");

	/*
	 * io_uring_enter with to_submit=0 is a no-op but still exercises
	 * the syscall path.
	 */
	rc = syscall(__NR_io_uring_enter, ring_fd, 0, 0, 0, NULL, 0);
	if (rc < 0 && errno != EBADFD)
		FAIL("io_uring_enter()", "errno=%d (%s)", errno, strerror(errno));
	else
		PASS("io_uring_enter()");

	close(ring_fd);
}

/* =========================================================================
 * 11. Mount / umount2  (optional — requires CAP_SYS_ADMIN)
 * ====================================================================== */

static void test_mount_operations(void)
{
	section("Mount operations");

	if (getuid() != 0) {
		SKIP("mount()",   "requires root / CAP_SYS_ADMIN");
		SKIP("umount2()", "requires root / CAP_SYS_ADMIN");
		return;
	}

	/*
	 * Bind-mount tmpfs at the test directory so we don't touch real
	 * mount points.  Immediate umount follows.
	 */
	char mnt[256];
	tmppath(mnt, sizeof(mnt), "mountpoint");
	mkdir(mnt, 0755);

	if (mount("none", mnt, "tmpfs", 0, NULL) < 0) {
		FAIL("mount()", "errno=%d (%s)", errno, strerror(errno));
	} else {
		PASS("mount()");
		if (umount2(mnt, 0) < 0)
			FAIL("umount2()", "errno=%d (%s)", errno, strerror(errno));
		else
			PASS("umount2()");
	}

	rmdir(mnt);
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(int argc, char *argv[])
{
	int test_mount = 0;
	const char *target_dir = "/tmp";

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--mount") == 0)
			test_mount = 1;
		else if (strcmp(argv[i], "--target-dir") == 0 && i + 1 < argc)
			target_dir = argv[++i];
	}

	/* Create a private temporary directory */
	if (snprintf(g_tmpdir, sizeof(g_tmpdir), "%s/test_syscalls_XXXXXX", target_dir)
	    >= (int)sizeof(g_tmpdir)) {
		fprintf(stderr, "target directory path too long\n");
		return 1;
	}
	if (!mkdtemp(g_tmpdir)) {
		fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
		return 1;
	}

	printf("======================================================================\n");
	printf("Syscall coverage test for iosnoop / ioslower\n");
	printf("Kernel: ");
	fflush(stdout);
	system("uname -r");
	printf("Tmpdir: %s\n", g_tmpdir);
	printf("======================================================================\n");

	test_file_operations();
	test_file_metadata();
	test_directory_operations();
	test_file_deletion();
	test_file_renaming();
	test_link_operations();
	test_vector_io();
	test_additional_vfs_operations();
	test_memory_mapping();
	test_linux_aio();
	test_io_uring();

	if (test_mount)
		test_mount_operations();
	else
		SKIP("mount()/umount2()", "pass --mount to test (requires root)");

	/* Cleanup */
	char rm_cmd[300];
	snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", g_tmpdir);
	system(rm_cmd);

	printf("\n======================================================================\n");
	printf("Results:  %d passed,  %d failed,  %d skipped\n",
	       g_passed, g_failed, g_skipped);
	printf("======================================================================\n");

	return g_failed > 0 ? 1 : 0;
}
