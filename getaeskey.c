#define _GNU_SOURCE

#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <dlfcn.h>

//--- syscalls
#define syscall0(nr) syscall6(nr, 0, 0, 0, 0, 0, 0)
#define syscall1(nr, a1) syscall6(nr, a1, 0, 0, 0, 0, 0)
#define syscall2(nr, a1, a2) syscall6(nr, a1, a2, 0, 0, 0, 0)
#define syscall3(nr, a1, a2, a3) syscall6(nr, a1, a2, a3, 0, 0, 0)
#define syscall4(nr, a1, a2, a3, a4) syscall6(nr, a1, a2, a3, a4, 0, 0)
#define syscall5(nr, a1, a2, a3, a4, a5) syscall6(nr, a1, a2, a3, a4, a5, 0)

static int __attribute__ ((noinline)) syscall6(uint32_t nr, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6)
{
	register uint32_t __r0 __asm__ ("r0") = arg1;
	register uint32_t __r1 __asm__ ("r1") = arg2;
	register uint32_t __r2 __asm__ ("r2") = arg3;
	register uint32_t __r3 __asm__ ("r3") = arg4;
	register uint32_t __r4 __asm__ ("r4") = arg5;
	register uint32_t __r5 __asm__ ("r5") = arg6;
	register uint32_t __r7 __asm__ ("r7") = nr;
	
	__asm__ __volatile__ (
        "svc #0\n" 	: "+r"(__r0)
					: "r" (__r0), "r" (__r1), "r" (__r2), "r" (__r3), "r" (__r4), "r" (__r5), "r" (__r7)
    );
	
	return __r0;
}

#define _open(pathname, flags, mode) syscall3(__NR_open, (int)pathname, (int)flags, (int)mode)
#define _close(fd) syscall1(__NR_close, fd)
#define _read(fd, buf, count) syscall3(__NR_read, (int)fd, (int)buf, (int)count)

#include "module.h"
#include "tee_client_api_A.h"

//--- /lib/libc.so.6
typedef int (*open_t)(const char *pathname, int flags, mode_t mode);
typedef int (*read_t)(int fd, void *buf, size_t count);
typedef int (*write_t)(int fd, const void *buf, size_t count);
typedef int (*close_t)(int fd);
typedef int (*rename_t)(const char *old, const char *new);
typedef DIR* (*opendir_t)(const char *name);
typedef int (*closedir_t)(DIR *dirp);
typedef struct dirent* (*readdir_t)(DIR *dirp);

typedef int (*ioctl_t)(int fd, unsigned long request, ...);

typedef void* (*mmap_t)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
typedef int (*munmap_t)(void *addr, size_t length);
typedef void (*memset_t)(void *s, int c, size_t n);
typedef void (*memcpy_t)(void *dest, const void * src, size_t n);
typedef int (*sprintf_t)(char *str, const char *format, ...);
typedef size_t (*strlen_t)(const char *str);
typedef char* (*strrchr_t)(const char *s, int c);

typedef uid_t (*getuid_t)(void);
typedef gid_t (*getgid_t)(void);
typedef int (*setuid_t)(uid_t uid);
typedef int (*setgid_t)(gid_t gid);
typedef pid_t (*getpid_t)(void);

typedef int (*chroot_t)(const char *path);

typedef int (*socket_t)(int domain, int type, int protocol);
typedef in_addr_t (*inet_addr_t)(const char *cp);
typedef int (*connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

typedef int (*dup2_t)(int oldfd, int newfd);
typedef int (*execve_t)(const char *pathname, char *const argv[], char *const envp[]);
typedef int (*system_t)(const char *command);

//--- /lib/libdl.so.2
typedef void* (*dlopen_t)(const char *filename, int flag);
typedef char* (*dlerror_t)(void);
typedef void* (*dlsym_t)(void *handle, const char *symbol);
typedef int   (*dlclose_t)(void *handle); 

//--- /usr/lib/libteec.so
typedef TEEC_Result (*TEEC_InitializeContext_t)(const char *name, TEEC_Context *context);
typedef void (*TEEC_FinalizeContext_t)(TEEC_Context *context);
typedef TEEC_Result (*TEEC_OpenSession_t)(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination, uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);
typedef void (*TEEC_CloseSession_t)(TEEC_Session *session);
typedef TEEC_Result (*TEEC_AllocateSharedMemory_t)(TEEC_Context *context, TEEC_SharedMemory *sharedMem);
typedef void (*TEEC_ReleaseSharedMemory_t)(TEEC_SharedMemory *sharedMem);
typedef TEEC_Result (*TEEC_InvokeCommand_t)(TEEC_Session *session, uint32_t commandID, TEEC_Operation *operation, uint32_t *returnOrigin);

typedef struct global_data_t 
{	
    int ret;
	int log_fd;
		
	open_t open;
	read_t read;
	write_t write;
	close_t close;
	
	opendir_t opendir;
	closedir_t closedir;
	readdir_t readdir;
		
	ioctl_t ioctl;
		
	mmap_t mmap;
	munmap_t munmap;	
	memset_t memset;
	memcpy_t memcpy;
	sprintf_t sprintf;
	strlen_t strlen;
	strrchr_t strrchr;
	
	getuid_t getuid;
	getgid_t getgid;
	setuid_t setuid;
	setgid_t setgid;
	getpid_t getpid;
	
	chroot_t chroot;
	
	socket_t socket;
	inet_addr_t inet_addr;
	connect_t connect;
	
	dup2_t dup2;
	execve_t execve;
	system_t system;
	
	dlopen_t dlopen;
	dlerror_t dlerror;
	dlsym_t dlsym;
	dlclose_t dlclose;
	
} gd_t;

#define assert( expr ) if( !(expr) ) { g->ret = __LINE__; return -1; }
#define fetch_proc_address( name ) g->name = (name##_t)get_proc_address(hmod, #name); assert(g->name)
#define fetch_dlsym( name ) g->name = (name##_t)g->dlsym(hmod, #name); assert(g->name)

static int init( gd_t *g, void* libdladdr )
{
	g->ret = 0;	
	
	void* hmod = get_proc_address(libdladdr, "dlopen") ? libdladdr : get_module_handle("libdl-");	
	assert(hmod);
			
	fetch_proc_address(dlopen);
	fetch_proc_address(dlerror);
	fetch_proc_address(dlsym);
	fetch_proc_address(dlclose);
			
	hmod = g->dlopen("/lib/libc.so.6", RTLD_NOW);	
	assert(hmod);
				
	fetch_dlsym(open);
	fetch_dlsym(read);
	fetch_dlsym(write);
	fetch_dlsym(close);
	
//	fetch_dlsym(mmap);
//	fetch_dlsym(munmap);
	fetch_dlsym(memcpy);
	fetch_dlsym(sprintf);
	fetch_dlsym(strlen);
//	fetch_dlsym(strrchr);
	
/*	fetch_dlsym(getuid);
	fetch_dlsym(getgid);
	fetch_dlsym(setuid);
	fetch_dlsym(setgid);
	fetch_dlsym(getpid);
	
	fetch_dlsym(socket);
	fetch_dlsym(inet_addr);
	fetch_dlsym(connect);
	
	fetch_dlsym(dup2);
	fetch_dlsym(execve);
	fetch_dlsym(system);
*/	
	g->dlclose(hmod);
	
	#define LOGFILE 	"/tmp/" FILENAME ".log"
	g->log_fd = g->open( LOGFILE, O_WRONLY | O_CREAT | O_TRUNC, 0666 );
	assert(g->log_fd != -1);
	
	return 0;
}

#define log0(g, fmt) __log(g, fmt, 0, 0, 0, 0)
#define log1(g, fmt, a1) __log(g, fmt, a1, 0, 0, 0)
#define log2(g, fmt, a1, a2) __log(g, fmt, a1, a2, 0, 0)
#define log3(g, fmt, a1, a2, a3) __log(g, fmt, a1, a2, a3, 0)
#define log4(g, fmt, a1, a2, a3, a4) __log(g, fmt, a1, a2, a3, a4)

static void __log( gd_t *g, uint8_t* fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4 )
{
	uint8_t msg[255];
	
	g->sprintf(msg, fmt, a1, a2, a3, a4);
	g->write(g->log_fd, msg, g->strlen(msg));	
}

int main(void* libdladdr)
{	
	gd_t g;
		
	if( init(&g, libdladdr) )
		return g.ret;
			
	// custom logic start
		
	#undef assert
	#undef fetch_dlsym
	#define assert( expr ) if( !(expr) ) { g.ret = __LINE__; goto out; }
	#define fetch_dlsym( name ) name##_t name = (name##_t)g.dlsym(hmod, #name); assert(name)
	
	void* hmod = g.dlopen("/usr/lib/libteec.so", RTLD_NOW);
	assert(hmod);
	
	fetch_dlsym(TEEC_InitializeContext);
	fetch_dlsym(TEEC_FinalizeContext);
	fetch_dlsym(TEEC_OpenSession);
	fetch_dlsym(TEEC_CloseSession);
	fetch_dlsym(TEEC_AllocateSharedMemory);
	fetch_dlsym(TEEC_ReleaseSharedMemory);
	fetch_dlsym(TEEC_InvokeCommand);
			
	// read key file
	int32_t fd, len;
	uint8_t buf[0x1000];
	//if( (fd = g.open( "/usr/share/org.tizen.tv.swu/OpenAPIAESPassphraseEncrypted.txt", O_RDONLY, 0 )) == -1 )			
	if( (fd = g.open( "/usr/share/org.tizen.tv.swu/itemsAESPassphraseEncrypted.txt", O_RDONLY, 0 )) == -1 )
	{
		log0(&g, "error opening file /usr/share/org.tizen.tv.swu/itemsAESPassphraseEncrypted.txt\n");
		g.ret = __LINE__; goto out;
	}
	
	if( (len = g.read( fd, buf, 0x1000 )) <= 0 )
	{
		log0(&g, "error reading key file\n");
		g.ret = __LINE__; goto out;
	}

	log1(&g, "key len=%d\n", len);
			
	TEEC_Result r;
	TEEC_Context context;			
//	uint8_t destination[16] = {0x21, 0x22, 0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};	
	TEEC_UUID destination = { .timeLow = 0x22222221, .timeMid = 0, .timeHiAndVersion = 0, .clockSeqAndNode = {0, 0, 0, 0, 0, 0, 0, 1} };	
		
	log1(&g, "TEEC_InitializeContext = 0x%08x\n", TEEC_InitializeContext(0, &context));
//	TEEC_InitializeContext(0, &context);
		
	//	TEEC_SharedMemory sharedMem = { .buffer = NULL, .size = 0x1000, .flags = TEEC_VALUE_INOUT };
	TEEC_SharedMemory shm[3];		// input, output, salt
	
	for( int i = 0; i < 3; i++ )
	{
		shm[i].buffer = NULL;
		shm[i].size = 0x10000;
		shm[i].flags = TEEC_VALUE_INOUT;
		
		log1(&g, "TEEC_AllocateSharedMemory = 0x%08x\n", TEEC_AllocateSharedMemory(&context, &shm[i]));
//		TEEC_AllocateSharedMemory(&context, &shm[i]);
	}
	
	TEEC_Session session;
	log1(&g, "TEEC_OpenSession = 0x%08x\n", TEEC_OpenSession(&context, &session, &destination, 0, 0, 0, 0));
//	TEEC_OpenSession(&context, &session, &destination, 0, 0, 0, 0);
	
	g.memcpy(shm[0].buffer, buf, len);
	g.close(fd);
			
	//TEEC_Operation operation = { .started = 0, .paramTypes = TEEC_MEMREF_PARTIAL_INOUT, .params = { {.memref = {.parent = &sharedMem, .size = sharedMem.size, .offset = 0}}} };
	TEEC_Operation operation;
	operation.started = 0;
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT, TEEC_VALUE_INOUT, 0);	
	operation.params[0].memref.parent = &shm[0];		// input buffer
	operation.params[0].memref.size = len;
	operation.params[0].memref.offset = 0;
	operation.params[1].memref.parent = &shm[1];		// output buffer
	operation.params[1].memref.size = shm[1].size;
	operation.params[1].memref.offset = 0;
	operation.params[2].value.a = 0;			// bEncrypt
	operation.params[2].value.b = 0;			// bPassphraseEncrypted
		
	log1(&g, "TEEC_InvokeCommand = 0x%08x\n", TEEC_InvokeCommand(&session, 3, &operation, 0));	
	//TEEC_InvokeCommand(&session, 3, &operation, 0);
		
	log0(&g, "decrypted:\n");
	g.write(g.log_fd, shm[1].buffer, shm[1].size);
	
	for( int i = 0; i < 3; i++ )
		TEEC_ReleaseSharedMemory(&shm[i]);
	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);

out:		
	g.dlclose(hmod);
	
	// custom logic end

	g.close(g.log_fd);
		
	return g.ret;
} 
