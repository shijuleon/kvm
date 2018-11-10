#include <err.h> // err & errx
#include <fcntl.h> // manipulate file descriptors
#include <stdlib.h> 
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/mman.h>

int kvm(const uint8_t code[], size_t code_len){


	int kvm, ret, vmfd;
	uint8_t *mem;
	struct kvm_run *run;
	struct kvm_sregs sregs;
		
	/* The kvm API is centered around file descriptors.  An initial
	   open("/dev/kvm") obtains a handle to the kvm subsystem; this handle
	   can be used to issue system ioctls */

	/* open with close-on-exec (automatically close fd when any of exec-family functions
	 * succed and read-write */ 
	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1) errx(1, "failed to open /dev/kvm");

	/* check if we have version 12 which is backward compatible */
	ret  = ioctl(kvm, KVM_GET_API_VERSION, NULL);
	if (ret == -1) err(1, "KVM_GET_API_VERSION");
	if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);
	
	/* example check for extension KVM_CAP_USER_MEM (to setup guest memory) */
	ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (ret == -1) err(1, "KVM_CHECK_EXTENSION: KVM_CAP_USER_MEM");
	if (!ret) errx(1, "Required extension KVM_CAP_USER_MEM not available");

	// Create a virtual machine
	vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
	if (vmfd == -1) err(1, "KVM_CREATE_VM");

	// allocate memory for the guest
	size_t mem_size = 0x40000000; // 1GB
	// create mapping in the virtual address space
	// MAP_ANONYMOUS - not backed by a fd, no copy-on-write 
	mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!mem) err(1, "allocating guest memory");
	size_t user_entry = 0x0;
	memcpy(mem, code, code_len);
	
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = user_entry,
		.memory_size = mem_size,
		.userspace_addr = (uint64_t)mem
	};
	ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
	if (ret == -1) err(1, "KVM_SET_USER_MEMORY_REGION");
	
	// create virtual CPU
	int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
	if (vcpufd == -1) err(1, "KVM_CREATE_VCPU");
	
	// map the shared kvm structure and following data
	size_t vcpu_mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
	if (vcpu_mmap_size < sizeof(*run))
		errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
	run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if (!run) err(1, "mmap vcpu");

	// initialize cs to point to 0 via a read-modify-write of sregs
	ret = ioctl(vcpufd, KVM_GET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_GET_SREGS");
	// sregs - special & segment registers
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	ret = ioctl(vcpufd, KVM_SET_SREGS, &sregs);
	if (ret == -1) err(1, "KVM_SET_SREGS");
	
	// setup vCPU's registers
	struct kvm_regs regs = {
		.rip = 0x1000,
		.rsp = 0x200000,
		.rflags = 0x2,
		.rax = 2,
		.rbx = 2,
	};
	ret = ioctl(vcpufd, KVM_SET_REGS, &regs);
	if (ret == -1) err(1, "KVM_SET_REGS");
	
	while (1) {
		ret = ioctl(vcpufd, KVM_RUN, NULL);
		if (ret == -1) err(1, "KVM_RUN");
		switch (run->exit_reason){
		case KVM_EXIT_HLT:
			puts("KVM_EXIT_HLT");
			return 0;
		case KVM_EXIT_IO:
			if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1)
				putchar(*(((char *)run) + run->io.data_offset));
			else
				errx(1, "unhandled KVM_EXIT_IO: 0x%x", run->exit_reason);
			break;
		case KVM_EXIT_FAIL_ENTRY:
			errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason: 0x%llx", 
					(unsigned long long)run->fail_entry.hardware_entry_failure_reason);
		case KVM_EXIT_INTERNAL_ERROR:
			errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x", run->internal.suberror);
		default:
			errx(1, "exit reason: 0x%x", run->exit_reason);
		}
	}
}


int main(){
	
	const uint8_t code[] = {
        	0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        	0x00, 0xd8,       /* add %bl, %al */
        	0x04, '0',        /* add $'0', %al */
        	0xee,             /* out %al, (%dx) */
        	0xb0, '\n',       /* mov $'\n', %al */
        	0xee,             /* out %al, (%dx) */
        	0xf4,             /* hlt */
    	};


	//const uint8_t code[] = "\xB0\x61\xBA\x17\x02\xEE\xB0\n\xEE\xF4";
	
	kvm(code, sizeof(code));
	return 0;
}
