// SPDX-License-Identifier: GPL-2.0-only
/*
 * mem_slot_test
 *
 * Copyright (C) 2020, Red Hat, Inc.
 *
 * Test it can be added memory slots up to KVM_CAP_NR_MEMSLOTS, then any
 * tentative to add further slots should fail.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <linux/kvm.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"

/* Memory region flags */
#define MEM_REG_FLAGS KVM_MEM_LOG_DIRTY_PAGES

/* Guest VM mode */
#define GUEST_VM_MODE VM_MODE_DEFAULT

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	/* Maximum allowed number of memory slots */
	uint32_t max_mem_slots;
	/* Slot number */
	uint32_t slot;
	/* Number of pages in a memory region */
	uint64_t mem_reg_npages;
	/* Memory region size */
	uint64_t mem_reg_size;
	/* Guest physical memory guest_address */
	uint64_t guest_addr;
	/* VM page size */
	uint64_t vm_page_size;
	int ret;

	max_mem_slots = kvm_check_cap(KVM_CAP_NR_MEMSLOTS);
	TEST_ASSERT(max_mem_slots > 0,
		    "KVM_CAP_NR_MEMSLOTS should be greater than 0");
	DEBUG("Allowed number of memory slots: %i\n", max_mem_slots);

	vm = vm_create(GUEST_VM_MODE, 0, O_RDWR);

	/* Determine the minimal number of pages as possible per region. */
	vm_page_size = vm_get_page_size(vm);
#ifdef __s390x__
	mem_reg_size = 0x100000;
#else
	uint64_t host_page_size = sysconf(_SC_PAGESIZE);

	mem_reg_size = (host_page_size > vm_page_size) ? host_page_size :
							 vm_page_size;
#endif
	mem_reg_npages = mem_reg_size / vm_page_size;
	guest_addr = 0x0;

	/* Check it can be added memory slots up to the maximum allowed */
	DEBUG("Adding slots 0..%i, each memory region with %ldK size\n",
	      (max_mem_slots - 1), mem_reg_size >> 10);
	for (slot = 0; slot < max_mem_slots; slot++) {
		vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
					    guest_addr, slot, mem_reg_npages,
					    MEM_REG_FLAGS);
		guest_addr += mem_reg_size;
	}

	/* Check it cannot be added memory slots beyond the limit */
	guest_addr += mem_reg_size;
	void *mem = mmap(NULL, mem_reg_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(mem != NULL, "Failed to mmap() host");

	struct kvm_userspace_memory_region kvm_region = {
		.slot = slot,
		.flags = MEM_REG_FLAGS,
		.guest_phys_addr = guest_addr,
		.memory_size = mem_reg_size,
		.userspace_addr = (uint64_t) mem,
	};

	ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION, &kvm_region);
	TEST_ASSERT(ret == -1, "Adding one more memory slot should fail");

	munmap(mem, mem_reg_size);
	kvm_vm_free(vm);

	return 0;
}
