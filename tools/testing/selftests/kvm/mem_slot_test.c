// SPDX-License-Identifier: GPL-2.0-only
/*
 * mem_slot_test
 *
 * Copyright (C) 2020, Red Hat, Inc.
 *
 * Test suite for memory region operations.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <linux/kvm.h>
#include <sys/mman.h>

#include "test_util.h"
#include "kvm_util.h"

/*
 * Test it can be added memory slots up to KVM_CAP_NR_MEMSLOTS, then any
 * tentative to add further slots should fail.
 */
static void test_add_max_slots(void)
{
	int ret;
	struct kvm_vm *vm;
	uint32_t max_mem_slots;
	uint32_t slot;
	uint64_t guest_addr;
	uint64_t mem_reg_npages;
	uint64_t mem_reg_size;
	void *mem;

	max_mem_slots = kvm_check_cap(KVM_CAP_NR_MEMSLOTS);
	TEST_ASSERT(max_mem_slots > 0,
		    "KVM_CAP_NR_MEMSLOTS should be greater than 0");
	pr_info("Allowed number of memory slots: %i\n", max_mem_slots);

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);

	/*
	 * Uses 1MB sized/aligned memory region since this is the minimal
	 * required on s390x.
	 */
	mem_reg_size = 0x100000;
	mem_reg_npages = vm_calc_num_guest_pages(VM_MODE_DEFAULT, mem_reg_size);

	guest_addr = 0x0;

	/* Check it can be added memory slots up to the maximum allowed */
	pr_info("Adding slots 0..%i, each memory region with %ldK size\n",
		(max_mem_slots - 1), mem_reg_size >> 10);
	for (slot = 0; slot < max_mem_slots; slot++) {
		vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
					    guest_addr, slot, mem_reg_npages,
					    0);
		guest_addr += mem_reg_size;
	}

	/* Check it cannot be added memory slots beyond the limit */
	mem = mmap(NULL, mem_reg_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(mem != MAP_FAILED, "Failed to mmap() host");

	ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION,
		    &(struct kvm_userspace_memory_region) {slot, 0, guest_addr,
		    mem_reg_size, (uint64_t) mem});
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "Adding one more memory slot should fail with EINVAL");

	munmap(mem, mem_reg_size);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	test_add_max_slots();
	return 0;
}
