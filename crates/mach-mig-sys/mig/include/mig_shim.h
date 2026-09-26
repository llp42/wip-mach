#ifndef WIPMACH_MIG_SHIM_H
#define WIPMACH_MIG_SHIM_H

#include <stdint.h>
#include <stddef.h>

typedef unsigned int natural_t;
typedef int integer_t;
typedef unsigned long long_natural_t;
typedef long long_integer_t;
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_size_t;
typedef vm_offset_t vm_address_t;
typedef vm_offset_t *vm_offset_array_t;
typedef vm_size_t *vm_size_array_t;
typedef uintptr_t rpc_uintptr_t;
typedef vm_offset_t rpc_vm_address_t;
typedef vm_offset_t rpc_vm_offset_t;
typedef vm_size_t rpc_vm_size_t;
typedef long_natural_t rpc_long_natural_t;
typedef long_integer_t rpc_long_integer_t;
typedef unsigned long phys_addr_t;
typedef unsigned long long rpc_phys_addr_t;

typedef int boolean_t;
#define TRUE ((boolean_t) 1)
#define FALSE ((boolean_t) 0)

typedef int kern_return_t;
#define KERN_SUCCESS 0

typedef unsigned int mach_port_name_t;
typedef vm_offset_t mach_port_t;
typedef mach_port_t *mach_port_array_t;
typedef natural_t mach_port_seqno_t;
typedef natural_t mach_port_right_t;
typedef natural_t mach_port_type_t;
typedef natural_t mach_port_urefs_t;
typedef integer_t mach_port_delta_t;

#define MACH_PORT_NULL 0
#define MACH_PORT_DEAD ((mach_port_t) ~0)
#define MACH_PORT_VALID(port) \
    (((port) != MACH_PORT_NULL) && ((port) != MACH_PORT_DEAD))

typedef unsigned int mach_msg_bits_t;
typedef unsigned int mach_msg_size_t;
typedef natural_t mach_msg_seqno_t;
typedef integer_t mach_msg_id_t;
typedef unsigned int mach_msg_type_name_t;
typedef unsigned int mach_msg_type_size_t;
typedef natural_t mach_msg_type_number_t;
typedef natural_t mach_msg_timeout_t;

typedef struct mach_msg_header {
    mach_msg_bits_t msgh_bits;
    mach_msg_size_t msgh_size;
    union {
        mach_port_t msgh_remote_port;
        rpc_uintptr_t msgh_remote_port_do_not_use;
    };
    union {
        mach_port_t msgh_local_port;
        rpc_uintptr_t msgh_protected_payload;
    };
    mach_port_seqno_t msgh_seqno;
    mach_msg_id_t msgh_id;
} mach_msg_header_t;

typedef struct {
    unsigned int msgt_name : 8, msgt_size : 16, msgt_unused : 5,
        msgt_inline : 1, msgt_longform : 1, msgt_deallocate : 1;
    mach_msg_type_number_t msgt_number;
} __attribute__((aligned(__alignof__(uintptr_t)))) mach_msg_type_t;

typedef struct {
    union {
        mach_msg_type_t msgtl_header;
        struct {
            unsigned int msgtl_name : 8, msgtl_size : 16, msgtl_unused : 5,
                msgtl_inline : 1, msgtl_longform : 1, msgtl_deallocate : 1;
            mach_msg_type_number_t msgtl_number;
        };
    };
} __attribute__((aligned(__alignof__(uintptr_t)))) mach_msg_type_long_t;

#define MACH_MSGH_BITS_REMOTE_MASK 0x000000ff
#define MACH_MSGH_BITS_LOCAL_MASK 0x0000ff00
#define MACH_MSGH_BITS_COMPLEX 0x80000000U
#define MACH_MSGH_BITS_CIRCULAR 0x40000000
#define MACH_MSGH_BITS_COMPLEX_PORTS 0x20000000
#define MACH_MSGH_BITS_COMPLEX_DATA 0x10000000
#define MACH_MSGH_BITS_MIGRATED 0x08000000
#define MACH_MSGH_BITS_UNUSED 0x07ff0000
#define MACH_MSGH_BITS(remote, local) ((remote) | ((local) << 8))
#define MACH_MSGH_BITS_REMOTE(bits) ((bits) & MACH_MSGH_BITS_REMOTE_MASK)
#define MACH_MSGH_BITS_LOCAL(bits) \
    (((bits) & MACH_MSGH_BITS_LOCAL_MASK) >> 8)
#define MACH_MSGH_BITS_PORTS_MASK \
    (MACH_MSGH_BITS_REMOTE_MASK | MACH_MSGH_BITS_LOCAL_MASK)
#define MACH_MSGH_BITS_OTHER(bits) ((bits) & ~MACH_MSGH_BITS_PORTS_MASK)

#define MACH_MSG_TYPE_UNSTRUCTURED 0
#define MACH_MSG_TYPE_BIT 0
#define MACH_MSG_TYPE_BOOLEAN 0
#define MACH_MSG_TYPE_INTEGER_16 1
#define MACH_MSG_TYPE_INTEGER_32 2
#define MACH_MSG_TYPE_CHAR 8
#define MACH_MSG_TYPE_BYTE 9
#define MACH_MSG_TYPE_INTEGER_8 9
#define MACH_MSG_TYPE_REAL 10
#define MACH_MSG_TYPE_INTEGER_64 11
#define MACH_MSG_TYPE_STRING 12
#define MACH_MSG_TYPE_STRING_C 12
#define MACH_MSG_TYPE_MOVE_RECEIVE 16
#define MACH_MSG_TYPE_MOVE_SEND 17
#define MACH_MSG_TYPE_MOVE_SEND_ONCE 18
#define MACH_MSG_TYPE_COPY_SEND 19
#define MACH_MSG_TYPE_MAKE_SEND 20
#define MACH_MSG_TYPE_MAKE_SEND_ONCE 21
#define MACH_MSG_TYPE_PORT_NAME 15
#define MACH_MSG_TYPE_PORT_RECEIVE MACH_MSG_TYPE_MOVE_RECEIVE
#define MACH_MSG_TYPE_PORT_SEND MACH_MSG_TYPE_MOVE_SEND
#define MACH_MSG_TYPE_PORT_SEND_ONCE MACH_MSG_TYPE_MOVE_SEND_ONCE
#define MACH_MSG_TYPE_POLYMORPHIC ((mach_msg_type_name_t) -1)
#define MACH_MSG_TYPE_PORT_ANY(x)                       \
    (((x) >= MACH_MSG_TYPE_MOVE_RECEIVE) &&             \
     ((x) <= MACH_MSG_TYPE_MAKE_SEND_ONCE))
#define MACH_MSG_TYPE_PORT_ANY_SEND(x)                  \
    (((x) >= MACH_MSG_TYPE_MOVE_SEND) &&                \
     ((x) <= MACH_MSG_TYPE_MAKE_SEND_ONCE))

#define MACH_MSG_SUCCESS 0
#define MACH_MSG_SIZE_MAX ((mach_msg_size_t) ~0)

#define MIG_TYPE_ERROR -300
#define MIG_REPLY_MISMATCH -301
#define MIG_REMOTE_ERROR -302
#define MIG_BAD_ID -303
#define MIG_BAD_ARGUMENTS -304
#define MIG_NO_REPLY -305
#define MIG_EXCEPTION -306
#define MIG_ARRAY_TOO_LARGE -307
#define MIG_SERVER_DIED -308
#define MIG_DESTROY_REQUEST -309

typedef struct mig_symtab {
    char *ms_routine_name;
    int ms_routine_number;
    void (*ms_routine)(void);
} mig_symtab_t;

typedef void (*mig_routine_t)(mach_msg_header_t *, mach_msg_header_t *);

typedef struct task *task_t;
typedef struct thread *thread_t;
typedef struct host *host_t;
typedef struct processor *processor_t;
typedef struct processor_set *processor_set_t;
typedef struct vm_map *vm_map_t;
typedef struct vm_object *vm_object_t;
typedef struct device *device_t;
typedef struct ipc_port *ipc_port_t;
typedef struct ipc_space *ipc_space_t;
typedef ipc_space_t space_t;
typedef host_t host_priv_t;
typedef mach_port_t processor_set_name_t;
typedef task_t *task_array_t;
typedef thread_t *thread_array_t;
typedef processor_t *processor_array_t;
typedef processor_set_t *processor_set_array_t;
typedef vm_offset_t *emulation_vector_t;

typedef struct descriptor {
    unsigned int low_word;
    unsigned int high_word;
} descriptor_t;
typedef descriptor_t *descriptor_list_t;
typedef unsigned short io_port_t;
typedef mach_port_t io_perm_t;

struct rpc_time_value {
    rpc_long_integer_t seconds;
    integer_t microseconds;
};

struct time_value {
    long_integer_t seconds;
    integer_t microseconds;
};
typedef struct time_value time_value_t;
typedef struct rpc_time_value rpc_time_value_t;

static __inline__ rpc_time_value_t
convert_time_value_to_user(time_value_t tv)
{
    rpc_time_value_t user = {
        .seconds = tv.seconds, .microseconds = tv.microseconds};
    return user;
}

static __inline__ time_value_t
convert_time_value_from_user(rpc_time_value_t tv)
{
    time_value_t kernel = {
        .seconds = tv.seconds, .microseconds = tv.microseconds};
    return kernel;
}

#define null_conversion(port) (port)
#define convert_vm_to_user null_conversion
#define convert_vm_from_user null_conversion
#define convert_long_natural_to_user convert_vm_to_user
#define convert_long_natural_from_user convert_vm_from_user
#define convert_time_value_to_kernel convert_time_value_from_user
#define convert_time_value_from_kernel convert_time_value_to_user

struct vm_cache_statistics {
    integer_t cache_object_count;
    integer_t cache_count;
    integer_t active_tmp_count;
    integer_t inactive_tmp_count;
    integer_t active_perm_count;
    integer_t inactive_perm_count;
    integer_t dirty_count;
    integer_t laundry_count;
    integer_t writeback_count;
    integer_t slab_count;
    integer_t slab_reclaim_count;
};
typedef struct vm_cache_statistics *vm_cache_statistics_t;
typedef struct vm_cache_statistics vm_cache_statistics_data_t;

struct vm_statistics {
    integer_t pagesize;
    integer_t free_count;
    integer_t active_count;
    integer_t inactive_count;
    integer_t wire_count;
    integer_t zero_fill_count;
    integer_t reactivations;
    integer_t pageins;
    integer_t pageouts;
    integer_t faults;
    integer_t cow_faults;
    integer_t lookups;
    integer_t hits;
};
typedef struct vm_statistics *vm_statistics_t;
typedef struct vm_statistics vm_statistics_data_t;

#define KERNEL_DEBUG_NAME_MAX (64)
typedef char kernel_debug_name_t[KERNEL_DEBUG_NAME_MAX];
typedef const char *const_kernel_debug_name_t;
typedef char symtab_name_t[32];

typedef int vm_prot_t;
#define VM_PROT_NONE ((vm_prot_t) 0)
#define VM_PROT_READ ((vm_prot_t) 0x01)
#define VM_PROT_WRITE ((vm_prot_t) 0x02)
#define VM_PROT_EXECUTE ((vm_prot_t) 0x04)
#define VM_PROT_DEFAULT (VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_NO_CHANGE ((vm_prot_t) 0x08)
#define VM_PROT_NOTIFY ((vm_prot_t) 0x10)

typedef int vm_inherit_t;
#define VM_INHERIT_SHARE ((vm_inherit_t) 0)
#define VM_INHERIT_COPY ((vm_inherit_t) 1)
#define VM_INHERIT_NONE ((vm_inherit_t) 2)
#define VM_INHERIT_DEFAULT VM_INHERIT_COPY

typedef int vm_sync_t;
#define VM_SYNC_ASYNCHRONOUS ((vm_sync_t) 0x01)
#define VM_SYNC_SYNCHRONOUS ((vm_sync_t) 0x02)
#define VM_SYNC_INVALIDATE ((vm_sync_t) 0x04)

typedef int vm_wire_t;
#define VM_WIRE_NONE 0
#define VM_WIRE_CURRENT 1
#define VM_WIRE_FUTURE 2
#define VM_WIRE_ALL (VM_WIRE_CURRENT | VM_WIRE_FUTURE)

typedef unsigned int vm_machine_attribute_t;
typedef int vm_machine_attribute_val_t;
#define MATTR_CACHE 1
#define MATTR_MIGRATE 2
#define MATTR_REPLICATE 4
#define MATTR_VAL_OFF 0
#define MATTR_VAL_ON 1
#define MATTR_VAL_GET 2
#define MATTR_VAL_CACHE_FLUSH 6
#define MATTR_VAL_DCACHE_FLUSH 7
#define MATTR_VAL_ICACHE_FLUSH 8

typedef unsigned int mach_port_ktype_t;
typedef unsigned int mach_port_mscount_t;
typedef unsigned int mach_port_msgcount_t;
typedef unsigned int mach_port_rights_t;
typedef mach_port_name_t *mach_port_name_array_t;
typedef mach_port_type_t *mach_port_type_array_t;
#define MACH_PORT_KTYPE_NONE 0
#define MACH_PORT_KTYPE_USER_DEVICE 28
#define MACH_PORT_QLIMIT_DEFAULT ((mach_port_msgcount_t) 5)

typedef struct mach_port_status {
    mach_port_name_t mps_pset;
    mach_port_seqno_t mps_seqno;
    mach_port_mscount_t mps_mscount;
    mach_port_msgcount_t mps_qlimit;
    mach_port_msgcount_t mps_msgcount;
    mach_port_rights_t mps_sorights;
    boolean_t mps_srights;
    boolean_t mps_pdrequest;
    boolean_t mps_nsrequest;
} mach_port_status_t;

typedef integer_t *host_info_t;
#define KERNEL_VERSION_MAX (512)
typedef char kernel_version_t[KERNEL_VERSION_MAX];
typedef integer_t *task_info_t;
typedef integer_t *thread_info_t;
typedef natural_t *thread_state_t;
typedef integer_t *processor_info_t;
typedef integer_t *processor_set_info_t;

typedef unsigned int dev_mode_t;
#define D_READ 0x1
#define D_WRITE 0x2
#define D_NODELAY 0x4
#define D_NOWAIT 0x8
typedef unsigned int dev_flavor_t;
typedef int *dev_status_t;
#define DEV_STATUS_MAX (1024)
typedef char dev_name_t[128];
typedef const char *const_dev_name_t;
typedef char *io_buf_ptr_t;
#define IO_INBAND_MAX (128)
typedef char io_buf_ptr_inband_t[IO_INBAND_MAX];
typedef long_natural_t recnum_t;
typedef rpc_long_natural_t rpc_recnum_t;
typedef unsigned short filter_t;
typedef filter_t *filter_array_t;

typedef struct time_value64 {
    int64_t seconds;
    int64_t nanoseconds;
} time_value64_t;

typedef ipc_port_t memory_object_t;
typedef memory_object_t *memory_object_array_t;
typedef int memory_object_copy_strategy_t;
#define MEMORY_OBJECT_COPY_NONE 0
#define MEMORY_OBJECT_COPY_CALL 1
#define MEMORY_OBJECT_COPY_DELAY 2
#define MEMORY_OBJECT_COPY_TEMPORARY 3
typedef int memory_object_return_t;
#define MEMORY_OBJECT_RETURN_NONE 0
#define MEMORY_OBJECT_RETURN_DIRTY 1
#define MEMORY_OBJECT_RETURN_ALL 2

typedef uint32_t vm_object_info_state_t;
typedef uint32_t vm_page_info_state_t;

typedef struct vm_region_info {
    rpc_vm_offset_t vri_start;
    rpc_vm_offset_t vri_end;
    vm_prot_t vri_protection;
    vm_prot_t vri_max_protection;
    vm_inherit_t vri_inheritance;
    unsigned int vri_wired_count;
    unsigned int vri_user_wired_count;
    rpc_vm_offset_t vri_object;
    rpc_vm_offset_t vri_offset;
    integer_t vri_needs_copy;
    unsigned int vri_sharing;
} vm_region_info_t;
typedef vm_region_info_t *vm_region_info_array_t;

typedef struct vm_object_info {
    rpc_vm_offset_t voi_object;
    rpc_vm_size_t voi_pagesize;
    rpc_vm_size_t voi_size;
    unsigned int voi_ref_count;
    unsigned int voi_resident_page_count;
    unsigned int voi_absent_count;
    rpc_vm_offset_t voi_copy;
    rpc_vm_offset_t voi_shadow;
    rpc_vm_offset_t voi_shadow_offset;
    rpc_vm_offset_t voi_paging_offset;
    memory_object_copy_strategy_t voi_copy_strategy;
    rpc_vm_offset_t voi_last_alloc;
    unsigned int voi_paging_in_progress;
    vm_object_info_state_t voi_state;
} vm_object_info_t;
typedef vm_object_info_t *vm_object_info_array_t;

typedef struct vm_page_info {
    rpc_vm_offset_t vpi_offset;
    rpc_vm_offset_t vpi_phys_addr;
    unsigned int vpi_wire_count;
    vm_prot_t vpi_page_lock;
    vm_prot_t vpi_unlock_request;
    vm_page_info_state_t vpi_state;
} vm_page_info_t;
typedef vm_page_info_t *vm_page_info_array_t;

typedef struct vm_page_phys_info {
    rpc_vm_offset_t vpi_offset;
    rpc_phys_addr_t vpi_phys_addr;
    unsigned int vpi_wire_count;
    vm_prot_t vpi_page_lock;
    vm_prot_t vpi_unlock_request;
    vm_page_info_state_t vpi_state;
} vm_page_phys_info_t;
typedef vm_page_phys_info_t *vm_page_phys_info_array_t;

#define CACHE_NAME_MAX_LEN 32
typedef struct cache_info {
    int flags;
    rpc_vm_size_t cpu_pool_size;
    rpc_vm_size_t obj_size;
    rpc_vm_size_t align;
    rpc_vm_size_t buf_size;
    rpc_vm_size_t slab_size;
    rpc_long_natural_t bufs_per_slab;
    rpc_long_natural_t nr_objs;
    rpc_long_natural_t nr_bufs;
    rpc_long_natural_t nr_slabs;
    rpc_long_natural_t nr_free_slabs;
    char name[CACHE_NAME_MAX_LEN];
} cache_info_t;
typedef cache_info_t *cache_info_array_t;

typedef struct hash_info_bucket {
    unsigned int hib_count;
} hash_info_bucket_t;
typedef hash_info_bucket_t *hash_info_bucket_array_t;

typedef const struct descriptor *const_descriptor_list_t;
typedef mach_port_t *processor_name_array_t;
typedef mach_port_t *processor_set_name_array_t;
typedef rpc_vm_offset_t *rpc_vm_offset_array_t;
typedef rpc_vm_size_t *rpc_vm_size_array_t;
typedef rpc_phys_addr_t *rpc_phys_addr_array_t;

#define IP_NULL ((ipc_port_t) 0)
#define IP_DEAD ((ipc_port_t) -1)
#define IP_VALID(port) (((port) != IP_NULL) && ((port) != IP_DEAD))

#define MACH_NOTIFY_FIRST 0100
#define MACH_NOTIFY_PORT_DELETED (MACH_NOTIFY_FIRST + 001)
#define MACH_NOTIFY_MSG_ACCEPTED (MACH_NOTIFY_FIRST + 002)
#define MACH_NOTIFY_PORT_DESTROYED (MACH_NOTIFY_FIRST + 005)
#define MACH_NOTIFY_NO_SENDERS (MACH_NOTIFY_FIRST + 006)
#define MACH_NOTIFY_SEND_ONCE (MACH_NOTIFY_FIRST + 007)
#define MACH_NOTIFY_DEAD_NAME (MACH_NOTIFY_FIRST + 010)
#define MACH_NOTIFY_LAST (MACH_NOTIFY_FIRST + 015)

typedef kern_return_t mach_msg_return_t;

typedef struct {
    mach_msg_header_t Head;
    mach_msg_type_t RetCodeType;
    kern_return_t RetCode;
} mig_reply_header_t;

void *memcpy(void *dest, const void *src, size_t n);
unsigned long strlen(const char *s);

void task_deallocate(task_t);
void thread_deallocate(thread_t);
void space_deallocate(ipc_space_t);
void pset_deallocate(processor_set_t);
void vm_map_deallocate(vm_map_t);
void vm_object_deallocate(vm_object_t);
void device_deallocate(device_t);
void io_perm_deallocate(io_perm_t);
void ipc_port_release_send(ipc_port_t);
boolean_t ipc_port_check_circularity(ipc_port_t, ipc_port_t);

task_t convert_port_to_task(ipc_port_t);
thread_t convert_port_to_thread(ipc_port_t);
vm_map_t convert_port_to_map(ipc_port_t);
ipc_space_t convert_port_to_space(ipc_port_t);
ipc_port_t convert_task_to_port(task_t);
ipc_port_t convert_thread_to_port(thread_t);
host_t convert_port_to_host(ipc_port_t);
host_t convert_port_to_host_priv(ipc_port_t);
ipc_port_t convert_host_to_port(host_t);
processor_t convert_port_to_processor(ipc_port_t);
processor_t convert_port_to_processor_name(ipc_port_t);
processor_set_t convert_port_to_pset(ipc_port_t);
processor_set_t convert_port_to_pset_name(ipc_port_t);
ipc_port_t convert_pset_to_port(processor_set_t);
ipc_port_t convert_pset_name_to_port(processor_set_t);
ipc_port_t convert_device_to_port(device_t);
io_perm_t convert_port_to_io_perm(ipc_port_t);
ipc_port_t convert_io_perm_to_port(io_perm_t);
vm_object_t vm_object_lookup(ipc_port_t);
vm_object_t vm_object_lookup_name(ipc_port_t);
device_t dev_port_lookup(ipc_port_t);

mach_msg_return_t mach_msg_send_from_kernel(
    mach_msg_header_t *msg, mach_msg_size_t send_size);
mach_msg_return_t mach_msg_rpc_from_kernel(
    const mach_msg_header_t *msg, mach_msg_size_t send_size,
    mach_msg_size_t reply_size);
void mig_dealloc_reply_port(mach_port_t);

#endif
