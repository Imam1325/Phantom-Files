/*
 * Phantom eBPF filesystem sensor — BPF LSM + tracepoints.
 *
 * Architecture:
 *   LSM_PROBE(file_open) — attaches to the security_file_open LSM hook.
 *   Runs IN-KERNEL before the file descriptor is created.
 *   Checks the file's inode against a BPF hash map of trap inodes.
 *   Returns -EACCES to block, 0 to allow.
 *
 * Why BPF LSM (not kprobe + bpf_override_return):
 *   - Stable ABI: LSM hooks are part of the kernel security API, they
 *     don't change between kernel versions (unlike kprobe on internal symbols).
 *   - No CONFIG_BPF_KPROBE_OVERRIDE needed — LSM programs natively return
 *     errno to deny operations.
 *   - Proper security framework: designed for access control, not debugging.
 *   - Sub-microsecond latency for non-trap files (single hash map lookup).
 *
 * Requirements:
 *   - Kernel >= 5.7
 *   - CONFIG_BPF_LSM=y
 *   - "bpf" in LSM list: lsm=lockdown,capability,landlock,yama,apparmor,bpf
 *   - BCC (python3-bpfcc) with LSM support
 *
 * Maps (populated by userspace ebpf.py):
 *   ph_trap_inodes  — hash map: inode -> trap_id_hash. O(1) kernel-side filter.
 *   ph_trap_devs    — hash map: device_id -> 1. Skip non-trap filesystems.
 *   ph_block_mode   — array[1]: 1 = active (deny), 0 = observation (allow + log).
 *   ph_whitelist    — hash map: UID -> 1. Never block daemon/system UIDs.
 *   ph_stats        — per-CPU array[4]: counters for observability.
 */

#include <linux/sched.h>

#define PH_PATH_LEN    256
#define PH_MAX_TRAPS   4096

enum ph_event_type {
    PH_EVT_OPEN    = 1,
    PH_EVT_ACCESS  = 2,
    PH_EVT_DELETE  = 3,
    PH_EVT_RENAME  = 4,
    PH_EVT_ATTRIB  = 5,
    PH_EVT_CHOWN   = 6,
    PH_EVT_WRITE   = 7,
    PH_EVT_MODIFY  = 8,
};

struct ph_event_t {
    u64 ts_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 event_type;
    s32 fd;
    u32 flags;
    u64 inode;
    u64 dev;
    char comm[TASK_COMM_LEN];
    char path[PH_PATH_LEN];
};

/*
 * ph_trap_inodes — kernel-side trap lookup table.
 *   key:   inode number (u64)
 *   value: trap_id hash (u64), non-zero = trap file
 *
 * Populated by userspace: for each trap file, stat() -> inode -> map_update.
 * Lookup cost: O(1) hash map — zero overhead for non-trap files.
 */
BPF_HASH(ph_trap_inodes, u64, u64, PH_MAX_TRAPS);

/*
 * ph_trap_devs — device filter (multi-filesystem support).
 *   key: device id (u64), value: 1
 *   If device has no traps, skip inode lookup entirely.
 */
BPF_HASH(ph_trap_devs, u64, u64, 64);

/*
 * ph_block_mode — blocking flag.
 *   key=0, value: 1 = active (deny access), 0 = observation (allow + log).
 *   Controlled by userspace RunMode.
 */
BPF_ARRAY(ph_block_mode, u64, 1);

/*
 * ph_whitelist — UIDs to never block.
 *   key: UID (u32), value: 1
 *   Used for daemon UID, root services, backup tools.
 */
BPF_HASH(ph_whitelist, u32, u32, 256);

/*
 * ph_stats — per-CPU observability counters.
 *   [0] = events submitted to userspace
 *   [1] = accesses blocked (EACCES returned)
 *   [2] = trap inode hits
 *   [3] = early returns (no trap match)
 */
BPF_PERCPU_ARRAY(ph_stats, u64, 4);

BPF_PERF_OUTPUT(events);


/* ---------- helpers ---------- */

static __always_inline void inc_stat(int idx) {
    u64 *val = ph_stats.lookup(&idx);
    if (val)
        (*val)++;
}

static __always_inline int blocking_enabled(void) {
    int key = 0;
    u64 *val = ph_block_mode.lookup(&key);
    return val && *val;
}

static __always_inline int uid_whitelisted(u32 uid) {
    return ph_whitelist.lookup(&uid) != NULL;
}


/* ================================================================
 * LSM_PROBE(file_open) — the core of Phantom's eBPF blocking.
 *
 * Called by the kernel LSM framework BEFORE a file is opened.
 * Return value:
 *   0       — allow the open
 *   -EACCES — deny the open (process gets "Permission denied")
 *
 * Flow:
 *   1. Read inode + device from struct file.
 *   2. Check ph_trap_devs (fast: skip if no traps on this device).
 *   3. Check ph_trap_inodes (O(1) hash lookup).
 *   4. If no match → return 0 (allow, zero overhead).
 *   5. If match:
 *      a. Check ph_whitelist (allow daemon's own UID).
 *      b. Submit ph_event_t to userspace via perf buffer.
 *      c. If ph_block_mode[0] == 1 → return -EACCES (block).
 *      d. Else → return 0 (observation: log but allow).
 * ================================================================
 */
LSM_PROBE(file_open, struct file *file, int ret) {
    if (ret != 0)
        return ret;

    /* Read inode number */
    struct inode *f_inode = NULL;
    bpf_probe_read_kernel(&f_inode, sizeof(f_inode), &file->f_inode);
    if (!f_inode)
        return 0;

    u64 ino = 0;
    bpf_probe_read_kernel(&ino, sizeof(ino), &f_inode->i_ino);
    if (ino == 0)
        return 0;

    /* Read device id: inode->i_sb->s_dev */
    struct super_block *i_sb = NULL;
    bpf_probe_read_kernel(&i_sb, sizeof(i_sb), &f_inode->i_sb);
    u64 dev = 0;
    if (i_sb) {
        u32 s_dev = 0;
        bpf_probe_read_kernel(&s_dev, sizeof(s_dev), &i_sb->s_dev);
        dev = (u64)s_dev;
    }

    /* Fast path: skip devices with no traps */
    if (ph_trap_devs.lookup(&dev) == NULL) {
        inc_stat(3);
        return 0;
    }

    /* Check if this inode is a trap */
    u64 *trap_id = ph_trap_inodes.lookup(&ino);
    if (trap_id == NULL) {
        inc_stat(3);
        return 0;
    }
    inc_stat(2);  /* trap hit */

    /* Whitelist check: never block daemon/system UIDs */
    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid      = (u32)uid_gid;
    if (uid_whitelisted(uid))
        return 0;

    /* Build event for userspace */
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct ph_event_t event = {};
    event.ts_ns      = bpf_ktime_get_ns();
    event.pid        = (u32)pid_tgid;
    event.tgid       = (u32)(pid_tgid >> 32);
    event.uid        = uid;
    event.event_type = PH_EVT_OPEN;
    event.fd         = -1;
    event.flags      = 0;
    event.inode      = ino;
    event.dev        = dev;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Best-effort path from dentry */
    struct dentry *dentry = NULL;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (dentry) {
        struct qstr d_name = {};
        bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (d_name.name)
            bpf_probe_read_kernel_str(&event.path, sizeof(event.path), d_name.name);
    }

    inc_stat(0);
    events.perf_submit(ctx, &event, sizeof(event));

    /* Block or allow based on mode */
    if (blocking_enabled()) {
        inc_stat(1);
        return -EACCES;
    }

    return 0;
}


/* ================================================================
 * Tracepoints — telemetry for write/delete/rename/chmod/chown.
 *
 * These fire on ALL syscalls (not just trap files), so userspace
 * does path filtering via TrapRegistry.lookup().
 * Used for enrichment: "the attacker also tried to delete the trap",
 * "wrote to adjacent files", etc.
 * ================================================================
 */

#define O_ACCMODE 00000003
#define O_WRONLY  00000001
#define O_RDWR    00000002
#define O_CREAT   00000100
#define O_TRUNC   00001000

struct ph_open_how {
    u64 flags;
    u64 mode;
    u64 resolve;
};

static __always_inline u32 classify_open_flags(int flags) {
    int access = flags & O_ACCMODE;
    if (access == O_WRONLY || access == O_RDWR)
        return PH_EVT_WRITE;
    if ((flags & O_TRUNC) || (flags & O_CREAT))
        return PH_EVT_MODIFY;
    return PH_EVT_OPEN;
}

static __always_inline int submit_path_event(
    void *ctx, const char *filename, u32 event_type, s32 fd, u32 flags
) {
    if (filename == NULL)
        return 0;

    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid      = (u32)uid_gid;

    /* Skip whitelisted UIDs to reduce overhead */
    if (uid_whitelisted(uid))
        return 0;

    struct ph_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    event.ts_ns      = bpf_ktime_get_ns();
    event.pid        = (u32)pid_tgid;
    event.tgid       = (u32)(pid_tgid >> 32);
    event.uid        = uid;
    event.event_type = event_type;
    event.fd         = fd;
    event.flags      = flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);

    inc_stat(0);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

static __always_inline int submit_fd_event(void *ctx, s32 fd, u32 event_type) {
    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid      = (u32)uid_gid;

    /* Skip whitelisted UIDs to reduce overhead */
    if (uid_whitelisted(uid))
        return 0;

    struct ph_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    event.ts_ns      = bpf_ktime_get_ns();
    event.pid        = (u32)pid_tgid;
    event.tgid       = (u32)(pid_tgid >> 32);
    event.uid        = uid;
    event.event_type = event_type;
    event.fd         = fd;
    event.flags      = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    inc_stat(0);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 event_type = classify_open_flags((int)args->flags);
    return submit_path_event(args, (const char *)args->filename, event_type, -1, (u32)args->flags);
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    struct ph_open_how how = {};
    bpf_probe_read_user(&how, sizeof(how), (void *)args->how);
    return submit_path_event(args, (const char *)args->filename, classify_open_flags((int)how.flags), -1, (u32)how.flags);
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    return submit_fd_event(args, (s32)args->fd, PH_EVT_WRITE);
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    return submit_fd_event(args, (s32)args->fd, PH_EVT_WRITE);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    return submit_path_event(args, (const char *)args->pathname, PH_EVT_DELETE, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    return submit_path_event(args, (const char *)args->pathname, PH_EVT_DELETE, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    return submit_path_event(args, (const char *)args->oldname, PH_EVT_RENAME, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return submit_path_event(args, (const char *)args->oldname, PH_EVT_RENAME, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    return submit_path_event(args, (const char *)args->filename, PH_EVT_ATTRIB, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    return submit_path_event(args, (const char *)args->filename, PH_EVT_ATTRIB, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchownat) {
    return submit_path_event(args, (const char *)args->filename, PH_EVT_CHOWN, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_chown) {
    return submit_path_event(args, (const char *)args->filename, PH_EVT_CHOWN, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
    return submit_path_event(args, (const char *)args->path, PH_EVT_MODIFY, -1, 0);
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
    return submit_fd_event(args, (s32)args->fd, PH_EVT_MODIFY);
}
