/*
 * Audit and filter SELinux access queries that probe Magisk contexts.
 *
 * The safe point for transaction queries is the selinuxfs write_op table,
 * where /sys/fs/selinux/access and /sys/fs/selinux/context still have the
 * original query text.  procattr writes are filtered at security_setprocattr().
 * Returning -EINVAL for Magisk contexts matches the clean-policy behavior
 * where the Magisk type/context does not exist.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fs.h>
#include <security.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

KPM_NAME("selinux_magisk_access_filter");
KPM_VERSION("1.1.2");
KPM_LICENSE("All rights reserved.");
KPM_AUTHOR("Admire");
KPM_DESCRIPTION("Audit and reject Magisk /sys/fs/selinux/access probes");

#define ACCESS_SAMPLE_MAX 256
#define ACCESS_PROBE_SLOTS 32
#define SELINUX_POLICYDB_FALLBACK_OFFSET sizeof(void *)
#define CLEAN_POLICYDB_ALLOC_SIZE 0x4000
#define SELINUX_LEGACY_BLOB_QUERY_MAX VERSION(4, 15, 0)
#define SELINUX_BLOB_ROUTE_MIN VERSION(5, 3, 0)
#define SELINUX_BLOB_ROUTE_MAX VERSION(6, 2, 0)
#define contains_case_literal(s, len, lit) contains_case_lit((s), (len), (lit), sizeof(lit) - 1)

#define MAGISK_MOCK_POLICY_PATH "/dev/.magisk_selinux_mock/load"
#define MAGISK_MOCK_POLICY_MAX_SIZE (8 * 1024 * 1024)
#define CLEAN_EVAL_SCOPE_SLOTS 8
#define STATUS_READ_SCOPE_SLOTS 8
#define SEL_WRITE_OP_CONTEXT 5
#define SEL_WRITE_OP_ACCESS 6
#define SELINUX_STATUS_SIZE 20
#define SELINUX_STATUS_CLEAN_SEQUENCE 4
#define SELINUX_STATUS_CLEAN_POLICYLOAD 1

#define selinux_hook_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)

static void *g_funcs[16];
static int g_hooks;
struct file;
static long (*copy_from_kernel_nofault_fn)(void *dst, const void *src, size_t size);
static long (*copy_to_user_nofault_fn)(void __user *dst, const void *src, size_t size);
static unsigned long (*copy_to_user_raw_fn)(void __user *dst, const void *src, unsigned long size);
static const char *g_copy_to_user_name;
static int (*security_read_policy_fn)(void **data, size_t *len);
static int (*security_read_policy_compat_fn)(void *state, void **data, size_t *len);
static int (*security_load_policy_fn)(void *data, size_t len, struct selinux_load_state *load_state);
static int (*security_load_policy_compat_fn)(void *state, void *data, size_t len,
                                             struct selinux_load_state *load_state);
static int (*security_context_to_sid_fn)(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
static int (*security_context_to_sid_compat_fn)(void *state, const char *scontext, u32 scontext_len,
                                                u32 *out_sid, gfp_t gfp);
struct policydb;
struct policy_file {
    char *data;
    size_t len;
};

struct flex_array;
struct hashtab;

struct symtab {
    struct hashtab *table;
    u32 nprim;
};

enum {
    SELINUX_EBITMAP_NODE_SIZE = 64,
    SELINUX_EBITMAP_UNIT_BITS = sizeof(unsigned long) * 8,
    SELINUX_EBITMAP_UNIT_NUMS =
        (SELINUX_EBITMAP_NODE_SIZE - sizeof(void *) - sizeof(u32)) /
        sizeof(unsigned long),
};

struct ebitmap_node {
    struct ebitmap_node *next;
    unsigned long maps[SELINUX_EBITMAP_UNIT_NUMS];
    u32 startbit;
};

struct ebitmap {
    struct ebitmap_node *node;
    u32 highbit;
};

struct mls_level {
    u32 sens;
    struct ebitmap cat;
};

struct mls_range {
    struct mls_level level[2];
};

struct context {
    u32 user;
    u32 role;
    u32 type;
    u32 len;
    struct mls_range range;
    char *str;
    u32 hash;
};

struct constraint_expr {
    u32 expr_type;
    u32 attr;
    u32 op;
    struct ebitmap names;
    struct type_set *type_names;
    struct constraint_expr *next;
};

struct constraint_node {
    u32 permissions;
    struct constraint_expr *expr;
    struct constraint_node *next;
};

struct common_datum {
    u32 value;
    struct symtab permissions;
};

struct class_datum {
    u32 value;
    char *comkey;
    struct common_datum *comdatum;
    struct symtab permissions;
    struct constraint_node *constraints;
    struct constraint_node *validatetrans;
    char default_user;
    char default_role;
    char default_type;
    char default_range;
};

struct role_datum {
    u32 value;
    u32 bounds;
    struct ebitmap dominates;
    struct ebitmap types;
};

struct role_trans {
    u32 role;
    u32 type;
    u32 tclass;
    u32 new_role;
    struct role_trans *next;
};

struct filename_trans {
    u32 stype;
    u32 ttype;
    u16 tclass;
    const char *name;
};

struct role_allow {
    u32 role;
    u32 new_role;
    struct role_allow *next;
};

struct type_datum {
    u32 value;
    u32 bounds;
    unsigned char primary;
    unsigned char attribute;
};

struct user_datum {
    u32 value;
    u32 bounds;
    struct ebitmap roles;
    struct mls_range range;
    struct mls_level dfltlevel;
};

struct level_datum {
    struct mls_level *level;
    unsigned char isalias;
};

struct cat_datum {
    u32 value;
    unsigned char isalias;
};

struct range_trans {
    u32 source_type;
    u32 target_type;
    u32 target_class;
};

struct cond_bool_datum {
    u32 value;
    int state;
};

struct cond_node;

struct type_set {
    struct ebitmap types;
    struct ebitmap negset;
    u32 flags;
};

struct ocontext {
    union {
        char *name;
        struct {
            u8 protocol;
            u16 low_port;
            u16 high_port;
        } port;
        struct {
            u32 addr;
            u32 mask;
        } node;
        struct {
            u32 addr[4];
            u32 mask[4];
        } node6;
        struct {
            u64 subnet_prefix;
            u16 low_pkey;
            u16 high_pkey;
        } ibpkey;
        struct {
            char *dev_name;
            u8 port;
        } ibendport;
    } u;
    union {
        u32 sclass;
        u32 behavior;
    } v;
    struct context context[2];
    u32 sid[2];
    struct ocontext *next;
};

struct genfs {
    char *fstype;
    struct ocontext *head;
    struct genfs *next;
};

struct avtab_key {
    u16 source_type;
    u16 target_type;
    u16 target_class;
    u16 specified;
};

#define AVTAB_ALLOWED 0x0001
#define AVTAB_AUDITALLOW 0x0002
#define AVTAB_AUDITDENY 0x0004
#define AVTAB_AV (AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY)
#define AVTAB_XPERMS_ALLOWED 0x0100
#define AVTAB_XPERMS_AUDITALLOW 0x0200
#define AVTAB_XPERMS_DONTAUDIT 0x0400
#define AVTAB_XPERMS (AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT)
#define AVTAB_XPERMS_IOCTLFUNCTION 0x01
#define AVTAB_XPERMS_IOCTLDRIVER 0x02

struct avtab_extended_perms {
    u8 specified;
    u8 driver;
    struct extended_perms_data perms;
};

struct avtab_datum {
    union {
        u32 data;
        struct avtab_extended_perms *xperms;
    } u;
};

struct avtab_node {
    struct avtab_key key;
    struct avtab_datum datum;
    struct avtab_node *next;
};

struct avtab {
    struct flex_array *htable;
    u32 nel;
    u32 nslot;
    u32 mask;
};

#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES 2
#define SYM_TYPES 3
#define SYM_USERS 4
#define SYM_BOOLS 5
#define SYM_LEVELS 6
#define SYM_CATS 7
#define SYM_NUM 8
#define OCON_ISID 0
#define OCON_FS 1
#define OCON_PORT 2
#define OCON_NETIF 3
#define OCON_NODE 4
#define OCON_FSUSE 5
#define OCON_NODE6 6
#define OCON_IBPKEY 7
#define OCON_IBENDPORT 8
#define OCON_NUM 9

struct policydb {
    int mls_enabled;
    int android_netlink_route;
    int android_netlink_getneigh;
    struct symtab symtab[SYM_NUM];
    struct flex_array *sym_val_to_name[SYM_NUM];
    struct class_datum **class_val_to_struct;
    struct role_datum **role_val_to_struct;
    struct user_datum **user_val_to_struct;
    struct flex_array *type_val_to_struct_array;
    struct avtab te_avtab;
    struct role_trans *role_tr;
    struct ebitmap filename_trans_ttypes;
    struct hashtab *filename_trans;
    struct cond_bool_datum **bool_val_to_struct;
    struct avtab te_cond_avtab;
    struct cond_node *cond_list;
    struct role_allow *role_allow;
    struct ocontext *ocontexts[OCON_NUM];
    struct genfs *genfs;
    struct hashtab *range_tr;
    struct flex_array *type_attr_map_array;
    struct ebitmap policycaps;
    struct ebitmap permissive_map;
    size_t len;
    unsigned int policyvers;
    unsigned int reject_unknown : 1;
    unsigned int allow_unknown : 1;
    u16 process_class;
    u32 process_trans_perms;
};

static int (*policydb_read_fn)(struct policydb *policydb, struct policy_file *fp);
static void (*policydb_destroy_fn)(struct policydb *policydb);
static void *(*flex_array_get_fn)(struct flex_array *fa, unsigned int element_nr);
static struct avtab_node *(*avtab_search_node_fn)(struct avtab *h, struct avtab_key *key);
static struct avtab_node *(*avtab_search_node_next_fn)(struct avtab_node *node, int specified);
static void (*cond_compute_av_fn)(struct avtab *ctab, struct avtab_key *key,
                                  struct av_decision *avd, struct extended_perms *xperms);
static int (*constraint_expr_eval_fn)(struct policydb *policydb,
                                      struct context *scontext,
                                      struct context *tcontext,
                                      struct context *xcontext,
                                      struct constraint_expr *cexpr);
static void (*type_attribute_bounds_av_fn)(struct policydb *policydb,
                                           struct context *scontext,
                                           struct context *tcontext,
                                           u16 tclass,
                                           struct av_decision *avd);
static void (*selinux_policy_cancel_fn)(struct selinux_load_state *load_state);
static void (*selinux_policy_cancel_compat_fn)(void *state, struct selinux_load_state *load_state);
struct sidtab;
static void (*sidtab_cancel_convert_fn)(struct sidtab *sidtab);
static void *(*vmalloc_fn)(unsigned long size);
static void (*vfree_fn)(const void *addr);
static struct task_struct *init_task_ptr;
static struct file *(*filp_open_fn)(const char *filename, int flags, umode_t mode);
static int (*filp_close_fn)(struct file *filp, fl_owner_t id);
static ssize_t (*kernel_read_fn)(struct file *file, void *buf, size_t count, loff_t *pos);
static loff_t (*vfs_llseek_fn)(struct file *file, loff_t offset, int whence);
static void *g_selinux_state;

static bool g_selinux_ready;
static bool g_dirty_policy_seen;
static void *g_first_policydb;
static u32 g_clean_access_count;
static u32 g_policy_read_count;
static void *g_clean_policy_blob;
static size_t g_clean_policy_len;
static bool g_clean_policy_has_magisk;
static struct selinux_load_state g_clean_load_state;
static bool g_clean_load_state_ready;
static bool g_clean_policydb_direct;
static bool g_clean_sidtab_convert_canceled;
static void *g_clean_policydb;
static void *g_first_policy;
static size_t g_policydb_offset;
static u32 g_clean_eval_depth;
static u32 g_bypass_access_log_count;
static u32 g_bypass_context_log_count;

/* Cached vmalloc copy of g_clean_policy_blob shared by every reader.
 * Snapshot runs once at module init, so the source pointer is effectively
 * immutable — the cache is reused on every hit and only re-vmalloc'd when
 * the source pointer changes.  Guarded by g_policy_cache_lock. */
static void *g_policy_read_cache;
static size_t g_policy_read_cache_len;
static void *g_policy_read_cache_src;
static raw_spinlock_t g_policy_cache_lock = { .raw_lock = ATOMIC_INIT(0) };
static u32 g_bypass_policy_log_count;
static u32 g_internal_policy_load_depth;
static u32 g_procattr_current_count;
static u32 g_setprocattr_probe_count;
static u32 g_selinux_setprocattr_probe_count;
static bool g_clean_policydb_av_disabled;
static bool g_policydb_offset_fallback_warned;
static u32 g_status_read_count;
static u32 g_status_probe_count;
static u32 g_status_redirect_count;
static bool g_simple_read_from_buffer_hooked;

struct access_probe {
    u32 id;
    uid_t uid;
    const char *node;
    char query[ACCESS_SAMPLE_MAX];
};

struct clean_eval_scope {
    void *task;
    u32 depth;
};

struct status_read_scope {
    void *task;
    u32 depth;
    u32 patched;
};

static struct access_probe g_probes[ACCESS_PROBE_SLOTS];
static struct clean_eval_scope g_clean_eval_scopes[CLEAN_EVAL_SCOPE_SLOTS];
static struct status_read_scope g_status_read_scopes[STATUS_READ_SCOPE_SLOTS];
static unsigned char g_clean_status_bytes[SELINUX_STATUS_SIZE];

/* Spinlock guards for the scope arrays.  We do not use DEFINE_SPINLOCK +
 * spin_lock() because the running kernel on this device does not export
 * _raw_spin_lock/_raw_spin_unlock through the kfunc ksymtab; the wrapper
 * expands to kf__raw_spin_lock/unknown.  Resolve the raw helpers via
 * kallsyms at init (mirroring vmalloc/vfree/etc.) and call them through
 * a function pointer, matching the convention used elsewhere in this
 * module. */
typedef void (*raw_spin_lock_fn_t)(raw_spinlock_t *lock);
typedef void (*raw_spin_unlock_fn_t)(raw_spinlock_t *lock);
static raw_spin_lock_fn_t g_raw_spin_lock_fn;
static raw_spin_unlock_fn_t g_raw_spin_unlock_fn;
static raw_spinlock_t g_scopes_lock = { .raw_lock = ATOMIC_INIT(0) };

static bool contains_magisk(const char *s, size_t len);
static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len);
static bool dirtysepolicy_context_should_hide(const char *query);
static bool dirtysepolicy_access_should_deny(const char *query, size_t len);
static bool clean_context_exists(const char *query);
static bool legacy_clean_query_should_block(const char *query, size_t len, bool access_query);
static bool legacy_should_block_access_query(const char *query, size_t len);
static int clean_policy_context_to_sid(const char *query, u32 *out_sid);
static void refresh_clean_policydb(const char *reason, bool allow_fallback);
static bool should_bypass_clean_filter(uid_t uid);
static const char *current_comm(void);
static bool current_is_policy_manager(void);
static bool should_log_live_bypass(uid_t uid);
static void log_bypass_once(const char *node, uid_t uid, const char *query);
static void cancel_clean_sidtab_convert(const char *reason);
static bool use_clean_blob_route(void);
static bool use_legacy_clean_blob_query(void);
static bool clean_policydb_redirect_supported(void);
static bool selinux_compat_call_needed(void);
static bool policydb_offset_fallback_allowed(void);
static bool write_op_slot_fallback_allowed(void);
static bool security_setprocattr_has_lsm_arg(void);
static void resolve_required_symbols_once(void);
static void *lookup_name_optional_suffix(const char *base);
static void log_symbol_addr(const char *name, const void *addr);
static void zero_bytes(void *dst, size_t len);
static int call_security_read_policy(void **data, size_t *len);
static int call_security_load_policy(void *data, size_t len, struct selinux_load_state *load_state);
static void call_selinux_policy_cancel(struct selinux_load_state *load_state);
static int call_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp);
static bool context_struct_compute_av_intel(struct policydb *policydb,
                                            struct context *scontext,
                                            struct context *tcontext,
                                            u16 tclass,
                                            struct av_decision *avd,
                                            struct extended_perms *xperms);
static bool magiskinit_process_exists(void);
static bool try_snapshot_mock_policy(const char *reason);
static void try_load_clean_policydb_from_blob(const char *reason);
static bool filter_procattr_current(const char *hook, const char *lsm,
                                    const char *name, const void *value,
                                    size_t size);
static void before_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u);
static void after_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u);
static void before_context_struct_compute_av_legacy(hook_fargs5_t *a, void *u);
static void before_sel_read_handle_status(hook_fargs4_t *a, void *u);
static void after_sel_read_handle_status(hook_fargs4_t *a, void *u);
static void before_simple_read_from_buffer(hook_fargs5_t *a, void *u);
static void after_simple_read_from_buffer(hook_fargs5_t *a, void *u);
static bool enter_status_read_scope(void);
static void leave_status_read_scope(void);
static bool current_in_status_read_scope(void);
static void mark_status_read_scope_patched(void);
static bool current_status_read_scope_patched(void);
static bool enter_clean_eval_scope(void);
static void leave_clean_eval_scope(void);
static bool current_in_clean_eval_scope(void);
static int install_write_op_hooks(void);
static void uninstall_write_op_hooks(void);
static void uninstall_inline_hooks(void);
static void after_sel_mmap_handle_status(hook_fargs2_t *a, void *u);
static void before_selinux_status_update_seqlock(hook_fargs4_t *a, void *u);
static void before_selinux_status_update_policyload(hook_fargs4_t *a, void *u);

/*
 * Patch the seqno field (5th whitespace-separated token, formatted as "%u")
 * in a /sys/fs/selinux/access response buffer to new_seqno.
 * Format: "%x %x %x %x %u %x"
 * Returns the new length (may differ if decimal widths differ).
 */
static ssize_t patch_response_seqno(char *buf, ssize_t ret, u32 new_seqno)
{
    char *p = buf;
    char *end = buf + ret;
    char *tok_start;
    char new_str[12];
    int ns_len;
    int tok;
    ssize_t diff;

    if (ret <= 0 || !buf)
        return ret;

    /* Skip 4 space-separated tokens to reach the 5th (seqno) */
    for (tok = 0; tok < 4; tok++) {
        while (p < end && *p == ' ') p++;
        while (p < end && *p != ' ') p++;
    }
    while (p < end && *p == ' ') p++;
    tok_start = p;
    while (p < end && *p != ' ' && *p != '\0' && *p != '\n') p++;

    if (tok_start >= p)
        return ret;

    /* Render new_seqno as decimal */
    {
        u32 v = new_seqno;
        int i = 0;
        char tmp[12];
        if (v == 0) {
            new_str[0] = '0';
            ns_len = 1;
        } else {
            while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
            for (ns_len = 0; ns_len < i; ns_len++)
                new_str[ns_len] = tmp[i - 1 - ns_len];
        }
    }

    diff = (ssize_t)ns_len - (ssize_t)(p - tok_start);
    if (diff != 0) {
        /* Shift the remainder of the string left or right */
        char *dst = tok_start + ns_len;
        char *src = p;
        size_t move = (size_t)(end - src);
        int j;
        if (diff < 0) {
            for (j = 0; j < (int)move; j++) dst[j] = src[j];
        } else {
            for (j = (int)move - 1; j >= 0; j--) dst[j] = src[j];
        }
        ret += diff;
    }

    {
        int k;
        for (k = 0; k < ns_len; k++)
            tok_start[k] = new_str[k];
    }
    return ret;
}

static void copy_bytes(void *dst, const void *src, size_t len)
{
    size_t i;
    char *d = (char *)dst;
    const char *s = (const char *)src;

    if (!d || !s)
        return;

    for (i = 0; i < len; i++)
        d[i] = s[i];
}

static void zero_bytes(void *dst, size_t len)
{
    size_t i;
    volatile char *d = (volatile char *)dst;

    if (!d)
        return;

    for (i = 0; i < len; i++)
        d[i] = 0;
}

static int copy_status_to_user(void __user *dst, const void *src, size_t len)
{
    int copied;

    if (copy_to_user_nofault_fn)
        return copy_to_user_nofault_fn(dst, src, len) ? -EFAULT : 0;

    if (copy_to_user_raw_fn)
        return copy_to_user_raw_fn(dst, src, len) ? -EFAULT : 0;

    copied = compat_copy_to_user(dst, src, (int)len);
    return copied == (int)len ? 0 : -EFAULT;
}

static void put_u32_le(unsigned char *dst, u32 value)
{
    if (!dst)
        return;

    dst[0] = (unsigned char)(value & 0xff);
    dst[1] = (unsigned char)((value >> 8) & 0xff);
    dst[2] = (unsigned char)((value >> 16) & 0xff);
    dst[3] = (unsigned char)((value >> 24) & 0xff);
}

static u32 get_u32_le(const unsigned char *src)
{
    if (!src)
        return 0;

    return (u32)src[0] |
           ((u32)src[1] << 8) |
           ((u32)src[2] << 16) |
           ((u32)src[3] << 24);
}

static void fill_clean_status_bytes(unsigned char *status)
{
    u32 seq, pload;

    if (!status)
        return;

    /* kernel >= 6.6: detection expects sequence=4 policyload=1
     * kernel <  6.6: detection expects sequence=0 policyload=0
     * (Java isNewKernel() uses >= 6.10 as threshold, we use 6.6 to
     *  be safe and avoid false positives on kernels in between)
     */
    if (kver >= VERSION(6, 7, 0)) {
        seq   = SELINUX_STATUS_CLEAN_SEQUENCE;
        pload = SELINUX_STATUS_CLEAN_POLICYLOAD;
    } else {
        seq   = 0;
        pload = 0;
    }

    zero_bytes(status, SELINUX_STATUS_SIZE);
    put_u32_le(status + 0,  1);
    put_u32_le(status + 4,  seq);
    put_u32_le(status + 8,  1);    /* enforcing — always 1 */
    put_u32_le(status + 12, pload);
    put_u32_le(status + 16, 1);
}

static bool buffer_contains_magisk(const char *buf, size_t len)
{
    return contains_magisk(buf, len);
}

static bool ascii_lower_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
        a = a - 'A' + 'a';
    if (b >= 'A' && b <= 'Z')
        b = b - 'A' + 'a';
    return a == b;
}

static bool str_eq_lit(const char *s, const char *lit)
{
    size_t i;

    if (!s || !lit)
        return false;

    for (i = 0; lit[i]; i++) {
        if (s[i] != lit[i])
            return false;
    }

    return s[i] == '\0';
}

static const char *current_comm(void)
{
    if (task_struct_offset.comm_offset <= 0)
        return "?";

    return get_task_comm(current) ?: "?";
}

static bool should_bypass_clean_filter(uid_t uid)
{
    if (uid < 10000)
        return true;

    /*
     * Let the policy management path see and write the live policy.  Otherwise
     * magiskpolicy/apd may read the clean snapshot as its baseline and lose
     * rules it is trying to install.
     */
    return current_is_policy_manager();
}

static bool should_log_live_bypass(uid_t uid)
{
    return uid >= 10000 || current_is_policy_manager();
}

static bool use_clean_blob_route(void)
{
    return kver >= SELINUX_BLOB_ROUTE_MIN && kver < SELINUX_BLOB_ROUTE_MAX;
}

static bool use_legacy_clean_blob_query(void)
{
    return kver < SELINUX_LEGACY_BLOB_QUERY_MAX;
}

static bool clean_policydb_redirect_supported(void)
{
    /*
     * 4.14 reference basis:
     *   - https://github.com/balgxmr/kernel_xiaomi_cepheus/tree/sixteen
     *   - https://github.com/LineageOS/android_kernel_xiaomi_sm8150/tree/lineage-22.2
     *   - https://android.googlesource.com/kernel/common/+/refs/heads/deprecated/android-4.14-stable
     *
     * Relevant source paths:
     *   - security/selinux/ss/services.c
     *       context_struct_compute_av(struct policydb *policydb, ...)
     *       security_read_policy(struct selinux_state *state, ...)
     *       security_context_to_sid(struct selinux_state *state, ...)
     *       security_load_policy(struct selinux_state *state, ...)
     *   - security/selinux/selinuxfs.c
     *       sel_write_access(), sel_write_context(), write_op[]
     *
     * 这里的 4.14 适配不是单纯按 kver 猜 ABI，而是用上述 cepheus/sm8150
     * 4.14 源码确认 SELinux helper 的真实签名。只要运行时能解析到
     * selinux_state，就认为它符合这组 4.14 stateful SELinux 布局；否则
     * 回退到更保守的 legacy 路径，避免把 policydb 参数强套到未知布局上。
     *
     * The Xiaomi sm8150/cepheus 4.14 lineage keeps selinux_state and also uses
     * the policydb-argument context_struct_compute_av() signature.  Therefore
     * selinux_state is the runtime confidence signal for using the 4.14
     * stateful SELinux helper signatures and the 6-argument policydb redirect
     * path.  Kernels older than this baseline stay on the pure legacy route.
     */
    return !use_legacy_clean_blob_query() || g_selinux_state;
}

static bool current_is_policy_manager(void)
{
    const char *comm = current_comm();

    if (str_eq_lit(comm, "magiskpolicy") ||
        str_eq_lit(comm, "apd") ||
        str_eq_lit(comm, "truncate"))
        return true;

    return false;
}

static u32 *bypass_counter_for_node(const char *node)
{
    if (str_eq_lit(node, "access"))
        return &g_bypass_access_log_count;
    if (str_eq_lit(node, "context"))
        return &g_bypass_context_log_count;
    return &g_bypass_policy_log_count;
}

static void log_bypass_once(const char *node, uid_t uid, const char *query)
{
    u32 *counter = bypass_counter_for_node(node);
    u32 n = READ_ONCE(*counter);

    n++;
    WRITE_ONCE(*counter, n);

    if (query)
        selinux_hook_dbg("[selinux_hook] LIVE bypass /sys/fs/selinux/%s #%u uid=%d comm=%s query=\"%s\"\n",
                         node ?: "?", n, uid, current_comm(), query);
    else
        selinux_hook_dbg("[selinux_hook] LIVE bypass /sys/fs/selinux/%s #%u uid=%d comm=%s\n",
                         node ?: "?", n, uid, current_comm());
}

static bool selinux_compat_call_needed(void)
{
    /*
     * 4.14 参考源码里的 security_read_policy() / security_context_to_sid()
     * 都需要 struct selinux_state * 作为第一个参数。这里用 selinux_state
     * 作为运行时信号，避免在没有 stateful ABI 的旧内核上误传参数。
     *
     * security_read_policy() and security_context_to_sid() are stateful on the
     * 4.14 sources listed above.  Keep the state argument through the Android
     * common stateful era, and stop before the newer 6.4+ LSM refactors where
     * this KPM has not been audited.
     */
    return g_selinux_state && kver >= VERSION(4, 14, 0) && kver < VERSION(6, 4, 0);
}

static bool policydb_offset_fallback_allowed(void)
{
    /*
     * policydb 偏移不能靠 sizeof(void *) 盲猜。只有确认当前内核像已审计的
     * 4.14 sm8150/cepheus stateful 布局，或者已经是非 legacy 的新内核时，
     * 才允许这个兜底；否则宁可跳过高风险路径。
     *
     * Do not guess policydb layout on pre-baseline legacy kernels.  The old
     * sizeof(void *) fallback is only acceptable once the runtime looks like
     * the audited 4.14 sm8150/cepheus stateful SELinux layout or a newer
     * non-legacy kernel.
     */
    return !use_legacy_clean_blob_query() || g_selinux_state;
}

static bool write_op_slot_fallback_allowed(void)
{
    /*
     * 参考 4.14 selinuxfs.c 可以确认 write_op[] 的 access/context 下标，
     * 但“下标可信”和“可以安全写函数指针表”是两回事。当前 APatch/KP c02
     * 不导出 hotpatch_nosync，所以实际写表逻辑在 install_write_op_hooks()
     * 里禁用，只保留这个布局置信度判断和日志。
     *
     * SEL_CONTEXT == 5 and SEL_ACCESS == 6 are confirmed in
     * security/selinux/selinuxfs.c for the referenced 4.14 trees.  This gate
     * only expresses layout confidence; the actual pointer-table patch is
     * disabled below on APatch/KP c02 because hotpatch_nosync is not exported.
     */
    return !use_legacy_clean_blob_query() || g_selinux_state;
}

static bool security_setprocattr_has_lsm_arg(void)
{
    /*
     * security/security.c:
     *   < 5.4  security_setprocattr(name, value, size)
     *   >=5.4  security_setprocattr(lsm, name, value, size)
     */
    return kver >= VERSION(5, 4, 0);
}

static bool security_load_policy_has_load_state(void)
{
    /*
     * 4.14 的 security_load_policy() 会直接提交 live policy，没有新版
     * load_state/cancel 流程。只有解析到 selinux_policy_cancel 这类新版
     * 辅助符号时，才走带 load_state 的调用；否则使用 clean blob /
     * policydb_read 路线。
     *
     * The referenced 4.14 services.c commits the loaded policy directly:
     *   security_load_policy(struct selinux_state *state, void *data, size_t len)
     *
     * Newer kernels grow staged load-state/cancel helpers.  Use the presence of
     * selinux_policy_cancel()/compat as the runtime signal before calling the
     * load_state form; otherwise fall back to clean blob / policydb_read.
     */
    return selinux_policy_cancel_fn || selinux_policy_cancel_compat_fn;
}

struct symbol_cache_entry {
    const char *base;
    size_t len;
    unsigned long addr;
    bool exact;
    bool suffixed;
};

typedef int (*kallsyms_on_each_symbol_nomod_fn)(int (*fn)(void *, const char *, unsigned long),
                                                void *data);

#define SYMBOL_CACHE_ENTRY(name) { name, 0, 0, false, false }

static struct symbol_cache_entry g_symbol_cache[] = {
    SYMBOL_CACHE_ENTRY("_raw_spin_lock"),
    SYMBOL_CACHE_ENTRY("_raw_spin_unlock"),
    SYMBOL_CACHE_ENTRY("copy_from_kernel_nofault"),
    SYMBOL_CACHE_ENTRY("probe_kernel_read"),
    SYMBOL_CACHE_ENTRY("copy_to_user_nofault"),
    SYMBOL_CACHE_ENTRY("_copy_to_user"),
    SYMBOL_CACHE_ENTRY("__copy_to_user"),
    SYMBOL_CACHE_ENTRY("vmalloc"),
    SYMBOL_CACHE_ENTRY("vmalloc_noprof"),
    SYMBOL_CACHE_ENTRY("vfree"),
    SYMBOL_CACHE_ENTRY("init_task"),
    SYMBOL_CACHE_ENTRY("filp_open"),
    SYMBOL_CACHE_ENTRY("filp_close"),
    SYMBOL_CACHE_ENTRY("kernel_read"),
    SYMBOL_CACHE_ENTRY("vfs_llseek"),
    SYMBOL_CACHE_ENTRY("selinux_state"),
    SYMBOL_CACHE_ENTRY("security_load_policy"),
    SYMBOL_CACHE_ENTRY("security_context_to_sid"),
    SYMBOL_CACHE_ENTRY("policydb_read"),
    SYMBOL_CACHE_ENTRY("policydb_destroy"),
    SYMBOL_CACHE_ENTRY("flex_array_get"),
    SYMBOL_CACHE_ENTRY("avtab_search_node"),
    SYMBOL_CACHE_ENTRY("avtab_search_node_next"),
    SYMBOL_CACHE_ENTRY("cond_compute_av"),
    SYMBOL_CACHE_ENTRY("constraint_expr_eval"),
    SYMBOL_CACHE_ENTRY("type_attribute_bounds_av"),
    SYMBOL_CACHE_ENTRY("selinux_policy_cancel"),
    SYMBOL_CACHE_ENTRY("sidtab_cancel_convert"),
    SYMBOL_CACHE_ENTRY("security_read_policy"),
    SYMBOL_CACHE_ENTRY("simple_read_from_buffer"),
    SYMBOL_CACHE_ENTRY("sel_read_handle_status"),
    SYMBOL_CACHE_ENTRY("sel_mmap_handle_status"),
    SYMBOL_CACHE_ENTRY("selinux_status_update_seqlock"),
    SYMBOL_CACHE_ENTRY("selinux_status_update_policyload"),
    SYMBOL_CACHE_ENTRY("security_setprocattr"),
    SYMBOL_CACHE_ENTRY("selinux_setprocattr"),
    SYMBOL_CACHE_ENTRY("sel_write_access"),
    SYMBOL_CACHE_ENTRY("sel_write_context"),
    SYMBOL_CACHE_ENTRY("write_op"),
    SYMBOL_CACHE_ENTRY("context_struct_compute_av"),
    SYMBOL_CACHE_ENTRY("string_to_context_struct"),
    SYMBOL_CACHE_ENTRY("selinux_complete_init"),
    SYMBOL_CACHE_ENTRY("selinux_policy_commit"),
};

#define SYMBOL_CACHE_COUNT (sizeof(g_symbol_cache) / sizeof(g_symbol_cache[0]))

static bool g_symbol_cache_resolved;

static size_t str_len_safe(const char *s)
{
    size_t len = 0;

    if (!s)
        return 0;

    while (s[len])
        len++;
    return len;
}

static bool suffix_contains_cfi(const char *suffix)
{
    size_t i;

    if (!suffix)
        return false;

    for (i = 0; suffix[i]; i++) {
        if (suffix[i] == 'c' && suffix[i + 1] == 'f' && suffix[i + 2] == 'i' &&
            (i == 0 || suffix[i - 1] == '.' || suffix[i - 1] == '$') &&
            (!suffix[i + 3] || suffix[i + 3] == '.' || suffix[i + 3] == '$'))
            return true;
    }
    return false;
}

static bool symbol_name_matches(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    return name[len] == '\0';
}

static bool symbol_has_compiler_suffix(const char *name, const char *base, size_t len)
{
    size_t i;

    if (!name || !base || !len)
        return false;

    for (i = 0; i < len; i++) {
        if (name[i] != base[i])
            return false;
    }

    if (!(name[len] == '.' || name[len] == '$') || !name[len + 1])
        return false;

    /* Skip CFI stub variants; they redirect to the real function */
    if (suffix_contains_cfi(name + len + 1))
        return false;

    return true;
}

static void prepare_symbol_cache(void)
{
    size_t i;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++)
        g_symbol_cache[i].len = str_len_safe(g_symbol_cache[i].base);
}

static void cache_symbol_match(const char *name, unsigned long addr)
{
    size_t i;

    if (!name || !addr)
        return;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        struct symbol_cache_entry *entry = &g_symbol_cache[i];

        if (!entry->base || !entry->len || entry->exact)
            continue;

        if (symbol_name_matches(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->exact = true;
            entry->suffixed = false;
            continue;
        }

        if (!entry->addr &&
            symbol_has_compiler_suffix(name, entry->base, entry->len)) {
            entry->addr = addr;
            entry->suffixed = true;
        }
    }
}

static int cache_symbol_cb(void *data, const char *name,
                           struct module *module, unsigned long addr)
{
    (void)data;
    (void)module;

    cache_symbol_match(name, addr);
    return 0;
}

static int cache_symbol_cb_nomod(void *data, const char *name, unsigned long addr)
{
    (void)data;

    cache_symbol_match(name, addr);
    return 0;
}

static void resolve_required_symbols_once(void)
{
    size_t i;
    u32 found = 0;
    u32 suffixed = 0;
    u32 missing = 0;

    if (READ_ONCE(g_symbol_cache_resolved))
        return;

    prepare_symbol_cache();

    if (!kallsyms_on_each_symbol) {
        pr_warn("[selinux_hook] kallsyms_on_each_symbol missing; falling back to exact symbol lookups only\n");
        for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
            unsigned long addr;

            addr = (unsigned long)kallsyms_lookup_name(g_symbol_cache[i].base);
            if (addr) {
                g_symbol_cache[i].addr = addr;
                g_symbol_cache[i].exact = true;
            }
        }
    } else if (kver <= VERSION(6, 1, 0)) {
        kallsyms_on_each_symbol(cache_symbol_cb, NULL);
    } else {
        kallsyms_on_each_symbol_nomod_fn on_each_symbol;

        on_each_symbol = (kallsyms_on_each_symbol_nomod_fn)kallsyms_on_each_symbol;
        on_each_symbol(cache_symbol_cb_nomod, NULL);
    }

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (g_symbol_cache[i].addr) {
            found++;
            if (g_symbol_cache[i].suffixed)
                suffixed++;
        } else {
            missing++;
        }
    }

    WRITE_ONCE(g_symbol_cache_resolved, true);
    pr_info("[selinux_hook] symbol cache resolved in one pass: found=%u suffixed=%u missing=%u\n",
            found, suffixed, missing);
}

static struct symbol_cache_entry *find_cached_symbol(const char *base)
{
    size_t i;

    if (!base)
        return NULL;

    for (i = 0; i < SYMBOL_CACHE_COUNT; i++) {
        if (str_eq_lit(base, g_symbol_cache[i].base))
            return &g_symbol_cache[i];
    }

    return NULL;
}

static void *lookup_name_optional_suffix(const char *base)
{
    struct symbol_cache_entry *entry;

    if (!base)
        return NULL;

    resolve_required_symbols_once();

    entry = find_cached_symbol(base);
    if (entry)
        return (void *)entry->addr;

    return (void *)kallsyms_lookup_name(base);
}

static void log_symbol_addr(const char *name, const void *addr)
{
    pr_info("[selinux_hook] symbol %-36s %s addr=%px\n",
            name ?: "(null)", addr ? "found" : "missing", addr);
}

static int call_security_read_policy(void **data, size_t *len)
{
    if (selinux_compat_call_needed() && security_read_policy_compat_fn)
        return security_read_policy_compat_fn(g_selinux_state, data, len);
    if (security_read_policy_fn)
        return security_read_policy_fn(data, len);
    return -ENOENT;
}

static int call_security_load_policy(void *data, size_t len, struct selinux_load_state *load_state)
{
    if (!security_load_policy_has_load_state())
        return -EOPNOTSUPP;
    if (selinux_compat_call_needed() && security_load_policy_compat_fn)
        return security_load_policy_compat_fn(g_selinux_state, data, len, load_state);
    if (security_load_policy_fn)
        return security_load_policy_fn(data, len, load_state);
    return -ENOENT;
}

static void call_selinux_policy_cancel(struct selinux_load_state *load_state)
{
    if (selinux_compat_call_needed() && selinux_policy_cancel_compat_fn) {
        selinux_policy_cancel_compat_fn(g_selinux_state, load_state);
        return;
    }
    if (selinux_policy_cancel_fn)
        selinux_policy_cancel_fn(load_state);
}

static int call_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
    if (selinux_compat_call_needed() && security_context_to_sid_compat_fn)
        return security_context_to_sid_compat_fn(g_selinux_state, scontext, scontext_len, out_sid, gfp);
    if (security_context_to_sid_fn)
        return security_context_to_sid_fn(scontext, scontext_len, out_sid, gfp);
    return -ENOENT;
}

static unsigned int ebitmap_start_positive_intel(struct ebitmap *e,
                                                 struct ebitmap_node **node)
{
    unsigned int map_i;
    unsigned int bit_i;

    if (!e || !node)
        return 0;

    for (*node = e->node; *node; *node = (*node)->next) {
        for (map_i = 0; map_i < SELINUX_EBITMAP_UNIT_NUMS; map_i++) {
            unsigned long map = (*node)->maps[map_i];

            if (!map)
                continue;
            for (bit_i = 0; bit_i < SELINUX_EBITMAP_UNIT_BITS; bit_i++) {
                if (map & (1UL << bit_i))
                    return (*node)->startbit +
                           map_i * SELINUX_EBITMAP_UNIT_BITS + bit_i;
            }
        }
    }

    return e->highbit;
}

static unsigned int ebitmap_next_positive_intel(struct ebitmap *e,
                                                struct ebitmap_node **node,
                                                unsigned int bit)
{
    unsigned int absolute;
    unsigned int offset;
    unsigned int map_i;
    unsigned int bit_i;

    if (!e || !node || !*node)
        return e ? e->highbit : 0;

    absolute = bit + 1;
    while (*node) {
        if (absolute < (*node)->startbit)
            absolute = (*node)->startbit;
        offset = absolute - (*node)->startbit;
        map_i = offset / SELINUX_EBITMAP_UNIT_BITS;
        bit_i = offset % SELINUX_EBITMAP_UNIT_BITS;

        for (; map_i < SELINUX_EBITMAP_UNIT_NUMS; map_i++) {
            unsigned long map = (*node)->maps[map_i];

            for (; bit_i < SELINUX_EBITMAP_UNIT_BITS; bit_i++) {
                if (map & (1UL << bit_i))
                    return (*node)->startbit +
                           map_i * SELINUX_EBITMAP_UNIT_BITS + bit_i;
            }
            bit_i = 0;
        }

        *node = (*node)->next;
        if (*node)
            absolute = (*node)->startbit;
    }

    return e->highbit;
}

#define ebitmap_for_each_positive_bit_intel(e, n, bit) \
    for ((bit) = ebitmap_start_positive_intel((e), &(n)); \
         (bit) < (e)->highbit; \
         (bit) = ebitmap_next_positive_intel((e), &(n), (bit)))

static void services_compute_xperms_drivers_intel(struct extended_perms *xperms,
                                                  struct avtab_node *node)
{
    unsigned int i;

    if (!xperms || !node || !node->datum.u.xperms)
        return;

    if (node->datum.u.xperms->specified == AVTAB_XPERMS_IOCTLDRIVER) {
        for (i = 0; i < sizeof(xperms->drivers.p) / sizeof(xperms->drivers.p[0]); i++)
            xperms->drivers.p[i] |= node->datum.u.xperms->perms.p[i];
    } else if (node->datum.u.xperms->specified == AVTAB_XPERMS_IOCTLFUNCTION) {
        security_xperm_set(xperms->drivers.p, node->datum.u.xperms->driver);
    }

    if (node->key.specified & AVTAB_XPERMS_ALLOWED)
        xperms->len = 1;
}

static bool context_struct_compute_av_intel(struct policydb *policydb,
                                            struct context *scontext,
                                            struct context *tcontext,
                                            u16 tclass,
                                            struct av_decision *avd,
                                            struct extended_perms *xperms)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr;
    struct ebitmap *tattr;
    struct ebitmap_node *snode;
    struct ebitmap_node *tnode;
    unsigned int i;
    unsigned int j;

    if (!policydb || !scontext || !tcontext || !avd)
        return false;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (xperms) {
        zero_bytes(&xperms->drivers, sizeof(xperms->drivers));
        xperms->len = 0;
    }

    if (unlikely(!tclass || tclass > policydb->symtab[SYM_CLASSES].nprim)) {
        pr_warn("[selinux_hook] intel_av invalid class %hu\n", tclass);
        return false;
    }

    if (!policydb->class_val_to_struct) {
        pr_warn("[selinux_hook] intel_av missing class_val_to_struct policydb=%px\n",
                policydb);
        return false;
    }

    tclass_datum = policydb->class_val_to_struct[tclass - 1];
    if (!tclass_datum) {
        pr_warn("[selinux_hook] intel_av missing class datum class=%hu policydb=%px\n",
                tclass, policydb);
        return false;
    }

    if (!flex_array_get_fn || !avtab_search_node_fn || !avtab_search_node_next_fn) {
        pr_warn("[selinux_hook] intel_av missing core helpers flex=%px search=%px next=%px\n",
                flex_array_get_fn, avtab_search_node_fn, avtab_search_node_next_fn);
        return false;
    }

    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;
    sattr = (struct ebitmap *)flex_array_get_fn(policydb->type_attr_map_array,
                                                scontext->type - 1);
    tattr = (struct ebitmap *)flex_array_get_fn(policydb->type_attr_map_array,
                                                tcontext->type - 1);
    if (!sattr || !tattr) {
        pr_warn("[selinux_hook] intel_av missing attr map s_type=%u t_type=%u sattr=%px tattr=%px policydb=%px\n",
                scontext->type, tcontext->type, sattr, tattr, policydb);
        return false;
    }

    ebitmap_for_each_positive_bit_intel(sattr, snode, i) {
        ebitmap_for_each_positive_bit_intel(tattr, tnode, j) {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for (node = avtab_search_node_fn(&policydb->te_avtab, &avkey);
                 node;
                 node = avtab_search_node_next_fn(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED)
                    avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW)
                    avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY)
                    avd->auditdeny &= node->datum.u.data;
                else if (xperms && (node->key.specified & AVTAB_XPERMS))
                    services_compute_xperms_drivers_intel(xperms, node);
            }

            if (cond_compute_av_fn)
                cond_compute_av_fn(&policydb->te_cond_avtab, &avkey, avd, xperms);
        }
    }

    constraint = tclass_datum->constraints;
    while (constraint) {
        if ((constraint->permissions & avd->allowed) &&
            constraint_expr_eval_fn &&
            !constraint_expr_eval_fn(policydb, scontext, tcontext, NULL,
                                     constraint->expr)) {
            avd->allowed &= ~constraint->permissions;
        }
        constraint = constraint->next;
    }

    if (tclass == policydb->process_class &&
        (avd->allowed & policydb->process_trans_perms) &&
        scontext->role != tcontext->role) {
        for (ra = policydb->role_allow; ra; ra = ra->next) {
            if (scontext->role == ra->role &&
                tcontext->role == ra->new_role)
                break;
        }
        if (!ra)
            avd->allowed &= ~policydb->process_trans_perms;
    }

    if (type_attribute_bounds_av_fn)
        type_attribute_bounds_av_fn(policydb, scontext, tcontext, tclass, avd);

    return true;
}

static void *read_load_state_policy(void *load_state)
{
    void *policy = NULL;

    if (!load_state)
        return NULL;

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(&policy, load_state, sizeof(policy)) == 0)
        return policy;

    return *(void **)load_state;
}

static struct sidtab *read_policy_sidtab(void *policy)
{
    struct sidtab *sidtab = NULL;

    if (!policy)
        return NULL;

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(&sidtab, policy, sizeof(sidtab)) == 0)
        return sidtab;

    return *(struct sidtab **)policy;
}

static void cancel_clean_sidtab_convert(const char *reason)
{
    void *policy;
    struct sidtab *sidtab;

    if (!READ_ONCE(g_clean_load_state_ready))
        return;
    if (READ_ONCE(g_clean_sidtab_convert_canceled))
        return;

    policy = READ_ONCE(g_first_policy);
    if (!policy)
        return;

    if (!sidtab_cancel_convert_fn) {
        pr_warn("[selinux_hook] CLEAN cannot cancel live sidtab convert reason=%s: missing sidtab_cancel_convert\n",
                reason ?: "(null)");
        return;
    }

    sidtab = read_policy_sidtab(policy);
    if (!sidtab) {
        pr_warn("[selinux_hook] CLEAN cannot cancel live sidtab convert reason=%s policy=%px sidtab=NULL\n",
                reason ?: "(null)", policy);
        return;
    }

    sidtab_cancel_convert_fn(sidtab);
    WRITE_ONCE(g_clean_sidtab_convert_canceled, true);
    selinux_hook_dbg("[selinux_hook] CLEAN canceled live sidtab convert reason=%s policy=%px sidtab=%px clean_policy=%px\n",
                     reason ?: "(null)", policy, sidtab, g_clean_load_state.policy);
}

static ssize_t call_kernel_read_file(struct file *file, void *buf, size_t count, loff_t *pos)
{
    if (!kernel_read_fn)
        return -ENOENT;

    if (kver < VERSION(4, 14, 0)) {
        loff_t offset = pos ? *pos : 0;
        int (*kernel_read_legacy)(struct file *file, loff_t offset, char *addr,
                                  unsigned long count) =
            (void *)kernel_read_fn;
        int rc = kernel_read_legacy(file, offset, (char *)buf,
                                    (unsigned long)count);

        if (pos && rc > 0)
            *pos = offset + rc;
        return rc;
    }

    return kernel_read_fn(file, buf, count, pos);
}

static bool magiskinit_process_exists(void)
{
    struct task_struct *init;
    struct task_struct *task;

    init = init_task_ptr;
    if (!init || task_struct_offset.tasks_offset <= 0 ||
        task_struct_offset.comm_offset <= 0)
        return false;

    for (task = init; (task = next_task(task)) != init;) {
        if (str_eq_lit(get_task_comm(task), "magiskinit"))
            return true;
    }

    return false;
}

static bool try_snapshot_mock_policy(const char *reason)
{
    struct file *filp;
    void *data;
    loff_t len;
    loff_t pos;
    ssize_t nread;

    if (!magiskinit_process_exists())
        return false;
    if (!vmalloc_fn)
        return false;
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn) {
        pr_warn("[selinux_hook] CLEAN mock policy file read disabled reason=%s open=%px close=%px read=%px llseek=%px\n",
                reason ?: "(null)", filp_open_fn, filp_close_fn,
                kernel_read_fn, vfs_llseek_fn);
        return false;
    }

    filp = filp_open_fn(MAGISK_MOCK_POLICY_PATH, O_RDONLY, 0);
    if (!filp || IS_ERR(filp)) {
        pr_warn("[selinux_hook] CLEAN mock policy open failed reason=%s path=%s rc=%ld\n",
                reason ?: "(null)", MAGISK_MOCK_POLICY_PATH,
                filp ? PTR_ERR(filp) : -ENOENT);
        return false;
    }

    len = vfs_llseek_fn(filp, 0, SEEK_END);
    if (len <= 0 || len > MAGISK_MOCK_POLICY_MAX_SIZE) {
        pr_warn("[selinux_hook] CLEAN mock policy bad len reason=%s path=%s len=%lld\n",
                reason ?: "(null)", MAGISK_MOCK_POLICY_PATH, len);
        filp_close_fn(filp, 0);
        return false;
    }
    vfs_llseek_fn(filp, 0, SEEK_SET);

    data = vmalloc_fn((unsigned long)len);
    if (!data) {
        pr_warn("[selinux_hook] CLEAN mock policy alloc failed reason=%s len=%lld\n",
                reason ?: "(null)", len);
        filp_close_fn(filp, 0);
        return false;
    }

    pos = 0;
    nread = call_kernel_read_file(filp, data, (size_t)len, &pos);
    filp_close_fn(filp, 0);
    if (nread != len || pos != len) {
        pr_warn("[selinux_hook] CLEAN mock policy read failed reason=%s read=%ld pos=%lld len=%lld\n",
                reason ?: "(null)", (long)nread, pos, len);
        if (vfree_fn)
            vfree_fn(data);
        return false;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, (size_t)len));
    WRITE_ONCE(g_clean_policy_len, (size_t)len);
    WRITE_ONCE(g_clean_policy_blob, data);
    pr_info("[selinux_hook] CLEAN mock policy snapshot saved reason=%s path=%s blob=%px len=%zu has_magisk=%d\n",
            reason ?: "(null)", MAGISK_MOCK_POLICY_PATH, data,
            READ_ONCE(g_clean_policy_len), READ_ONCE(g_clean_policy_has_magisk));
    return true;
}

static void refresh_policydb_offset(const char *reason, bool allow_fallback)
{
    void *policy = READ_ONCE(g_first_policy);
    void *policydb = READ_ONCE(g_first_policydb);
    unsigned long diff;

    if (READ_ONCE(g_policydb_offset))
        return;

    if (policy && policydb && policydb > policy) {
        diff = (unsigned long)policydb - (unsigned long)policy;
        if (diff < 0x100000) {
            WRITE_ONCE(g_policydb_offset, (size_t)diff);
            selinux_hook_dbg("[selinux_hook] policydb offset learned reason=%s policy=%px policydb=%px off=%zu\n",
                             reason ?: "(null)", policy, policydb,
                             READ_ONCE(g_policydb_offset));
            return;
        }
    }

    if (!allow_fallback)
        return;

    if (!policydb_offset_fallback_allowed()) {
        if (!READ_ONCE(g_policydb_offset_fallback_warned)) {
            WRITE_ONCE(g_policydb_offset_fallback_warned, true);
            pr_warn("[selinux_hook] policydb offset fallback refused reason=%s kver=%x policy=%px policydb=%px: legacy route lacks 4.14 selinux_state baseline\n",
                    reason ?: "(null)", kver, policy, policydb);
        }
        return;
    }

    WRITE_ONCE(g_policydb_offset, (size_t)SELINUX_POLICYDB_FALLBACK_OFFSET);
    selinux_hook_dbg("[selinux_hook] policydb offset fallback reason=%s policy=%px policydb=%px off=%zu\n",
                     reason ?: "(null)", policy, policydb, READ_ONCE(g_policydb_offset));
}

static void refresh_clean_policydb(const char *reason, bool allow_fallback)
{
    void *policy;
    size_t off;

    if (!clean_policydb_redirect_supported())
        return;
    if (READ_ONCE(g_clean_policydb_direct))
        return;

    if (!READ_ONCE(g_clean_load_state_ready) || !g_clean_load_state.policy)
        return;

    refresh_policydb_offset(reason, allow_fallback);
    off = READ_ONCE(g_policydb_offset);
    if (!off)
        return;

    policy = g_clean_load_state.policy;
    WRITE_ONCE(g_clean_policydb, (void *)((char *)policy + off));
}

static void try_load_clean_policydb_from_blob(const char *reason)
{
    struct policy_file fp;
    struct policydb *policydb;
    void *blob = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    int rc;

    if (READ_ONCE(g_clean_policydb))
        return;
    if (!blob || !len)
        return;
    if (!policydb_read_fn || !policydb_destroy_fn || !vmalloc_fn)
        return;

    policydb = (struct policydb *)vmalloc_fn(CLEAN_POLICYDB_ALLOC_SIZE);
    if (!policydb) {
        pr_warn("[selinux_hook] CLEAN policydb_read alloc failed reason=%s size=%u\n",
                reason ?: "(null)", CLEAN_POLICYDB_ALLOC_SIZE);
        return;
    }
    zero_bytes(policydb, CLEAN_POLICYDB_ALLOC_SIZE);

    fp.data = (char *)blob;
    fp.len = len;
    rc = policydb_read_fn(policydb, &fp);
    if (rc) {
        pr_warn("[selinux_hook] CLEAN policydb_read failed reason=%s rc=%d policydb=%px blob=%px len=%zu\n",
                reason ?: "(null)", rc, policydb, blob, len);
        if (policydb_destroy_fn)
            policydb_destroy_fn(policydb);
        if (vfree_fn)
            vfree_fn(policydb);
        return;
    }

    WRITE_ONCE(g_clean_policydb, policydb);
    WRITE_ONCE(g_clean_policydb_direct, true);
    pr_info("[selinux_hook] CLEAN policydb_read saved reason=%s policydb=%px blob=%px len=%zu alloc=%u\n",
            reason ?: "(null)", policydb, blob, len, CLEAN_POLICYDB_ALLOC_SIZE);
}

static void snapshot_clean_policy(const char *reason)
{
    void *data = NULL;
    size_t len = 0;
    int rc;

    if (READ_ONCE(g_clean_policy_blob))
        return;
    if (READ_ONCE(g_dirty_policy_seen))
        return;

    if (try_snapshot_mock_policy(reason)) {
        if (use_clean_blob_route()) {
            try_load_clean_policydb_from_blob(reason);
            pr_info("[selinux_hook] CLEAN mock route reason=%s: blob=%px len=%zu policydb=%px direct=%d\n",
                    reason ?: "(null)", READ_ONCE(g_clean_policy_blob),
                    READ_ONCE(g_clean_policy_len), READ_ONCE(g_clean_policydb),
                    READ_ONCE(g_clean_policydb_direct) ? 1 : 0);
            return;
        }
        if (!clean_policydb_redirect_supported()) {
            try_load_clean_policydb_from_blob(reason);
            pr_info("[selinux_hook] CLEAN legacy mock blob route reason=%s: blob=%px len=%zu policydb=%px\n",
                    reason ?: "(null)", READ_ONCE(g_clean_policy_blob),
                    READ_ONCE(g_clean_policy_len), READ_ONCE(g_clean_policydb));
            return;
        }
        data = READ_ONCE(g_clean_policy_blob);
        len = READ_ONCE(g_clean_policy_len);
        goto load_clean_policy;
    }

    if (!security_read_policy_fn && !security_read_policy_compat_fn)
        return;

    rc = call_security_read_policy(&data, &len);
    if (rc || !data || !len) {
        pr_warn("[selinux_hook] clean policy snapshot failed reason=%s rc=%d data=%px len=%zu\n",
                reason ?: "(null)", rc, data, len);
        if (data)
            if (vfree_fn)
                vfree_fn(data);
        return;
    }

    WRITE_ONCE(g_clean_policy_has_magisk, buffer_contains_magisk(data, len));
    WRITE_ONCE(g_clean_policy_len, len);
    WRITE_ONCE(g_clean_policy_blob, data);
    selinux_hook_dbg("[selinux_hook] CLEAN policy snapshot saved reason=%s blob=%px len=%zu has_magisk=%d\n",
                     reason ?: "(null)", data, len, READ_ONCE(g_clean_policy_has_magisk));

    if (!clean_policydb_redirect_supported()) {
        try_load_clean_policydb_from_blob(reason);
        pr_info("[selinux_hook] CLEAN legacy blob route reason=%s: blob=%px len=%zu policydb=%px\n",
                reason ?: "(null)", data, len, READ_ONCE(g_clean_policydb));
        return;
    }

    if (use_clean_blob_route()) {
        try_load_clean_policydb_from_blob(reason);
        pr_info("[selinux_hook] CLEAN 5.10-6.1 route reason=%s: skip staged security_load_policy, blob=%px len=%zu policydb=%px direct=%d\n",
                reason ?: "(null)", data, len, READ_ONCE(g_clean_policydb),
                READ_ONCE(g_clean_policydb_direct) ? 1 : 0);
        return;
    }

load_clean_policy:
    if (!security_load_policy_has_load_state()) {
        try_load_clean_policydb_from_blob(reason);
        pr_info("[selinux_hook] CLEAN policy load skipped reason=%s: legacy security_load_policy commits live policy, blob fallback active\n",
                reason ?: "(null)");
        return;
    }

    if ((security_load_policy_fn || security_load_policy_compat_fn) &&
        !READ_ONCE(g_clean_load_state_ready)) {
        WRITE_ONCE(g_internal_policy_load_depth,
                   READ_ONCE(g_internal_policy_load_depth) + 1);
        rc = call_security_load_policy(data, len, &g_clean_load_state);
        if (READ_ONCE(g_internal_policy_load_depth))
            WRITE_ONCE(g_internal_policy_load_depth,
                       READ_ONCE(g_internal_policy_load_depth) - 1);
        if (!rc && g_clean_load_state.policy) {
            WRITE_ONCE(g_clean_load_state_ready, true);
            refresh_clean_policydb("clean_load", false);
            cancel_clean_sidtab_convert("clean_load");
            selinux_hook_dbg("[selinux_hook] CLEAN policy loaded policy=%px policydb=%px convert=%px\n",
                             g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                             g_clean_load_state.convert_data);
        } else {
            pr_warn("[selinux_hook] CLEAN policy load failed rc=%d policy=%px\n",
                    rc, g_clean_load_state.policy);
        }
    }
}

static bool contains_magisk(const char *s, size_t len)
{
    return contains_case_literal(s, len, "magisk");
}

static bool contains_case_lit(const char *s, size_t len, const char *lit, size_t lit_len)
{
    size_t i;
    size_t j;

    if (!s || !lit || !lit_len || len < lit_len)
        return false;

    for (i = 0; i + lit_len <= len; i++) {
        for (j = 0; j < lit_len; j++) {
            if (!ascii_lower_eq(s[i + j], lit[j]))
                break;
        }
        if (j == lit_len)
            return true;
    }

    return false;
}

static size_t sanitize_query_sample(char *dst, size_t size)
{
    size_t i;

    if (!dst)
        return 0;

    for (i = 0; i < size && i < ACCESS_SAMPLE_MAX - 1; i++) {
        char c = dst[i];

        if (!c)
            break;
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
        dst[i] = c;
    }

    dst[i] = '\0';
    return i;
}

static size_t copy_query_sample(char *dst, const char *src, size_t size)
{
    size_t limit;
    long copied;

    if (!dst || !src)
        return 0;

    limit = size;
    if (!limit || limit > ACCESS_SAMPLE_MAX - 1)
        limit = ACCESS_SAMPLE_MAX - 1;

    dst[0] = '\0';

    if (copy_from_kernel_nofault_fn &&
        copy_from_kernel_nofault_fn(dst, src, limit) == 0) {
        dst[limit] = '\0';
        return sanitize_query_sample(dst, limit);
    }

    copied = compat_strncpy_from_user(dst, (const char __user *)src, limit + 1);
    if (copied <= 0) {
        dst[0] = '\0';
        return 0;
    }

    if ((size_t)copied > limit)
        copied = limit;
    return sanitize_query_sample(dst, (size_t)copied);
}

static size_t token_len(const char *s)
{
    size_t i = 0;

    if (!s)
        return 0;

    while (s[i] && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '\t')
        i++;
    return i;
}

static const char *skip_spaces(const char *s)
{
    while (s && (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t'))
        s++;
    return s;
}

static bool clean_blob_has_name(const char *name, size_t len)
{
    const char *blob = (const char *)READ_ONCE(g_clean_policy_blob);
    size_t blob_len = READ_ONCE(g_clean_policy_len);
    size_t i;

    if (!blob || !blob_len || !name || !len)
        return true;

    for (i = 0; i + len <= blob_len; i++) {
        size_t j;

        for (j = 0; j < len; j++) {
            if (blob[i + j] != name[j])
                break;
        }
        if (j == len)
            return true;
    }

    return false;
}

static bool clean_context_token_exists(const char *ctx, size_t len)
{
    size_t i;
    size_t first = (size_t)-1;
    size_t second = (size_t)-1;
    size_t third = (size_t)-1;

    if (!ctx || !len)
        return true;

    for (i = 0; i < len; i++) {
        if (ctx[i] != ':')
            continue;
        if (first == (size_t)-1)
            first = i;
        else if (second == (size_t)-1)
            second = i;
        else {
            third = i;
            break;
        }
    }

    if (second == (size_t)-1)
        return true;

    if (third == (size_t)-1)
        third = len;

    if (third <= second + 1)
        return false;

    return clean_blob_has_name(ctx + second + 1, third - second - 1);
}

static bool clean_context_exists(const char *query)
{
    query = skip_spaces(query);
    return clean_context_token_exists(query, token_len(query));
}

static bool token_eq_lit(const char *token, size_t len, const char *lit)
{
    size_t i;

    if (!token || !lit)
        return false;

    for (i = 0; i < len; i++) {
        if (!lit[i] || !ascii_lower_eq(token[i], lit[i]))
            return false;
    }

    return lit[i] == '\0';
}

static bool context_token_matches(const char *query, const char *lit)
{
    const char *ctx = skip_spaces(query);

    return token_eq_lit(ctx, token_len(ctx), lit);
}

static bool dirtysepolicy_context_should_hide(const char *query)
{
    /*
     * DirtySepolicy reference:
     *   https://github.com/LSPosed/DirtySepolicy/tree/0cda3b89cd168c88cbf639da9e3d4f44d70c0b78
     *
     * Relevant source paths:
     *   - app/src/main/java/org/lsposed/dirtysepolicy/AppZygote.java
     *       contextExists("u:r:adbroot:s0")
     *       contextExists("u:r:magisk:s0")
     *       contextExists("u:object_r:magisk_file:s0")
     *       contextExists("u:r:ksu:s0")
     *       contextExists("u:object_r:ksu_file:s0")
     *       contextExists("u:object_r:lsposed_file:s0")
     *       contextExists("u:object_r:xposed_data:s0")
     *       contextExists("u:object_r:xposed_file:s0")
     *   - app/src/main/java/org/lsposed/dirtysepolicy/SELinux.java
     *       contextExists() first writes /sys/fs/selinux/context.
     *       On EINVAL it falls back to /sys/fs/selinux/access.
     *       On EINVAL again it writes /proc/self/attr/current; EPERM is still
     *       interpreted as "context exists".
     *
     * DirtySepolicy 的 contextExists() 不是只测 /sys/fs/selinux/context。
     * 如果这里只拦 context 节点，它还会继续走 access fallback，最后再写
     * /proc/self/attr/current；其中 EPERM 也会被它当成“上下文存在”。因此
     * 这些敏感 context 必须在三条路径里都表现成 EINVAL/不存在。
     *
     * Because of that three-stage fallback, hiding a dirty context requires all
     * three kernel paths to return an "invalid context" style result for
     * app-side probes.
     */
    if (context_token_matches(query, "u:r:adbroot:s0"))
        return true;
    if (context_token_matches(query, "u:r:magisk:s0"))
        return true;
    if (context_token_matches(query, "u:object_r:magisk_file:s0"))
        return true;
    if (context_token_matches(query, "u:r:ksu:s0"))
        return true;
    if (context_token_matches(query, "u:object_r:ksu_file:s0"))
        return true;
    if (context_token_matches(query, "u:object_r:lsposed_file:s0"))
        return true;
    if (context_token_matches(query, "u:object_r:xposed_data:s0"))
        return true;
    if (context_token_matches(query, "u:object_r:xposed_file:s0"))
        return true;

    return false;
}

static const char *next_token(const char *s)
{
    s = skip_spaces(s);
    while (s && *s && *s != ' ' && *s != '\n' && *s != '\r' && *s != '\t')
        s++;
    return skip_spaces(s);
}

static bool clean_access_contexts_exist(const char *query)
{
    const char *src;
    const char *dst;
    size_t src_len;
    size_t dst_len;

    src = skip_spaces(query);
    src_len = token_len(src);
    if (!clean_context_token_exists(src, src_len))
        return false;

    dst = next_token(src);
    dst_len = token_len(dst);
    if (!clean_context_token_exists(dst, dst_len))
        return false;

    return true;
}

static bool access_contexts_match(const char *query, const char *src_lit,
                                  const char *dst_lit)
{
    const char *src;
    const char *dst;

    src = skip_spaces(query);
    dst = next_token(src);

    return token_eq_lit(src, token_len(src), src_lit) &&
           token_eq_lit(dst, token_len(dst), dst_lit);
}

static bool dirtysepolicy_access_should_deny(const char *query, size_t len)
{
    const char *src;
    const char *dst;

    if (!query || !len)
        return false;

    src = skip_spaces(query);
    dst = next_token(src);

    /*
     * contextExists() second stage calls /access with the same hidden context
     * as source and target.  Hide either side to keep the fallback consistent.
     *
     * 这是为了堵住 contextExists() 的第二段 fallback：它会拿同一个 context
     * 当源和目标去查 /access。只要源或目标是需要隐藏的 dirty context，
     * 这里就直接 deny。
     */
    if (dirtysepolicy_context_should_hide(src) ||
        dirtysepolicy_context_should_hide(dst))
        return true;

    /*
     * AppZygote.java DirtySepolicy access probes:
     *   system_server -> system_server        process execmem
     *   shell         -> su                   process transition
     *   rootfs        -> tmpfs                filesystem associate
     *   kernel        -> tmpfs                fifo_file open
     *   kernel        -> adb_data_file        file read
     *   system_server -> apk_data_file        file execute
     *   dex2oat       -> dex2oat_exec         file execute_no_trans
     *   zygote        -> adb_data_file        dir search
     *
     * SELinux.java resolves the class/permission bit separately from
     * /sys/fs/selinux/class and then checks the returned av_decision.allowed.
     * Matching the context pair here is enough to force the DirtySepolicy
     * result to false while leaving policy-manager processes bypassed earlier.
     *
     * DirtySepolicy 会先从 /sys/fs/selinux/class 读 class/perm 编号，再向
     * /access 写入 source context、target context 和 class id。这里按它
     * 固定使用的 context 对拦截即可；管理进程已经在入口处 bypass，不影响
     * APatch/magiskpolicy 自己操作策略。
     */
    if (access_contexts_match(query, "u:r:system_server:s0", "u:r:system_server:s0"))
        return true;
    if (access_contexts_match(query, "u:r:shell:s0", "u:r:su:s0"))
        return true;
    if (access_contexts_match(query, "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0"))
        return true;
    if (access_contexts_match(query, "u:r:kernel:s0", "u:object_r:tmpfs:s0"))
        return true;
    if (access_contexts_match(query, "u:r:kernel:s0", "u:object_r:adb_data_file:s0"))
        return true;
    if (access_contexts_match(query, "u:r:system_server:s0", "u:object_r:apk_data_file:s0"))
        return true;
    if (access_contexts_match(query, "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0"))
        return true;
    if (access_contexts_match(query, "u:r:zygote:s0", "u:object_r:adb_data_file:s0"))
        return true;

    return false;
}

static bool legacy_clean_query_should_block(const char *query, size_t len, bool access_query)
{
    if (access_query && dirtysepolicy_access_should_deny(query, len))
        return true;
    if (!access_query && dirtysepolicy_context_should_hide(query))
        return true;
    if (legacy_should_block_access_query(query, len))
        return true;
    if (!READ_ONCE(g_clean_policy_blob))
        return false;

    if (access_query)
        return !clean_access_contexts_exist(query);

    return !clean_context_exists(query);
}

static bool legacy_should_block_access_query(const char *query, size_t len)
{
    if (!query || !len)
        return false;

    if (dirtysepolicy_access_should_deny(query, len))
        return true;
    if (contains_case_literal(query, len, "magisk"))
        return true;
    if (contains_case_literal(query, len, "ksu_file"))
        return true;
    if (contains_case_literal(query, len, "lsposed_file"))
        return true;
    if (contains_case_literal(query, len, "xposed_data"))
        return true;
    if (contains_case_literal(query, len, "adbroot"))
        return true;

    return false;
}

static bool enter_clean_eval_scope(void)
{
    void *task = current;
    int empty = -1;
    int i;
    u32 depth;
    bool entered = false;

    if (!clean_policydb_redirect_supported())
        return false;
    if (!READ_ONCE(g_clean_policydb))
        return false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task) {
            depth = g_clean_eval_scopes[i].depth + 1;
            g_clean_eval_scopes[i].depth = depth;
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
            entered = true;
            break;
        }
        if (empty < 0 && !g_clean_eval_scopes[i].task)
            empty = i;
    }

    if (!entered) {
        if (empty < 0) {
            if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
            pr_warn("[selinux_hook] clean eval scope slots exhausted task=%px comm=%s\n",
                    task, current_comm());
            return false;
        }
        g_clean_eval_scopes[empty].task = task;
        g_clean_eval_scopes[empty].depth = 1;
        WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) + 1);
        entered = true;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return true;
}

static void leave_clean_eval_scope(void)
{
    void *task = current;
    int i;
    u32 depth;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task != task)
            continue;

        depth = g_clean_eval_scopes[i].depth;
        if (depth > 1) {
            g_clean_eval_scopes[i].depth = depth - 1;
        } else {
            g_clean_eval_scopes[i].depth = 0;
            g_clean_eval_scopes[i].task = NULL;
        }
        if (READ_ONCE(g_clean_eval_depth))
            WRITE_ONCE(g_clean_eval_depth, READ_ONCE(g_clean_eval_depth) - 1);
        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
        return;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
}

static bool current_in_clean_eval_scope(void)
{
    void *task = current;
    int i;
    bool in_scope = false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < CLEAN_EVAL_SCOPE_SLOTS; i++) {
        if (g_clean_eval_scopes[i].task == task &&
            g_clean_eval_scopes[i].depth) {
            in_scope = true;
            break;
        }
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return in_scope;
}

static bool enter_status_read_scope(void)
{
    void *task = current;
    int empty = -1;
    int i;
    u32 depth;
    bool entered = false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task) {
            depth = g_status_read_scopes[i].depth + 1;
            g_status_read_scopes[i].depth = depth;
            entered = true;
            break;
        }
        if (empty < 0 && !g_status_read_scopes[i].task)
            empty = i;
    }

    if (!entered) {
        if (empty < 0) {
            if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
            pr_warn("[selinux_hook] status read scope slots exhausted task=%px comm=%s\n",
                    task, current_comm());
            return false;
        }
        g_status_read_scopes[empty].task = task;
        g_status_read_scopes[empty].depth = 1;
        g_status_read_scopes[empty].patched = 0;
        entered = true;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return true;
}

static void leave_status_read_scope(void)
{
    void *task = current;
    int i;
    u32 depth;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task != task)
            continue;

        depth = g_status_read_scopes[i].depth;
        if (depth > 1) {
            g_status_read_scopes[i].depth = depth - 1;
        } else {
            g_status_read_scopes[i].depth = 0;
            g_status_read_scopes[i].patched = 0;
            g_status_read_scopes[i].task = NULL;
        }
        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
        return;
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
}

static bool current_in_status_read_scope(void)
{
    void *task = current;
    int i;
    bool in_scope = false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            in_scope = true;
            break;
        }
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return in_scope;
}

static void mark_status_read_scope_patched(void)
{
    void *task = current;
    int i;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            g_status_read_scopes[i].patched = 1;
            if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
            return;
        }
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
}

static bool current_status_read_scope_patched(void)
{
    void *task = current;
    int i;
    bool patched = false;

    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_scopes_lock);
    for (i = 0; i < STATUS_READ_SCOPE_SLOTS; i++) {
        if (g_status_read_scopes[i].task == task &&
            g_status_read_scopes[i].depth) {
            patched = g_status_read_scopes[i].patched != 0;
            break;
        }
    }
    if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_scopes_lock);
    return patched;
}

static int clean_policy_context_to_sid(const char *query, u32 *out_sid)
{
    const char *ctx;
    size_t len;
    int rc;

    if (!query || !out_sid)
        return -EINVAL;

    refresh_clean_policydb("procattr_current", true);
    if (!READ_ONCE(g_clean_policydb) ||
        (!security_context_to_sid_fn && !security_context_to_sid_compat_fn))
        return 1;
    if (!clean_policydb_redirect_supported())
        return 1;

    ctx = skip_spaces(query);
    len = token_len(ctx);
    if (!len)
        return -EINVAL;

    if (!enter_clean_eval_scope())
        return -EAGAIN;

    rc = call_security_context_to_sid(ctx, (u32)len, out_sid, (gfp_t)0);
    leave_clean_eval_scope();

    return rc;
}

/* Hook: selinux_complete_init */
static void after_selinux_complete_init(hook_fargs0_t *a, void *u)
{
    WRITE_ONCE(g_selinux_ready, true);
    selinux_hook_dbg("[selinux_hook] SELinux complete_init done\n");
    snapshot_clean_policy("complete_init");
}

/* Hook: selinux_policy_commit */
static void after_selinux_policy_commit(hook_fargs1_t *a, void *u)
{
    void *policy = read_load_state_policy((void *)a->arg0);

    WRITE_ONCE(g_selinux_ready, true);
    if (policy && !READ_ONCE(g_first_policy))
        WRITE_ONCE(g_first_policy, policy);
    refresh_clean_policydb("policy_commit", false);
    cancel_clean_sidtab_convert("policy_commit");
    selinux_hook_dbg("[selinux_hook] SELinux policy committed, first policy=%px first policydb=%px clean policydb=%px\n",
                     g_first_policy, g_first_policydb, READ_ONCE(g_clean_policydb));
    snapshot_clean_policy("policy_commit");
}

static void before_policydb_arg0(hook_fargs6_t *a, void *u)
{
    void *policydb = (void *)a->arg0;
    void *clean_policydb = READ_ONCE(g_clean_policydb);
    bool bypass = should_bypass_clean_filter(current_uid());

    if (!clean_policydb_redirect_supported())
        return;

    if (READ_ONCE(g_internal_policy_load_depth) ||   // 模块内部加载
        current_is_policy_manager()) {                // magiskpolicy 等
        return;  // 完全跳过，使用原始 policydb
    }
    
    
    /*
     * Only calls running in an explicit clean-eval scope may redirect policydb
     * input.  The scope is tied to current so unrelated callers on other tasks
     * remain observational and keep using the live policydb.
     */
    if (clean_policydb_redirect_supported() &&
        current_in_clean_eval_scope() && clean_policydb && !bypass) {
        a->arg0 = (uint64_t)clean_policydb;
        return;
    }

    if (!policydb)
        return;

    if (!READ_ONCE(g_selinux_ready)) {
        WRITE_ONCE(g_selinux_ready, true);
        selinux_hook_dbg("[selinux_hook] SELinux ready inferred from context_struct_compute_av\n");
    }

    if (!READ_ONCE(g_first_policydb)) {
        WRITE_ONCE(g_first_policydb, policydb);
        selinux_hook_dbg("[selinux_hook] SAVED first policydb @ %px\n", g_first_policydb);
        refresh_clean_policydb("first_compute_av", false);
        snapshot_clean_policy("first_compute_av");
        return;
    }

    if (!READ_ONCE(g_dirty_policy_seen) &&
        policydb != READ_ONCE(g_first_policydb) &&
        policydb != READ_ONCE(g_clean_policydb)) {
        WRITE_ONCE(g_dirty_policy_seen, true);
        selinux_hook_dbg("[selinux_hook] policydb changed %px -> %px, Magisk access probes will hit clean-policy EINVAL\n",
                         g_first_policydb, policydb);
    }
}

static void before_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u)
{
    struct av_decision *avd;
    void *clean_policydb;

    a->local.data0 = 0;

    before_policydb_arg0(a, u);

    clean_policydb = READ_ONCE(g_clean_policydb);
    if (!clean_policydb || (void *)a->arg0 != clean_policydb ||
        !current_in_clean_eval_scope())
        return;

    avd = (struct av_decision *)a->arg4;
    if (!avd)
        return;

    a->local.data0 = 1;
    a->local.data1 = (uint64_t)avd;
    a->local.data2 = READ_ONCE(avd->seqno);
    a->local.data3 = READ_ONCE(avd->flags);
}

static void after_context_struct_compute_av_policydb(hook_fargs6_t *a, void *u)
{
    struct av_decision *avd;

    if (!a->local.data0)
        return;

    avd = (struct av_decision *)a->local.data1;
    if (!avd)
        return;

    WRITE_ONCE(avd->seqno, SELINUX_STATUS_CLEAN_SEQUENCE);
    WRITE_ONCE(avd->flags, (u32)a->local.data3);
}

static void before_context_struct_compute_av_legacy(hook_fargs5_t *a, void *u)
{
    struct policydb *clean_pdb;
    struct context *scontext;
    struct context *tcontext;
    u16 tclass;
    struct av_decision *avd;
    struct extended_perms *xperms;
    struct av_decision clean_avd;

    if (READ_ONCE(g_internal_policy_load_depth) || current_is_policy_manager())
        return;

    clean_pdb = (struct policydb *)READ_ONCE(g_clean_policydb);
    if (clean_pdb && !READ_ONCE(g_clean_policydb_av_disabled)) {
        scontext = (struct context *)a->arg0;
        tcontext = (struct context *)a->arg1;
        tclass = (u16)a->arg2;
        avd = (struct av_decision *)a->arg3;
        xperms = (struct extended_perms *)a->arg4;

        if (context_struct_compute_av_intel(clean_pdb, scontext, tcontext,
                                            tclass, &clean_avd, xperms)) {
            clean_avd.seqno = SELINUX_STATUS_CLEAN_SEQUENCE;
            clean_avd.flags = avd->flags;
            *avd = clean_avd;
            a->skip_origin = 1;
            return;
        }

        WRITE_ONCE(g_clean_policydb_av_disabled, true);
        pr_warn("[selinux_hook] legacy clean policydb AV disabled kver=%x policydb=%px tclass=%hu; falling back to live compute\n",
                kver, clean_pdb, tclass);
    }

    if (!READ_ONCE(g_selinux_ready)) {
        WRITE_ONCE(g_selinux_ready, true);
        selinux_hook_dbg("[selinux_hook] SELinux ready inferred from legacy context_struct_compute_av\n");
    }

    snapshot_clean_policy("legacy_compute_av");
}

/* Hook: /sys/fs/selinux/access write handler */
static void before_sel_write_access(hook_fargs4_t *a, void *u)
{
    // if (current_uid() < 10000 || current_is_policy_manager()) {
    //     return; 
    // }
    // pr_info("[selinux_hook] before_sel_write_access called uid=%u\n", current_uid());
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    size_t sample_len;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;

    uid = current_uid();
    sample_len = copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid)) {
        if (should_log_live_bypass(uid))
            log_bypass_once("access", uid, sample);
        return;
    }

    if (dirtysepolicy_access_should_deny(sample, sample_len)) {
        n = READ_ONCE(g_clean_access_count) + 1;
        WRITE_ONCE(g_clean_access_count, n);
        a->local.data0 = 4;
        a->local.data1 = n;
        slot = n & (ACCESS_PROBE_SLOTS - 1);
        a->local.data2 = slot;
        g_probes[slot].id = n;
        g_probes[slot].uid = uid;
        g_probes[slot].node = "access";
        copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
        pr_info("[selinux_hook] DIRTYSEPOLICY deny /sys/fs/selinux/access #%u uid=%d comm=%s query=\"%s\"\n",
                n, uid, current_comm(), sample);
        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    if (!clean_policydb_redirect_supported()) {
        snapshot_clean_policy("legacy_access");
        if (legacy_clean_query_should_block(sample, sample_len, true)) {
            n = READ_ONCE(g_clean_access_count) + 1;
            WRITE_ONCE(g_clean_access_count, n);
            a->local.data0 = 2;
            a->local.data1 = n;
            slot = n & (ACCESS_PROBE_SLOTS - 1);
            a->local.data2 = slot;
            g_probes[slot].id = n;
            g_probes[slot].uid = uid;
            g_probes[slot].node = "access";
            copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
            a->skip_origin = 1;
            a->ret = -EINVAL;
        }
        return;
    }

    refresh_clean_policydb("access", true);

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

    if (!READ_ONCE(g_clean_policydb) && READ_ONCE(g_clean_policy_blob) &&
        legacy_should_block_access_query(sample, sample_len)) {
        a->local.data0 = 2;
        a->local.data1 = n;
        slot = n & (ACCESS_PROBE_SLOTS - 1);
        a->local.data2 = slot;
        g_probes[slot].id = n;
        g_probes[slot].uid = uid;
        g_probes[slot].node = "access";
        copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    /* Run the original selinuxfs write_op under the current task's clean scope. */
    a->local.data0 = 3;
    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "access";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

/* Hook: /sys/fs/selinux/context write handler */
static void before_sel_write_context(hook_fargs4_t *a, void *u)
{
    const char *query = (const char *)a->arg1;
    size_t size = (size_t)a->arg2;
    size_t sample_len;
    char sample[ACCESS_SAMPLE_MAX];
    u32 slot;
    u32 n;
    uid_t uid;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;

    uid = current_uid();
    sample_len = copy_query_sample(sample, query, size);

    if (should_bypass_clean_filter(uid)) {
        if (should_log_live_bypass(uid))
            log_bypass_once("context", uid, sample);
        return;
    }

    if (dirtysepolicy_context_should_hide(sample)) {
        n = READ_ONCE(g_clean_access_count) + 1;
        WRITE_ONCE(g_clean_access_count, n);
        a->local.data0 = 4;
        a->local.data1 = n;
        slot = n & (ACCESS_PROBE_SLOTS - 1);
        a->local.data2 = slot;
        g_probes[slot].id = n;
        g_probes[slot].uid = uid;
        g_probes[slot].node = "context";
        copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
        pr_info("[selinux_hook] DIRTYSEPOLICY hide /sys/fs/selinux/context #%u uid=%d comm=%s query=\"%s\"\n",
                n, uid, current_comm(), sample);
        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    if (!clean_policydb_redirect_supported()) {
        snapshot_clean_policy("legacy_context");
        if (legacy_clean_query_should_block(sample, sample_len, false)) {
            n = READ_ONCE(g_clean_access_count) + 1;
            WRITE_ONCE(g_clean_access_count, n);
            a->local.data0 = 2;
            a->local.data1 = n;
            slot = n & (ACCESS_PROBE_SLOTS - 1);
            a->local.data2 = slot;
            g_probes[slot].id = n;
            g_probes[slot].uid = uid;
            g_probes[slot].node = "context";
            copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);
            a->skip_origin = 1;
            a->ret = -EINVAL;
        }
        return;
    }

    refresh_clean_policydb("context", true);

    n = READ_ONCE(g_clean_access_count) + 1;
    WRITE_ONCE(g_clean_access_count, n);

    a->local.data1 = n;
    slot = n & (ACCESS_PROBE_SLOTS - 1);
    a->local.data2 = slot;
    g_probes[slot].id = n;
    g_probes[slot].uid = uid;
    g_probes[slot].node = "context";
    copy_bytes(g_probes[slot].query, sample, ACCESS_SAMPLE_MAX);

    a->local.data0 = 3;
    if (enter_clean_eval_scope()) {
        a->local.data3 = 1;
    } else {
        a->local.data0 = 0;
    }
}

static void after_sel_write_common(hook_fargs4_t *a, void *u)
{
    long live_ret;
    struct access_probe *probe;
    u32 id;
    u32 slot;
    u32 mode;

    if (!a->local.data0)
        return;

    mode = (u32)a->local.data0;
    id = (u32)a->local.data1;
    slot = (u32)a->local.data2;
    if (a->local.data3)
        leave_clean_eval_scope();

    probe = &g_probes[slot];
    if (probe->id != id)
        return;

    live_ret = (long)a->ret;

    /* Patch seqno in the access response buffer to match /sys/fs/selinux/status */
    if (live_ret > 0 && probe->node && probe->node[0] == 'a') {
        char *rbuf = (char *)a->arg1;
        ssize_t new_ret = patch_response_seqno(rbuf, live_ret, 1);
        if (new_ret > 0) {
            live_ret = new_ret;
            a->ret = (uint64_t)new_ret;
        }
    }

    if (mode == 2) {
        selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/%s #%u uid=%d comm=%s clean_ret=%ld clean_policy=%px clean_policydb=%px blob=%px len=%zu query=\"%s\"\n",
                         probe->node ?: "?", id, probe->uid, current_comm(), live_ret,
                         g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                         READ_ONCE(g_clean_policy_blob), READ_ONCE(g_clean_policy_len),
                         probe->query);
        return;
    }

    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/%s #%u uid=%d comm=%s clean_ret=%ld clean_policy=%px clean_policydb=%px blob=%px len=%zu query=\"%s\"\n",
                     probe->node ?: "?", id, probe->uid, current_comm(), live_ret,
                     g_clean_load_state.policy, READ_ONCE(g_clean_policydb),
                     READ_ONCE(g_clean_policy_blob), READ_ONCE(g_clean_policy_len),
                     probe->query);
}

static int install_write_op_hooks(void)
{
    unsigned long addr_access, addr_context;
    void *write_op;

    /* Prefer direct symbol lookup; fall back to LLVM-suffix variant */
    addr_access = (unsigned long)lookup_name_optional_suffix("sel_write_access");

    addr_context = (unsigned long)lookup_name_optional_suffix("sel_write_context");
    log_symbol_addr("sel_write_access", (void *)addr_access);
    log_symbol_addr("sel_write_context", (void *)addr_context);

    if (addr_access) {
        g_funcs[g_hooks++] = (void *)addr_access;
        pr_info("[selinux_hook] hook sel_write_access argc=3 mode=direct\n");
        hook_wrap((void *)addr_access, 3, before_sel_write_access, after_sel_write_common, NULL);
        selinux_hook_dbg("[selinux_hook] inline hook sel_write_access @ %lx\n", addr_access);

        if (addr_context) {
            g_funcs[g_hooks++] = (void *)addr_context;
            pr_info("[selinux_hook] hook sel_write_context argc=3 mode=direct\n");
            hook_wrap((void *)addr_context, 3, before_sel_write_context, after_sel_write_common, NULL);
            selinux_hook_dbg("[selinux_hook] inline hook sel_write_context @ %lx\n", addr_context);
        } else {
            pr_warn("[selinux_hook] sel_write_context not found, context hook skipped\n");
        }
        return 0;
    }

    /*
     * write_op[] fallback notes:
     *
     * The referenced 4.14 selinuxfs.c trees confirm:
     *   SEL_CONTEXT == 5
     *   SEL_ACCESS  == 6
     *
     * Older builds patched write_op[5]/write_op[6] with hotpatch_nosync when
     * direct sel_write_access()/sel_write_context() symbols were missing.
     * The APatch bugreport captured on this cepheus device shows:
     *   KernelPatch Version: c02
     *   KP E unknown symbol: hotpatch_nosync
     *   KP load kpm: selinux_magisk_access_filter, rc: -2
     *
     * 这不是 SELinux hook 逻辑失败，而是 KPM loader 在重定位阶段就找不到
     * hotpatch_nosync，导致 init() 都不会执行。为了让模块至少能加载并打印
     * 诊断，本分支完全避免静态导入 hotpatch_nosync；如果 direct symbol
     * 不存在，就记录降级原因，而不是再尝试写 write_op[]。
     *
     * That failure happens before module init(), so this c02-compatible build
     * deliberately avoids importing hotpatch_nosync at all.  If direct symbols
     * are absent, log the downgrade and keep the KPM loaded for diagnostics
     * instead of failing relocation.
     */
    if (!write_op_slot_fallback_allowed()) {
        pr_warn("[selinux_hook] sel_write_access unresolved; skip hardcoded write_op[%d/%d] fallback because legacy route lacks 4.14 selinux_state baseline kver=%x\n",
                SEL_WRITE_OP_CONTEXT, SEL_WRITE_OP_ACCESS, kver);
        return 0;
    }

    write_op = lookup_name_optional_suffix("write_op");
    log_symbol_addr("write_op", write_op);
    if (!write_op) {
        pr_warn("[selinux_hook] sel_write_access unresolved and write_op missing; access/context hooks skipped\n");
        return 0;
    }

    pr_warn("[selinux_hook] write_op[%d/%d] fallback unavailable on this KP core because hotpatch_nosync is not exported; direct sel_write_access hook is required\n",
            SEL_WRITE_OP_CONTEXT, SEL_WRITE_OP_ACCESS);
    return 0;
}

static void uninstall_write_op_hooks(void)
{
    /* No write_op[] slots are modified on KP c02-compatible builds. */
}

static void uninstall_inline_hooks(void)
{
    int i;

    for (i = 0; i < g_hooks; i++)
        unhook(g_funcs[i]);
    g_hooks = 0;
}

static bool filter_procattr_current(const char *hook, const char *lsm,
                                    const char *name, const void *value,
                                    size_t size)
{
    char sample[ACCESS_SAMPLE_MAX];
    size_t sample_len;
    uid_t uid;
    u32 n;
    bool clean_checked = false;
    bool blocked;
    bool manager;
    int clean_ret = 0;
    u32 clean_sid = 0;

    if (!str_eq_lit(name, "current"))
        return false;

    sample[0] = '\0';
    sample_len = value && size ? copy_query_sample(sample, (const char *)value, size) : 0;
    manager = current_is_policy_manager();
    if (!manager) {
        if (dirtysepolicy_context_should_hide(sample)) {
            clean_checked = true;
            clean_ret = -EINVAL;
        } else if (!READ_ONCE(g_clean_policydb) && READ_ONCE(g_clean_policy_blob) &&
            legacy_should_block_access_query(sample, sample_len)) {
            clean_checked = true;
            clean_ret = -EINVAL;
        } else {
            clean_ret = clean_policy_context_to_sid(sample, &clean_sid);
            clean_checked = clean_ret <= 0;
        }
        if (clean_ret == 1 && READ_ONCE(g_clean_policy_blob)) {
            clean_checked = true;
            clean_ret = clean_context_exists(sample) ? 0 : -EINVAL;
        } else if (clean_ret == 1) {
            clean_ret = 0;
        }
    }
    blocked = !manager && clean_ret == -EINVAL;

    uid = current_uid();
    n = READ_ONCE(g_procattr_current_count) + 1;
    WRITE_ONCE(g_procattr_current_count, n);

    pr_info("[selinux_hook] AUDIT /proc/self/attr/current #%u hook=%s lsm=%s uid=%d comm=%s name_ptr=%px value=%px size=%zu sample_len=%zu manager=%d clean_checked=%d clean_ret=%d clean_sid=%u clean_policydb=%px action=%s forced_ret=%d query=\"%s\"\n",
            n, hook ?: "?", lsm ?: "-", uid, current_comm(), name, value, size,
            sample_len, manager, clean_checked,
            clean_ret, clean_sid, READ_ONCE(g_clean_policydb),
            blocked ? "block" : "pass", blocked ? -EINVAL : 0, sample);
    return blocked;
}

/* Hook: security_setprocattr(lsm, name, value, size) */
static void before_security_setprocattr(hook_fargs4_t *a, void *u)
{
    const char *lsm = (const char *)a->arg0;
    const char *name = (const char *)a->arg1;
    const void *value = (const void *)a->arg2;
    size_t size = (size_t)a->arg3;
    u32 n;

    n = READ_ONCE(g_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE security_setprocattr4 #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%px arg3=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, (void *)a->arg2, size);
    }

    if (str_eq_lit(lsm, "current")) {
        if (!filter_procattr_current("security_setprocattr_compat3", NULL,
                                     lsm, (const void *)a->arg1,
                                     (size_t)a->arg2))
            return;

        a->skip_origin = 1;
        a->ret = -EINVAL;
        return;
    }

    if (lsm && !str_eq_lit(lsm, "selinux"))
        return;

    if (!filter_procattr_current("security_setprocattr", lsm, name, value, size))
        return;

    a->skip_origin = 1;
    a->ret = -EINVAL;
}

/* Hook: legacy security_setprocattr(name, value, size) */
static void before_security_setprocattr_legacy(hook_fargs3_t *a, void *u)
{
    const char *name = (const char *)a->arg0;
    const void *value = (const void *)a->arg1;
    size_t size = (size_t)a->arg2;
    u32 n;

    n = READ_ONCE(g_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE security_setprocattr3 #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, size);
    }

    if (!filter_procattr_current("security_setprocattr", NULL, name, value, size))
        return;

    a->skip_origin = 1;
    a->ret = -EINVAL;
}

/* Hook fallback: selinux_setprocattr(name, value, size) */
static void before_selinux_setprocattr(hook_fargs3_t *a, void *u)
{
    const char *name = (const char *)a->arg0;
    const void *value = (const void *)a->arg1;
    size_t size = (size_t)a->arg2;
    u32 n;

    n = READ_ONCE(g_selinux_setprocattr_probe_count);
    if (n < 16) {
        n++;
        WRITE_ONCE(g_selinux_setprocattr_probe_count, n);
        pr_info("[selinux_hook] PROBE selinux_setprocattr #%u uid=%d comm=%s arg0=%px arg1=%px arg2=%zu\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (void *)a->arg1, size);
    }

    if (!filter_procattr_current("selinux_setprocattr", NULL, name, value, size))
        return;

    a->skip_origin = 1;
    a->ret = -EINVAL;
}

static ssize_t copy_clean_status_to_user(char __user *buf, size_t count,
                                         loff_t *ppos)
{
    unsigned char status[SELINUX_STATUS_SIZE];
    loff_t pos;
    size_t avail;
    int rc;

    if (!buf || !ppos)
        return -EINVAL;

    pos = *ppos;
    if (pos < 0)
        return -EINVAL;
    if (!count || pos >= (loff_t)sizeof(status))
        return 0;

    fill_clean_status_bytes(status);

    avail = sizeof(status) - (size_t)pos;
    if (count > avail)
        count = avail;

    rc = copy_status_to_user(buf, ((char *)&status) + pos, count);
    if (rc)
        return -EFAULT;

    *ppos = pos + (loff_t)count;
    return (ssize_t)count;
}

/*
 * Hook: /sys/fs/selinux/status mmap handler
 *
 * Android libselinux and detection tools access the status page via mmap(),
 * not read(). sel_read_handle_status is therefore never called. We hook
 * sel_mmap_handle_status instead and patch the sequence field in the mapped
 * page to keep it consistent with our spoofed read() path.
 *
 * struct selinux_kernel_status layout (20 bytes):
 *   u32 version;      offset  0
 *   u32 sequence;     offset  4  ← patch to clean value (0 or 4)
 *   u32 enforcing;    offset  8  (always 1; not patched)
 *   u32 policyload;   offset 12  ← patch to clean value (0 or 1)
 *   u32 deny_unknown; offset 16  (always 1; not patched)
 *
 * struct vm_area_struct vm_start offset:
 *   kernel < 6.1 (no PER_VMA_LOCK): offset 0
 *   kernel >= 6.1 (CONFIG_PER_VMA_LOCK): int(4)+pad(4)+ptr(8) = offset 16
 */
static void after_sel_mmap_handle_status(hook_fargs2_t *a, void *u)
{
    void *vma;
    unsigned long vm_start = 0;
    unsigned long vm_start_off;
    u32 n;

    if ((int)a->ret != 0)
        return;

    vma = (void *)a->arg1;
    if (!vma)
        return;

    /* vm_start offset depends on CONFIG_PER_VMA_LOCK presence */
    vm_start_off = (kver >= VERSION(6, 1, 0)) ? 16 : 0;

    if (!copy_from_kernel_nofault_fn ||
        copy_from_kernel_nofault_fn(&vm_start, (char *)vma + vm_start_off,
                                    sizeof(vm_start)) != 0)
        return;

    /* Sanity check: must look like a user virtual address */
    if (!vm_start || vm_start < 0x10000UL || vm_start >= 0xffffff0000000000UL)
        return;

    /* Patch sequence (offset 4) and policyload (offset 12) in struct selinux_kernel_status */
    if (copy_to_user_nofault_fn) {
        unsigned char patch_bytes[4];
        /* sequence at offset 4 */
        put_u32_le(patch_bytes, get_u32_le(g_clean_status_bytes + 4));
        copy_to_user_nofault_fn((void __user *)(vm_start + 4), patch_bytes, 4);
        /* policyload at offset 12 */
        put_u32_le(patch_bytes, get_u32_le(g_clean_status_bytes + 12));
        copy_to_user_nofault_fn((void __user *)(vm_start + 12), patch_bytes, 4);
    }

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);
    selinux_hook_dbg("[selinux_hook] STATUS mmap patch #%u uid=%d comm=%s vm_start=%lx seq=%u pload=%u\n",
                     n, current_uid(), current_comm(), vm_start,
                     get_u32_le(g_clean_status_bytes + 4),
                     get_u32_le(g_clean_status_bytes + 12));
}

/*
 * Hook: selinux_status_update_seqlock
 *
 * Prevents the kernel from updating the sequence field in the status page.
 * Old kernels (< 6.6): detection expects sequence=0 policyload=0 (initial state).
 * Skip the update entirely so the status page stays frozen at 0/0.
 *
 * Kernel < 5.19: selinux_status_update_seqlock(struct selinux_state *state)  argc=1
 * Kernel >= 5.19: selinux_status_update_seqlock(void)                        argc=0
 */
static void before_selinux_status_update_seqlock(hook_fargs4_t *a, void *u)
{
    if (kver < VERSION(6, 6, 0))
        a->skip_origin = 1;
}

/*
 * Hook: selinux_status_update_policyload
 *
 * Prevents the policyload counter in the status page from incrementing.
 *
 * Kernel < 5.19: selinux_status_update_policyload(state, seqno)  argc=2
 * Kernel >= 5.19: selinux_status_update_policyload(seqno)        argc=1
 */
static void before_selinux_status_update_policyload(hook_fargs4_t *a, void *u)
{
    if (kver < VERSION(6, 6, 0))
        a->skip_origin = 1;
}
static void before_sel_read_handle_status(hook_fargs4_t *a, void *u)
{
    uid_t uid = current_uid();
    ssize_t ret;
    u32 n;
    u32 probe;
    loff_t pos_before = -1;
    loff_t pos_after = -1;

    a->local.data0 = 0;
    a->local.data1 = 0;
    a->local.data2 = 0;
    a->local.data3 = 0;

    if (should_bypass_clean_filter(uid))
        return;

    probe = READ_ONCE(g_status_probe_count) + 1;
    WRITE_ONCE(g_status_probe_count, probe);
    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_before, (void *)a->arg3,
                                        sizeof(pos_before)) != 0)
            pos_before = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_before = *(loff_t *)a->arg3;
    }

    if (READ_ONCE(g_simple_read_from_buffer_hooked) && enter_status_read_scope()) {
        a->local.data0 = 1;
        a->local.data1 = probe;
        a->local.data2 = (uint64_t)pos_before;
        a->local.data3 = uid;
        return;
    }

    ret = copy_clean_status_to_user((char __user *)a->arg1,
                                    (size_t)a->arg2,
                                    (loff_t *)a->arg3);
    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_after, (void *)a->arg3,
                                        sizeof(pos_after)) != 0)
            pos_after = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_after = *(loff_t *)a->arg3;
    }

    if (probe <= 16)
        pr_info("[selinux_hook] STATUS probe #%u uid=%d comm=%s file=%px buf=%px count=%zu ppos=%px pos_before=%lld ret=%zd pos_after=%lld copy=%s clean_version=%u clean_sequence=%u clean_policyload=%u\n",
                probe, uid, current_comm(), (void *)a->arg0,
                (void *)a->arg1, (size_t)a->arg2, (void *)a->arg3,
                pos_before, ret, pos_after, g_copy_to_user_name ?: "compat_copy_to_user",
                SELINUX_KERNEL_STATUS_VERSION,
                SELINUX_STATUS_CLEAN_SEQUENCE,
                SELINUX_STATUS_CLEAN_POLICYLOAD);

    if (ret < 0)
        return;

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);

    a->skip_origin = 1;
    a->ret = (uint64_t)ret;
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/status #%u uid=%d comm=%s ret=%zd sequence=%u policyload=%u copy=%s\n",
                     n, uid, current_comm(), ret,
                     SELINUX_STATUS_CLEAN_SEQUENCE,
                     SELINUX_STATUS_CLEAN_POLICYLOAD,
                     g_copy_to_user_name ?: "compat_copy_to_user");
}

static void after_sel_read_handle_status(hook_fargs4_t *a, void *u)
{
    loff_t pos_after = -1;
    u32 probe;
    u32 n;
    bool patched;

    if (!a->local.data0)
        return;

    if (a->arg3) {
        if (copy_from_kernel_nofault_fn &&
            copy_from_kernel_nofault_fn(&pos_after, (void *)a->arg3,
                                        sizeof(pos_after)) != 0)
            pos_after = -2;
        else if (!copy_from_kernel_nofault_fn)
            pos_after = *(loff_t *)a->arg3;
    }

    patched = current_status_read_scope_patched();
    leave_status_read_scope();

    probe = (u32)a->local.data1;
    if (probe <= 16)
        pr_info("[selinux_hook] STATUS probe #%u uid=%u comm=%s mode=simple_read ret=%ld pos_before=%lld pos_after=%lld\n",
                probe, (u32)a->local.data3, current_comm(), (long)a->ret,
                (loff_t)a->local.data2, pos_after);

    if (!patched || (long)a->ret < 0)
        return;

    n = READ_ONCE(g_status_read_count) + 1;
    WRITE_ONCE(g_status_read_count, n);
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/status #%u uid=%u comm=%s mode=simple_read ret=%ld sequence=%u policyload=%u\n",
                     n, (u32)a->local.data3, current_comm(), (long)a->ret,
                     SELINUX_STATUS_CLEAN_SEQUENCE,
                     SELINUX_STATUS_CLEAN_POLICYLOAD);
}

static void before_simple_read_from_buffer(hook_fargs5_t *a, void *u)
{
    unsigned char *from;
    u32 n;

    a->local.data0 = 0;

    if (!current_in_status_read_scope())
        return;
    if ((size_t)a->arg4 != sizeof(g_clean_status_bytes))
        return;

    from = (unsigned char *)a->arg3;
    if (!from)
        return;

    copy_bytes(&a->local.data2, from, sizeof(g_clean_status_bytes));
    copy_bytes(from, g_clean_status_bytes, sizeof(g_clean_status_bytes));
    mark_status_read_scope_patched();

    a->local.data0 = 1;
    a->local.data1 = (uint64_t)from;

    n = READ_ONCE(g_status_redirect_count) + 1;
    WRITE_ONCE(g_status_redirect_count, n);
    if (n <= 16)
        pr_info("[selinux_hook] STATUS v3 simple_read patch #%u uid=%d comm=%s to=%px count=%zu ppos=%px from=%px available=%zu old=%u,%u,%u,%u,%u clean=%u,%u,%u,%u,%u bytes=%02x %02x %02x %02x\n",
                n, current_uid(), current_comm(), (void *)a->arg0,
                (size_t)a->arg1, (void *)a->arg2, from,
                (size_t)a->arg4,
                get_u32_le((unsigned char *)&a->local.data2 + 0),
                get_u32_le((unsigned char *)&a->local.data2 + 4),
                get_u32_le((unsigned char *)&a->local.data2 + 8),
                get_u32_le((unsigned char *)&a->local.data2 + 12),
                get_u32_le((unsigned char *)&a->local.data2 + 16),
                get_u32_le(g_clean_status_bytes + 0),
                get_u32_le(g_clean_status_bytes + 4),
                get_u32_le(g_clean_status_bytes + 8),
                get_u32_le(g_clean_status_bytes + 12),
                get_u32_le(g_clean_status_bytes + 16),
                g_clean_status_bytes[0], g_clean_status_bytes[1],
                g_clean_status_bytes[2], g_clean_status_bytes[3]);
}

static void after_simple_read_from_buffer(hook_fargs5_t *a, void *u)
{
    unsigned char *from;

    if (!a->local.data0)
        return;

    from = (unsigned char *)a->local.data1;
    if (!from)
        return;

    copy_bytes(from, &a->local.data2, sizeof(g_clean_status_bytes));
}

static void before_security_read_policy_common(hook_fargs4_t *a, void **out_data,
                                               size_t *out_len)
{
    void *snapshot = READ_ONCE(g_clean_policy_blob);
    size_t len = READ_ONCE(g_clean_policy_len);
    void *copy;
    u32 n;

    if (!snapshot || !len || !out_data || !out_len)
        return;
    if (current_is_policy_manager()) {
        if (should_log_live_bypass(current_uid()))
            log_bypass_once("policy", current_uid(), NULL);
        return;
    }

    if (!vmalloc_fn) {
        pr_warn("[selinux_hook] CLEAN policy read copy disabled: vmalloc unavailable\n");
        return;
    }

    /* Cache hit: a previous reader already vfree'd-into-cache for this
     * exact source pointer.  Reuse the cached vmalloc buffer — no fresh
     * allocation, no leak. */
    if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_policy_cache_lock);
    if (g_policy_read_cache && g_policy_read_cache_src == snapshot &&
        g_policy_read_cache_len == len) {
        copy = g_policy_read_cache;
        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_policy_cache_lock);
    } else {
        void *stale = g_policy_read_cache;

        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_policy_cache_lock);

        copy = vmalloc_fn(len);
        if (!copy) {
            pr_warn("[selinux_hook] CLEAN policy read copy alloc failed len=%zu\n", len);
            return;
        }
        copy_bytes(copy, snapshot, len);

        if (g_raw_spin_lock_fn)
        g_raw_spin_lock_fn(&g_policy_cache_lock);
        g_policy_read_cache = copy;
        g_policy_read_cache_len = len;
        g_policy_read_cache_src = snapshot;
        if (g_raw_spin_unlock_fn)
        g_raw_spin_unlock_fn(&g_policy_cache_lock);

        if (stale && vfree_fn)
            vfree_fn(stale);
    }

    *out_data = copy;
    *out_len = len;

    n = READ_ONCE(g_policy_read_count) + 1;
    WRITE_ONCE(g_policy_read_count, n);

    a->skip_origin = 1;
    a->ret = 0;
    selinux_hook_dbg("[selinux_hook] CLEAN /sys/fs/selinux/policy read #%u uid=%d comm=%s blob=%px copy=%px len=%zu\n",
                     n, current_uid(), current_comm(), snapshot, copy, len);
}

/* Hook: /sys/fs/selinux/policy read backend, security_read_policy(data, len) */
static void before_security_read_policy(hook_fargs2_t *a, void *u)
{
    before_security_read_policy_common(a, (void **)a->arg0, (size_t *)a->arg1);
}

/* Hook: /sys/fs/selinux/policy read backend, security_read_policy(state, data, len) */
static void before_security_read_policy_compat(hook_fargs3_t *a, void *u)
{
    before_security_read_policy_common(a, (void **)a->arg1, (size_t *)a->arg2);
}

static long init(const char *args, const char *event, void *__user r)
{
    unsigned long addr;
    int rc;

    selinux_hook_dbg("[selinux_hook] init event=%s\n", event ?: "(null)");

    /* Initialize clean status bytes based on kernel version */
    fill_clean_status_bytes(g_clean_status_bytes);
    selinux_hook_dbg("[selinux_hook] clean status: kver=%u.%u seq=%u pload=%u\n",
                     (unsigned)(kver >> 16), (unsigned)((kver >> 8) & 0xff),
                     get_u32_le(g_clean_status_bytes + 4),
                     get_u32_le(g_clean_status_bytes + 12));
    pr_info("[selinux_hook] kernel kver=%x legacy_blob=%d blob_route=%d\n",
            kver, use_legacy_clean_blob_query() ? 1 : 0,
            use_clean_blob_route() ? 1 : 0);
    resolve_required_symbols_once();

    /* Raw spinlock helpers — kfunc wrappers are not exported on this kernel,
     * so resolve through kallsyms and call via function pointer.  The locks
     * become no-ops if resolution fails, which is acceptable for these
     * scope arrays (they only see per-task scope entry/exit pairs that
     * are also serialized against themselves). */
    g_raw_spin_lock_fn = (raw_spin_lock_fn_t)lookup_name_optional_suffix("_raw_spin_lock");
    g_raw_spin_unlock_fn = (raw_spin_unlock_fn_t)lookup_name_optional_suffix("_raw_spin_unlock");
    if (!g_raw_spin_lock_fn || !g_raw_spin_unlock_fn)
        pr_warn("[selinux_hook] raw_spin_lock/unlock unresolved: lock=%px unlock=%px; scope/cache lock will be a no-op\n",
                g_raw_spin_lock_fn, g_raw_spin_unlock_fn);

    copy_from_kernel_nofault_fn = (void *)lookup_name_optional_suffix("copy_from_kernel_nofault");
    if (!copy_from_kernel_nofault_fn)
        copy_from_kernel_nofault_fn = (void *)lookup_name_optional_suffix("probe_kernel_read");
    copy_to_user_nofault_fn = (void *)lookup_name_optional_suffix("copy_to_user_nofault");
    if (copy_to_user_nofault_fn) {
        g_copy_to_user_name = "copy_to_user_nofault";
    } else {
        copy_to_user_raw_fn = (void *)lookup_name_optional_suffix("_copy_to_user");
        if (copy_to_user_raw_fn) {
            g_copy_to_user_name = "_copy_to_user";
        } else {
            copy_to_user_raw_fn = (void *)lookup_name_optional_suffix("__copy_to_user");
            if (copy_to_user_raw_fn)
                g_copy_to_user_name = "__copy_to_user";
        }
    }
    if (!copy_to_user_nofault_fn && !copy_to_user_raw_fn)
        pr_warn("[selinux_hook] cannot find raw copy_to_user, status hook will use compat_copy_to_user fallback\n");
    vmalloc_fn = (void *)lookup_name_optional_suffix("vmalloc");
    if (!vmalloc_fn)
        vmalloc_fn = (void *)lookup_name_optional_suffix("vmalloc_noprof");
    vfree_fn = (void *)lookup_name_optional_suffix("vfree");
    init_task_ptr = lookup_name_optional_suffix("init_task");
    filp_open_fn = (void *)lookup_name_optional_suffix("filp_open");
    filp_close_fn = (void *)lookup_name_optional_suffix("filp_close");
    kernel_read_fn = (void *)lookup_name_optional_suffix("kernel_read");
    vfs_llseek_fn = (void *)lookup_name_optional_suffix("vfs_llseek");
    g_selinux_state = lookup_name_optional_suffix("selinux_state");
    if (!init_task_ptr)
        pr_warn("[selinux_hook] cannot find init_task, mock policy process gate disabled\n");
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn || !vfs_llseek_fn)
        pr_warn("[selinux_hook] cannot find file-read symbols: filp_open=%px filp_close=%px kernel_read=%px vfs_llseek=%px\n",
                filp_open_fn, filp_close_fn, kernel_read_fn, vfs_llseek_fn);
    security_load_policy_fn = (void *)lookup_name_optional_suffix("security_load_policy");
    security_load_policy_compat_fn = (void *)security_load_policy_fn;
    security_context_to_sid_fn = (void *)lookup_name_optional_suffix("security_context_to_sid");
    security_context_to_sid_compat_fn = (void *)security_context_to_sid_fn;
    policydb_read_fn = (void *)lookup_name_optional_suffix("policydb_read");
    policydb_destroy_fn = (void *)lookup_name_optional_suffix("policydb_destroy");
    flex_array_get_fn = (void *)lookup_name_optional_suffix("flex_array_get");
    avtab_search_node_fn = (void *)lookup_name_optional_suffix("avtab_search_node");
    avtab_search_node_next_fn = (void *)lookup_name_optional_suffix("avtab_search_node_next");
    cond_compute_av_fn = (void *)lookup_name_optional_suffix("cond_compute_av");
    constraint_expr_eval_fn = (void *)lookup_name_optional_suffix("constraint_expr_eval");
    type_attribute_bounds_av_fn = (void *)lookup_name_optional_suffix("type_attribute_bounds_av");
    selinux_policy_cancel_fn = (void *)lookup_name_optional_suffix("selinux_policy_cancel");
    selinux_policy_cancel_compat_fn = (void *)selinux_policy_cancel_fn;
    sidtab_cancel_convert_fn = (void *)lookup_name_optional_suffix("sidtab_cancel_convert");
    security_read_policy_fn = (void *)lookup_name_optional_suffix("security_read_policy");
    security_read_policy_compat_fn = (void *)security_read_policy_fn;
    log_symbol_addr("selinux_state", g_selinux_state);
    log_symbol_addr("security_read_policy", (void *)security_read_policy_fn);
    log_symbol_addr("security_context_to_sid", (void *)security_context_to_sid_fn);
    log_symbol_addr("security_load_policy", (void *)security_load_policy_fn);
    log_symbol_addr("policydb_read", (void *)policydb_read_fn);
    log_symbol_addr("policydb_destroy", (void *)policydb_destroy_fn);
    log_symbol_addr("avtab_search_node", (void *)avtab_search_node_fn);
    log_symbol_addr("avtab_search_node_next", (void *)avtab_search_node_next_fn);
    log_symbol_addr("cond_compute_av", (void *)cond_compute_av_fn);
    log_symbol_addr("constraint_expr_eval", (void *)constraint_expr_eval_fn);
    log_symbol_addr("type_attribute_bounds_av", (void *)type_attribute_bounds_av_fn);
    log_symbol_addr("selinux_policy_cancel", (void *)selinux_policy_cancel_fn);
    log_symbol_addr("sidtab_cancel_convert", (void *)sidtab_cancel_convert_fn);
    pr_info("[selinux_hook] compat route: state_calls=%d policydb_redirect=%d policydb_offset_fallback=%d write_op_fallback=%d load_state=%d\n",
            selinux_compat_call_needed() ? 1 : 0,
            clean_policydb_redirect_supported() ? 1 : 0,
            policydb_offset_fallback_allowed() ? 1 : 0,
            write_op_slot_fallback_allowed() ? 1 : 0,
            security_load_policy_has_load_state() ? 1 : 0);
    if (selinux_compat_call_needed())
        pr_info("[selinux_hook] SELinux compat calls enabled kver=%x state=%px\n",
                kver, g_selinux_state);
    if (!sidtab_cancel_convert_fn)
        pr_warn("[selinux_hook] cannot find sidtab_cancel_convert, clean snapshot may leave live policy busy\n");
    if (!security_read_policy_fn)
        pr_warn("[selinux_hook] cannot find security_read_policy, clean policy snapshot disabled\n");
    else
        snapshot_clean_policy("module_init");
    if (!security_context_to_sid_fn)
        pr_warn("[selinux_hook] cannot find security_context_to_sid, procattr clean policydb query will use blob fallback\n");
    if (!policydb_read_fn || !policydb_destroy_fn)
        pr_warn("[selinux_hook] cannot find policydb_read/policydb_destroy, legacy clean policydb disabled\n");
    if (!flex_array_get_fn || !avtab_search_node_fn || !avtab_search_node_next_fn)
        pr_warn("[selinux_hook] intel_av missing core lookup helpers flex_array_get=%px avtab_search_node=%px avtab_search_node_next=%px\n",
                flex_array_get_fn, avtab_search_node_fn, avtab_search_node_next_fn);
    if (!cond_compute_av_fn)
        pr_warn("[selinux_hook] intel_av cannot find cond_compute_av, conditional av rules will be skipped\n");
    if (!constraint_expr_eval_fn)
        pr_warn("[selinux_hook] intel_av cannot find constraint_expr_eval, class constraints will be skipped\n");
    if (!type_attribute_bounds_av_fn)
        pr_warn("[selinux_hook] intel_av cannot find type_attribute_bounds_av, type bounds masking will be skipped\n");

    if (security_read_policy_fn) {
        int argc = selinux_compat_call_needed() ? 3 : 2;
        g_funcs[g_hooks++] = (void *)security_read_policy_fn;
        pr_info("[selinux_hook] hook security_read_policy argc=%d\n", argc);
        if (selinux_compat_call_needed())
            hook_wrap((void *)security_read_policy_fn, 3, before_security_read_policy_compat, NULL, NULL);
        else
            hook_wrap((void *)security_read_policy_fn, 2, before_security_read_policy, NULL, NULL);
    }

    addr = (unsigned long)lookup_name_optional_suffix("simple_read_from_buffer");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        WRITE_ONCE(g_simple_read_from_buffer_hooked, true);
        selinux_hook_dbg("[selinux_hook] hook simple_read_from_buffer argc=5 for status patch\n");
        hook_wrap((void *)addr, 5, before_simple_read_from_buffer,
                  after_simple_read_from_buffer, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find simple_read_from_buffer, status hook will use direct user copy fallback\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("sel_read_handle_status");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook sel_read_handle_status argc=4\n");
        hook_wrap((void *)addr, 4, before_sel_read_handle_status,
                  after_sel_read_handle_status, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find sel_read_handle_status, status read hook skipped\n");
    }

    /* Hook the mmap handler; Android libselinux uses mmap() not read(). */
    addr = (unsigned long)lookup_name_optional_suffix("sel_mmap_handle_status");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook sel_mmap_handle_status argc=2\n");
        hook_wrap((void *)addr, 2, NULL, after_sel_mmap_handle_status, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find sel_mmap_handle_status, status mmap patch skipped\n");
    }

    /* Freeze status page sequence/policyload on old kernels */
    addr = (unsigned long)lookup_name_optional_suffix("selinux_status_update_seqlock");
    if (addr) {
        /* argc=1 on < 5.19 (state arg), argc=0 on >= 5.19 */
        int argc = (kver < VERSION(5, 19, 0)) ? 1 : 0;
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook selinux_status_update_seqlock argc=%d kver=%x\n", argc, kver);
        hook_wrap((void *)addr, argc, before_selinux_status_update_seqlock, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_status_update_seqlock\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_status_update_policyload");
    if (addr) {
        /* argc=2 on < 5.19 (state, seqno), argc=1 on >= 5.19 (seqno) */
        int argc = (kver < VERSION(5, 19, 0)) ? 2 : 1;
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook selinux_status_update_policyload argc=%d kver=%x\n", argc, kver);
        hook_wrap((void *)addr, argc, before_selinux_status_update_policyload, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_status_update_policyload\n");
    }

    if (!security_load_policy_fn) {
        pr_warn("[selinux_hook] cannot find security_load_policy, live policy load audit disabled\n");
    } else {
        selinux_hook_dbg("[selinux_hook] security_load_policy hook skipped; clean snapshots call it directly\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("security_setprocattr");
    if (addr) {
        bool setprocattr_lsm_arg = security_setprocattr_has_lsm_arg();

        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook security_setprocattr argc=%d\n",
                         setprocattr_lsm_arg ? 4 : 3);
        if (setprocattr_lsm_arg)
            hook_wrap((void *)addr, 4, before_security_setprocattr, NULL, NULL);
        else
            hook_wrap((void *)addr, 3, before_security_setprocattr_legacy, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find security_setprocattr\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_setprocattr");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        selinux_hook_dbg("[selinux_hook] hook selinux_setprocattr argc=3\n");
        hook_wrap((void *)addr, 3, before_selinux_setprocattr, NULL, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_setprocattr\n");
    }

    rc = install_write_op_hooks();
    if (rc) {
        uninstall_inline_hooks();
        return rc;
    }

    addr = (unsigned long)lookup_name_optional_suffix("context_struct_compute_av");
    if (addr) {
        if (clean_policydb_redirect_supported()) {
            g_funcs[g_hooks++] = (void *)addr;
            pr_info("[selinux_hook] hook context_struct_compute_av argc=6\n");
            hook_wrap((void *)addr, 6, before_context_struct_compute_av_policydb,
                      after_context_struct_compute_av_policydb, NULL);
        } else {
            g_funcs[g_hooks++] = (void *)addr;
            pr_info("[selinux_hook] hook legacy context_struct_compute_av argc=5\n");
            hook_wrap((void *)addr, 5, before_context_struct_compute_av_legacy, NULL, NULL);
        }
    } else {
        pr_warn("[selinux_hook] cannot find context_struct_compute_av\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("string_to_context_struct");
    if (addr && clean_policydb_redirect_supported()) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook string_to_context_struct argc=5\n");
        hook_wrap((void *)addr, 5, before_policydb_arg0, NULL, NULL);
    } else if (addr) {
        pr_info("[selinux_hook] skip legacy string_to_context_struct policydb redirect\n");
    } else {
        pr_warn("[selinux_hook] cannot find string_to_context_struct\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_complete_init");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook selinux_complete_init argc=0\n");
        hook_wrap((void *)addr, 0, NULL, after_selinux_complete_init, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_complete_init\n");
    }

    addr = (unsigned long)lookup_name_optional_suffix("selinux_policy_commit");
    if (addr) {
        g_funcs[g_hooks++] = (void *)addr;
        pr_info("[selinux_hook] hook selinux_policy_commit argc=1\n");
        hook_wrap((void *)addr, 1, NULL, after_selinux_policy_commit, NULL);
    } else {
        pr_warn("[selinux_hook] cannot find selinux_policy_commit\n");
    }

    selinux_hook_dbg("[selinux_hook] %d hooks installed\n", g_hooks);
    return 0;
}

static long exit_(void *__user r)
{
    uninstall_write_op_hooks();
    uninstall_inline_hooks();

    if (READ_ONCE(g_clean_policydb_direct) && g_clean_policydb) {
        if (policydb_destroy_fn)
            policydb_destroy_fn((struct policydb *)g_clean_policydb);
        if (vfree_fn)
            vfree_fn(g_clean_policydb);
        g_clean_policydb = NULL;
        g_clean_policydb_direct = false;
    }

    if (g_clean_load_state_ready && (selinux_policy_cancel_fn || selinux_policy_cancel_compat_fn)) {
        call_selinux_policy_cancel(&g_clean_load_state);
        g_clean_load_state_ready = false;
        g_clean_load_state.policy = NULL;
        g_clean_load_state.convert_data = NULL;
        g_clean_policydb = NULL;
        g_clean_policydb_direct = false;
    }

    if (g_clean_policy_blob) {
        if (vfree_fn)
            vfree_fn(g_clean_policy_blob);
        g_clean_policy_blob = NULL;
        g_clean_policy_len = 0;
    }

    if (g_policy_read_cache) {
        if (vfree_fn)
            vfree_fn(g_policy_read_cache);
        g_policy_read_cache = NULL;
        g_policy_read_cache_len = 0;
        g_policy_read_cache_src = NULL;
    }

    selinux_hook_dbg("[selinux_hook] exited\n");
    return 0;
}
static long control(const char* args, char* __user out_msg, int outlen) {

    int rc = 0;
    char echo[64] = "";
    if (rc < 0) {
    sprintf(echo, "error, rc=%d\n", rc);
        logke("fg_sram_write %s", echo);
        if (out_msg) {
            compat_copy_to_user(out_msg, echo, sizeof(echo));
            return 1;
        }
    } else {
        sprintf(echo, "success resp\n");
        logki("fg_sram_write %s", echo);
        if (out_msg) {
            compat_copy_to_user(out_msg, echo, sizeof(echo));
            return 0;
        }
    }
    return 0;
}
KPM_INIT(init);
KPM_CTL0(control);
KPM_EXIT(exit_);
