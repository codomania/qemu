/*
 * QEMU SEV support
 *
 * Copyright Advanced Micro Devices 2016-2018
 *
 * Author:
 *      Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <sys/ioctl.h>
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "qemu/base64.h"
#include "sysemu/kvm.h"
#include "sysemu/sev.h"
#include "sysemu/sysemu.h"
#include "trace.h"
#include "qapi-event.h"
#include "migration/blocker.h"
#include "migration/qemu-file.h"
#include "migration/misc.h"

#include <sys/ioctl.h>
#include <linux/psp-sev.h>

#define DEFAULT_GUEST_POLICY    0x1 /* disable debug */
#define DEFAULT_SEV_DEVICE      "/dev/sev"
#define GUEST_POLICY_DBG_BIT    0x1

static uint64_t me_mask;
static bool sev_active;
static int sev_fd;
static SEVState *sev_state;
static MemoryRegionRAMReadWriteOps  sev_ops;
static Error *sev_mig_blocker;

#define SEV_FW_MAX_ERROR      0x17

static SevGuestState current_sev_guest_state = SEV_STATE_UNINIT;

static const char *const sev_state_str[] = {
    "uninit",
    "lupdate",
    "secret",
    "running",
    "supdate",
    "rupdate",
};

static const char *const sev_fw_errlist[] = {
    "",
    "Platform state is invalid",
    "Guest state is invalid",
    "Platform configuration is invalid",
    "Buffer too small",
    "Platform is already owned",
    "Certificate is invalid",
    "Policy is not allowed",
    "Guest is not active",
    "Invalid address",
    "Bad signature",
    "Bad measurement",
    "Asid is already owned",
    "Invalid ASID",
    "WBINVD is required",
    "DF_FLUSH is required",
    "Guest handle is invalid",
    "Invalid command",
    "Guest is active",
    "Hardware error",
    "Hardware unsafe",
    "Feature not supported",
    "Invalid parameter"
};

static int
sev_ioctl(int cmd, void *data, int *error)
{
    int r;
    struct kvm_sev_cmd input;

    memset(&input, 0x0, sizeof(input));

    input.id = cmd;
    input.sev_fd = sev_fd;
    input.data = (__u64)data;

    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &input);

    if (error) {
        *error = input.error;
    }

    return r;
}

static int
sev_platform_ioctl(int cmd, void *data, int *error)
{
    int r;
    struct sev_issue_cmd arg;

    arg.cmd = cmd;
    arg.data = (unsigned long)data;
    r = ioctl(sev_fd, SEV_ISSUE_CMD, &arg);
    if (error) {
        *error = arg.error;
    }

    return r;
}

static const char *
fw_error_to_str(int code)
{
    if (code >= SEV_FW_MAX_ERROR) {
        return "unknown error";
    }

    return sev_fw_errlist[code];
}

static bool
sev_check_state(SevGuestState state)
{
    return current_sev_guest_state == state ? true : false;
}

static void
sev_set_guest_state(SevGuestState new_state)
{
    assert(new_state < SEV_STATE_MAX);

    trace_kvm_sev_change_state(sev_state_str[current_sev_guest_state],
                               sev_state_str[new_state]);
    current_sev_guest_state = new_state;
}

static void
sev_ram_block_added(RAMBlockNotifier *n, void *host, size_t size)
{
    int r;
    struct kvm_enc_region range;

    range.addr = (__u64)host;
    range.size = size;

    trace_kvm_memcrypt_register_region(host, size);
    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_REG_REGION, &range);
    if (r) {
        error_report("%s: failed to register region (%p+%#lx)",
                     __func__, host, size);
    }
}

static void
sev_ram_block_removed(RAMBlockNotifier *n, void *host, size_t size)
{
    int r;
    struct kvm_enc_region range;

    range.addr = (__u64)host;
    range.size = size;

    trace_kvm_memcrypt_unregister_region(host, size);
    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_UNREG_REGION, &range);
    if (r) {
        error_report("%s: failed to unregister region (%p+%#lx)",
                     __func__, host, size);
    }
}

static struct RAMBlockNotifier sev_ram_notifier = {
    .ram_block_added = sev_ram_block_added,
    .ram_block_removed = sev_ram_block_removed,
};

static void
qsev_guest_finalize(Object *obj)
{
}

static char *
qsev_guest_get_session_file(Object *obj, Error **errp)
{
    QSevGuestInfo *s = QSEV_GUEST_INFO(obj);

    return s->session_file ? g_strdup(s->session_file) : NULL;
}

static void
qsev_guest_set_session_file(Object *obj, const char *value, Error **errp)
{
    QSevGuestInfo *s = QSEV_GUEST_INFO(obj);

    s->session_file = g_strdup(value);
}

static char *
qsev_guest_get_dh_cert_file(Object *obj, Error **errp)
{
    QSevGuestInfo *s = QSEV_GUEST_INFO(obj);

    return g_strdup(s->dh_cert_file);
}

static void
qsev_guest_set_dh_cert_file(Object *obj, const char *value, Error **errp)
{
    QSevGuestInfo *s = QSEV_GUEST_INFO(obj);

    s->dh_cert_file = g_strdup(value);
}

static char *
qsev_guest_get_sev_device(Object *obj, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    return g_strdup(sev->sev_device);
}

static void
qsev_guest_set_sev_device(Object *obj, const char *value, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    sev->sev_device = g_strdup(value);
}

static void
qsev_guest_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "sev-device",
                                  qsev_guest_get_sev_device,
                                  qsev_guest_set_sev_device,
                                  NULL);
    object_class_property_set_description(oc, "sev-device",
            "SEV device to use", NULL);
    object_class_property_add_str(oc, "dh-cert-file",
                                  qsev_guest_get_dh_cert_file,
                                  qsev_guest_set_dh_cert_file,
                                  NULL);
    object_class_property_set_description(oc, "dh-cert-file",
            "guest owners DH certificate (encoded with base64)", NULL);
    object_class_property_add_str(oc, "session-file",
                                  qsev_guest_get_session_file,
                                  qsev_guest_set_session_file,
                                  NULL);
    object_class_property_set_description(oc, "session-file",
            "guest owners session parameters (encoded with base64)", NULL);
}

static void
qsev_guest_set_handle(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint32_t value;

    visit_type_uint32(v, name, &value, errp);
    sev->handle = value;
}

static void
qsev_guest_set_policy(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint32_t value;

    visit_type_uint32(v, name, &value, errp);
    sev->policy = value;
}

static void
qsev_guest_set_cbitpos(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint32_t value;

    visit_type_uint32(v, name, &value, errp);
    sev->cbitpos = value;
}

static void
qsev_guest_get_policy(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    uint32_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->policy;
    visit_type_uint32(v, name, &value, errp);
}

static void
qsev_guest_get_handle(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    uint32_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->handle;
    visit_type_uint32(v, name, &value, errp);
}

static void
qsev_guest_get_cbitpos(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    uint32_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->cbitpos;
    visit_type_uint32(v, name, &value, errp);
}

static uint32_t
sev_get_host_cbitpos(void)
{
    uint32_t ebx;

    host_cpuid(0x8000001F, 0, NULL, &ebx, NULL, NULL);

    return ebx & 0x3f;
}

static void
qsev_guest_init(Object *obj)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);
    sev->policy = DEFAULT_GUEST_POLICY;
    sev->cbitpos = sev_get_host_cbitpos();
    object_property_add(obj, "policy", "uint32", qsev_guest_get_policy,
                        qsev_guest_set_policy, NULL, NULL, NULL);
    object_property_add(obj, "handle", "uint32", qsev_guest_get_handle,
                        qsev_guest_set_handle, NULL, NULL, NULL);
    object_property_add(obj, "cbitpos", "uint32", qsev_guest_get_cbitpos,
                        qsev_guest_set_cbitpos, NULL, NULL, NULL);
}

/* sev guest info */
static const TypeInfo qsev_guest_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_QSEV_GUEST_INFO,
    .instance_size = sizeof(QSevGuestInfo),
    .instance_finalize = qsev_guest_finalize,
    .class_size = sizeof(QSevGuestInfoClass),
    .class_init = qsev_guest_class_init,
    .instance_init = qsev_guest_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static QSevGuestInfo *
lookup_sev_guest_info(const char *id)
{
    Object *obj;
    QSevGuestInfo *info;

    obj = object_resolve_path_component(object_get_objects_root(), id);
    if (!obj) {
        return NULL;
    }

    info = (QSevGuestInfo *)
            object_dynamic_cast(obj, TYPE_QSEV_GUEST_INFO);
    if (!info) {
        return NULL;
    }

    return info;
}

uint64_t
sev_get_me_mask(void)
{
    return ~me_mask;
}

void
sev_get_current_state(char **state)
{
    *state = g_strdup(sev_state_str[current_sev_guest_state]);
}

bool
sev_enabled(void)
{
    return sev_active;
}

void
sev_get_fw_version(uint8_t *major, uint8_t *minor, uint8_t *build)
{
    struct sev_user_data_status status = {};
    int r, err;

    r = sev_platform_ioctl(SEV_PLATFORM_STATUS, &status, &err);
    if (r) {
        error_report("%s: failed to get platform status ret=%d"
                     "fw_error='%d: %s'", __func__, r, err,
                     fw_error_to_str(err));
        return;
    }

    *major = status.api_major;
    *minor = status.api_minor;
    *build = status.build;
}

void
sev_get_policy(uint32_t *policy)
{
    struct kvm_sev_guest_status status = {};
    int r, err;

    if (current_sev_guest_state == SEV_STATE_UNINIT) {
        return;
    }

    r = sev_ioctl(KVM_SEV_GUEST_STATUS, &status, &err);
    if (r) {
        error_report("%s: failed to get platform status ret=%d "
                     "fw_error='%d: %s'", __func__, r, err,
                     fw_error_to_str(err));
        return;
    }

    *policy = status.policy;
}

static int
__sev_get_migration_info(guchar **pdh, size_t *pdh_len, guchar **plat_cert,
                         size_t *plat_cert_len)
{
    guchar *pdh_data, *plat_cert_data;
    struct sev_user_data_pdh_cert_export export = {};
    int r, err;

    /* query the certificate length */
    r = sev_platform_ioctl(SEV_PDH_CERT_EXPORT, &export, &err);
    if (r < 0) {
        if (err != SEV_RET_INVALID_LEN) {
            error_report("failed to export PDH cert ret=%d fw_err=%d (%s)",
                         r, err, fw_error_to_str(err));
            return 1;
        }
    }

    pdh_data = g_new(guchar, export.pdh_cert_len);
    plat_cert_data = g_new(guchar, export.cert_chain_len);
    export.pdh_cert_address = (unsigned long)pdh_data;
    export.cert_chain_address = (unsigned long)plat_cert_data;

    r = sev_platform_ioctl(SEV_PDH_CERT_EXPORT, &export, &err);
    if (r < 0) {
        error_report("failed to export PDH cert ret=%d fw_err=%d (%s)",
                     r, err, fw_error_to_str(err));
        goto e_free;
    }

    *pdh = pdh_data;
    *plat_cert = plat_cert_data;
    *pdh_len = export.pdh_cert_len;
    *plat_cert_len = export.cert_chain_len;
    return 0;

e_free:
    g_free(pdh_data);
    g_free(plat_cert);
    return 1;
}

void
sev_get_migration_info(char **pdh, char **plat_cert)
{
    guchar *pdh_data, *plat_cert_data;
    size_t pdh_data_len = 0, plat_cert_len = 0;

    if (__sev_get_migration_info(&pdh_data, &pdh_data_len,
                &plat_cert_data, &plat_cert_len)) {
        return;
    }

    *pdh = g_base64_encode(pdh_data, pdh_data_len);;
    *plat_cert = g_base64_encode(plat_cert_data, plat_cert_len);
}

void
sev_set_migration_info(const char *pdh, const char *plat_cert,
                       const char *amd_cert)
{
    SEVState *s = sev_state;

    s->remote_pdh = g_base64_decode(pdh, &s->remote_pdh_len);
    s->remote_plat_cert = g_base64_decode(plat_cert,
                                          &s->remote_plat_cert_len);
    s->amd_cert = g_base64_decode(amd_cert, &s->amd_cert_len);
}

static int
sev_read_file_base64(const char *filename, guchar **data, gsize *len)
{
    gsize sz;
    gchar *base64;
    GError *error = NULL;

    if (!g_file_get_contents(filename, &base64, &sz, &error)) {
        error_report("failed to read '%s' (%s)", filename, error->message);
        return -1;
    }

    *data = g_base64_decode(base64, len);
    return 0;
}

static int
sev_launch_start(SEVState *s)
{
    gsize sz;
    int ret = 1;
    int fw_error;
    QSevGuestInfo *sev = s->sev_info;
    struct kvm_sev_launch_start *start;
    guchar *session = NULL, *dh_cert = NULL;

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    start->handle = object_property_get_int(OBJECT(sev), "handle",
                                            &error_abort);
    start->policy = object_property_get_int(OBJECT(sev), "policy",
                                            &error_abort);
    if (sev->session_file) {
        if (sev_read_file_base64(sev->session_file, &session, &sz) < 0) {
            return 1;
        }
        start->session_uaddr = (unsigned long)session;
        start->session_len = sz;
    }

    if (sev->dh_cert_file) {
        if (sev_read_file_base64(sev->dh_cert_file, &dh_cert, &sz) < 0) {
            return 1;
        }
        start->dh_uaddr = (unsigned long)dh_cert;
        start->dh_len = sz;
    }

    trace_kvm_sev_launch_start(start->policy, session, dh_cert);
    ret = sev_ioctl(KVM_SEV_LAUNCH_START, start, &fw_error);
    if (ret < 0) {
        error_report("%s: LAUNCH_START ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        return 1;
    }

    object_property_set_int(OBJECT(sev), start->handle, "handle",
                            &error_abort);
    sev_set_guest_state(SEV_STATE_LUPDATE);

    g_free(start);
    g_free(session);
    g_free(dh_cert);

    return 0;
}

static int
sev_launch_update_data(uint8_t *addr, uint64_t len)
{
    int ret, fw_error;
    struct kvm_sev_launch_update_data *update;

    if (addr == NULL || len <= 0) {
        return 1;
    }

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return 1;
    }

    update->uaddr = (__u64)addr;
    update->len = len;
    trace_kvm_sev_launch_update_data(addr, len);
    ret = sev_ioctl(KVM_SEV_LAUNCH_UPDATE_DATA, update, &fw_error);
    if (ret) {
        error_report("%s: LAUNCH_UPDATE ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

err:
    g_free(update);
    return ret;
}

static void
sev_launch_get_measure(Notifier *notifier, void *unused)
{
    int ret, error;
    guchar *data;
    SEVState *s = sev_state;
    struct kvm_sev_launch_measure *measurement;

    if (!sev_check_state(SEV_STATE_LUPDATE)) {
        return;
    }

    measurement = g_malloc0(sizeof(*measurement));
    if (!measurement) {
        return;
    }

    /* query the measurement blob length */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measurement, &error);
    if (!measurement->len) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(errno));
        goto free_measurement;
    }

    data = g_malloc(measurement->len);
    if (s->measurement) {
        goto free_data;
    }

    measurement->uaddr = (unsigned long)data;

    /* get the measurement blob */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measurement, &error);
    if (ret) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(errno));
        goto free_data;
    }

    sev_set_guest_state(SEV_STATE_SECRET);

    /* encode the measurement value and emit the event */
    s->measurement = g_base64_encode(data, measurement->len);
    trace_kvm_sev_launch_measurement(s->measurement);

free_data:
    g_free(data);
free_measurement:
    g_free(measurement);
}

char *
sev_get_launch_measurement(void)
{
    return current_sev_guest_state >= SEV_STATE_SECRET ?
            g_strdup(sev_state->measurement) : NULL;
}

static void
sev_send_finish(void)
{
    int ret, error;

    trace_kvm_sev_send_finish();
    ret = sev_ioctl(KVM_SEV_SEND_FINISH, 0, &error);
    if (ret) {
        error_report("%s: LAUNCH_FINISH ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(error));
    }

    sev_set_guest_state(SEV_STATE_RUNNING);
}

static void
sev_migration_state_notifier(Notifier *notifier, void *data)
{
    MigrationState *s = data;

    if (migration_has_finished(s) ||
        migration_in_postcopy_after_devices(s) ||
        migration_has_failed(s)) {
        if (sev_check_state(SEV_STATE_SUPDATE)) {
            sev_send_finish();
        }
    }
}

static Notifier sev_machine_done_notify = {
    .notify = sev_launch_get_measure,
};

static Notifier sev_migration_state_notify = {
    .notify = sev_migration_state_notifier,
};

static void
sev_launch_finish(SEVState *s)
{
    int ret, error;
    Error *local_err = NULL;

    trace_kvm_sev_launch_finish();
    ret = sev_ioctl(KVM_SEV_LAUNCH_FINISH, 0, &error);
    if (ret) {
        error_report("%s: LAUNCH_FINISH ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(error));
        exit(1);
    }

    sev_set_guest_state(SEV_STATE_RUNNING);

    /* add migration blocker */
    error_setg(&sev_mig_blocker,
               "SEV: Migration is not implemented");
    ret = migrate_add_blocker(sev_mig_blocker, &local_err);
    if (local_err) {
        error_report_err(local_err);
        error_free(sev_mig_blocker);
        exit(1);
    }
}

static int
sev_receive_finish(SEVState *s)
{
    int error, ret = 1;

    trace_kvm_sev_receive_finish();
    ret = sev_ioctl(KVM_SEV_RECEIVE_FINISH, 0, &error);
    if (ret) {
        error_report("%s: RECEIVE_FINISH ret=%d fw_error=%d '%s'\n",
                __func__, ret, error, fw_error_to_str(error));
        goto err;
    }

    sev_set_guest_state(SEV_STATE_RUNNING);
err:
    return ret;
}

static void
sev_vm_state_change(void *opaque, int running, RunState state)
{
    SEVState *s = opaque;

    if (running) {
        if (!sev_check_state(SEV_STATE_RUNNING)) {
            if (sev_check_state(SEV_STATE_RUPDATE)) {
                sev_receive_finish(s);
            } else if (sev_check_state(SEV_STATE_SECRET)) {
                sev_launch_finish(s);
            }
        }
    }
}

static int
sev_dbg_enc_dec(uint8_t *dst, const uint8_t *src, uint32_t len, bool write)
{
    int ret, error;
    struct kvm_sev_dbg *dbg;

    dbg = g_malloc0(sizeof(*dbg));
    if (!dbg) {
        return 1;
    }

    dbg->src_uaddr = (unsigned long)src;
    dbg->dst_uaddr = (unsigned long)dst;
    dbg->len = len;

    trace_kvm_sev_debug(write ? "encrypt" : "decrypt", src, dst, len);
    ret = sev_ioctl(write ? KVM_SEV_DBG_ENCRYPT : KVM_SEV_DBG_DECRYPT,
                    dbg, &error);
    if (ret) {
        error_report("%s (%s) %#llx->%#llx+%#x ret=%d fw_error=%d '%s'",
                     __func__, write ? "write" : "read", dbg->src_uaddr,
                     dbg->dst_uaddr, dbg->len, ret, error,
                     fw_error_to_str(error));
    }

    g_free(dbg);
    return ret;
}

static int
sev_mem_read(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    assert(attrs.debug);

    return sev_dbg_enc_dec(dst, src, len, false);
}

static int
sev_mem_write(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    assert(attrs.debug);

    return sev_dbg_enc_dec(dst, src, len, true);
}

void *
sev_guest_init(const char *id)
{
    SEVState *s;
    char *devname;
    int ret, fw_error;
    uint32_t host_cbitpos, cbitpos;

    s = g_new0(SEVState, 1);
    s->sev_info = lookup_sev_guest_info(id);
    if (!s->sev_info) {
        error_report("%s: '%s' is not a valid '%s' object",
                     __func__, id, TYPE_QSEV_GUEST_INFO);
        goto err;
    }

    host_cbitpos = sev_get_host_cbitpos();
    cbitpos = object_property_get_int(OBJECT(s->sev_info), "cbitpos", NULL);
    if (host_cbitpos != cbitpos) {
        error_report("%s: cbitpos check failed, host '%d' request '%d'",
                     __func__, host_cbitpos, cbitpos);
        goto err;
    }

    me_mask = (1UL << cbitpos);

    devname = object_property_get_str(OBJECT(s->sev_info), "sev-device", NULL);
    sev_fd = open(devname, O_RDWR);
    if (sev_fd < 0) {
        error_report("%s: Failed to open %s '%s'", __func__,
                     devname, strerror(errno));
        goto err;
    }
    g_free(devname);

    trace_kvm_sev_init();
    ret = sev_ioctl(KVM_SEV_INIT, NULL, &fw_error);
    if (ret) {
        error_report("%s: failed to initialize ret=%d fw_error=%d '%s'",
                     __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    if (!runstate_check(RUN_STATE_INMIGRATE)) {
        ret = sev_launch_start(s);
        if (ret) {
            error_report("%s: failed to create encryption context", __func__);
            goto err;
        }
    }


    sev_active = true;
    ram_block_notifier_add(&sev_ram_notifier);
    qemu_add_machine_init_done_notifier(&sev_machine_done_notify);
    qemu_add_vm_change_state_handler(sev_vm_state_change, s);
    add_migration_state_change_notifier(&sev_migration_state_notify);

    sev_state = s;

    return s;
err:
    g_free(s);
    return NULL;
}

int
sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len)
{
    assert(handle);

    /* if SEV is in update state then encrypt the data else do nothing */
    if (sev_check_state(SEV_STATE_LUPDATE)) {
        return sev_launch_update_data(ptr, len);
    }

    return 0;
}

void
sev_set_debug_ops(void *handle, MemoryRegion *mr)
{
    int policy;
    SEVState *s = (SEVState *)handle;

    policy = object_property_get_int(OBJECT(s->sev_info),
                                     "policy", &error_abort);

    /*
     * Check if guest policy supports debugging
     * Bit 0 :
     *   0 - debug allowed
     *   1 - debug is not allowed
     */
    if (policy & GUEST_POLICY_DBG_BIT) {
        return;
    }

    sev_ops.read = sev_mem_read;
    sev_ops.write = sev_mem_write;

    memory_region_set_ram_debug_ops(mr, &sev_ops);
}

static int
sev_get_send_session_length(void)
{
    int ret, fw_err = 0;
    struct kvm_sev_send_start *start;

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return -1;
    }

    ret = sev_ioctl(KVM_SEV_SEND_START, start, &fw_err);
    if (fw_err != SEV_RET_INVALID_LEN) {
        ret = -1;
        error_report("%s: failed to get session length ret=%d fw_error=%d '%s'",
                     __func__, ret, fw_err, fw_error_to_str(fw_err));
        goto err;
    }

    ret = start->session_len;
err:
    g_free(start);
    return ret;
}

static int
sev_send_start(SEVState *s, QEMUFile *f, uint64_t *bytes_sent)
{
    gsize pdh_len = 0, plat_cert_len;
    int session_len, ret, fw_error;
    struct kvm_sev_send_start *start;
    guchar *pdh = NULL, *plat_cert = NULL, *session = NULL;

    if (!s->remote_pdh_len || !s->remote_plat_cert_len) {
        error_report("%s: missing remote PDH or PLAT_CERT", __func__);
        return 1;
    }

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    start->pdh_cert_uaddr = (unsigned long) s->remote_pdh;
    start->pdh_cert_len = s->remote_pdh_len;

    start->plat_cert_uaddr = (unsigned long)s->remote_plat_cert;
    start->plat_cert_len = s->remote_plat_cert_len;

    if (s->amd_cert_len) {
        start->amd_cert_uaddr = (unsigned long)s->amd_cert;
        start->amd_cert_len = s->amd_cert_len;
    }

    /* get the session length */
    session_len = sev_get_send_session_length();
    if (session_len < 0) {
        ret = 1;
        goto err;
    }

    session = g_malloc(session_len);
    if (!session) {
        ret = 1;
        goto err;
    }
    start->session_uaddr = (unsigned long)session;
    start->session_len = session_len;

    /* Get our PDH certificate */
    ret = __sev_get_migration_info(&pdh, &pdh_len, &plat_cert, &plat_cert_len);
    if (ret) {
        error_report("Failed to get our PDH cert");
        goto err;
    }

    trace_kvm_sev_send_start(start->pdh_cert_uaddr, start->pdh_cert_len,
                             start->plat_cert_uaddr, start->plat_cert_len,
                             start->amd_cert_uaddr, start->amd_cert_len);

    ret = sev_ioctl(KVM_SEV_SEND_START, start, &fw_error);
    if (ret < 0) {
        error_report("%s: SEND_START ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    qemu_put_be32(f, start->policy);
    qemu_put_be32(f, pdh_len);
    qemu_put_buffer(f, (uint8_t *)pdh, pdh_len);
    qemu_put_be32(f, start->session_len);
    qemu_put_buffer(f, (uint8_t *)start->session_uaddr, start->session_len);
    *bytes_sent = 12 + pdh_len + start->session_len;

    sev_set_guest_state(SEV_STATE_SUPDATE);

err:
    g_free(start);
    g_free(pdh);
    g_free(plat_cert);
    return ret;
}

static int
sev_send_get_packet_len(int *fw_err)
{
#if 0
    int ret;
    struct kvm_sev_send_update_data *update;

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return -1;
    }

    ret = sev_ioctl(KVM_SEV_SEND_UPDATE_DATA, update, fw_err);
    if (*fw_err != SEV_RET_INVALID_LEN) {
        ret = -1;
        error_report("%s: failed to get session length ret=%d fw_error=%d '%s'",
                    __func__, ret, *fw_err, fw_error_to_str(*fw_err));
        goto err;
    }

    ret = update->hdr_len;

err:
    g_free(update);
    return ret;
#endif
    /* FIXME: SEV FW 0.14 build 20 does not return a valid header length */
    return 52;
}

static int
sev_send_update_data(SEVState *s, QEMUFile *f, uint8_t *ptr, uint32_t size,
                     uint64_t *bytes_sent)
{
    int ret, fw_error = 0;
    uint8_t *trans = NULL;
    struct kvm_sev_send_update_data *update;

    /* If this is first call then query the packet header bytes and allocate
     * the packet buffer.
     */
    if (!s->send_packet_hdr) {
        s->send_packet_hdr_len = sev_send_get_packet_len(&fw_error);
        if (s->send_packet_hdr_len < 0) {
            error_report("%s: SEND_UPDATE fw_error=%d '%s'",
                    __func__, fw_error, fw_error_to_str(fw_error));
            return 1;
        }

        s->send_packet_hdr = g_malloc(s->send_packet_hdr_len);
        if (!s->send_packet_hdr) {
            return 1;
        }
    }

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return 1;
    }

    /* allocate transport buffer */
    trans = g_malloc(size);
    if (!trans) {
        ret = 1;
        goto err;
    }

    update->hdr_uaddr = (unsigned long)s->send_packet_hdr;
    update->hdr_len = s->send_packet_hdr_len;
    update->guest_uaddr = (unsigned long)ptr;
    update->guest_len = size;
    update->trans_uaddr = (unsigned long)trans;
    update->trans_len = size;

    trace_kvm_sev_send_update_data(ptr, trans, size);

    ret = sev_ioctl(KVM_SEV_SEND_UPDATE_DATA, update, &fw_error);
    if (ret) {
        error_report("%s: SEND_UPDATE_DATA ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    qemu_put_be32(f, update->hdr_len);
    qemu_put_buffer(f, (uint8_t *)update->hdr_uaddr, update->hdr_len);
    *bytes_sent = 4 + update->hdr_len;

    qemu_put_be32(f, update->trans_len);
    qemu_put_buffer(f, (uint8_t *)update->trans_uaddr, update->trans_len);
    *bytes_sent += (4 + update->trans_len);

err:
    g_free(trans);
    g_free(update);
    return ret;
}

int
sev_save_outgoing_page(void *handle, QEMUFile *f, uint8_t *ptr,
                       uint32_t sz, uint64_t *bytes_sent)
{
    SEVState *s = (SEVState *)handle;

    /* If this is first buffer then create outgoing encryption context
     * and write ours PDH key, policy and session data.
     */
    if (!sev_check_state(SEV_STATE_SUPDATE) &&
        sev_send_start(s, f, bytes_sent)) {
        error_report("Failed to create outgoing context");
        return 1;
    }

    return sev_send_update_data(s, f, ptr, sz, bytes_sent);
}

static int
sev_receive_start(QSevGuestInfo *sev, QEMUFile *f)
{
    int ret = 1;
    int fw_error;
    struct kvm_sev_receive_start *start;
    gchar *session = NULL, *pdh_cert = NULL;

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    /* get SEV guest handle */
    start->handle = object_property_get_int(OBJECT(sev), "handle",
            &error_abort);

    /* get the source policy */
    start->policy = qemu_get_be32(f);

    /* get source PDH key */
    start->pdh_len = qemu_get_be32(f);
    pdh_cert = g_malloc(start->pdh_len);
    if (!pdh_cert) {
        goto err;
    }
    qemu_get_buffer(f, (uint8_t *)pdh_cert, start->pdh_len);
    start->pdh_uaddr = (unsigned long)pdh_cert;

    /* get source session data */
    start->session_len = qemu_get_be32(f);
    session = g_malloc(start->session_len);
    if (!session) {
        goto err;
    }
    qemu_get_buffer(f, (uint8_t *)session, start->session_len);
    start->session_uaddr = (unsigned long)session;

    trace_kvm_sev_receive_start(start->policy, session, pdh_cert);

    ret = sev_ioctl(KVM_SEV_RECEIVE_START, start, &fw_error);
    if (ret < 0) {
        error_report("Error RECEIVE_START ret=%d fw_error=%d '%s'",
                ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    object_property_set_int(OBJECT(sev), start->handle, "handle", &error_abort);
    sev_set_guest_state(SEV_STATE_RUPDATE);
err:
    g_free(start);
    g_free(session);
    g_free(pdh_cert);

    return ret;
}

static int sev_receive_update_data(QEMUFile *f, uint8_t *ptr)
{
    int ret = 1, fw_error = 0;
    gchar *hdr = NULL, *trans = NULL;
    struct kvm_sev_receive_update_data *update;

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return 1;
    }

    /* get packet header */
    update->hdr_len = qemu_get_be32(f);
    hdr = g_malloc(update->hdr_len);
    if (!hdr) {
        goto err;
    }
    qemu_get_buffer(f, (uint8_t *)hdr, update->hdr_len);
    update->hdr_uaddr = (unsigned long)hdr;

    /* get transport buffer */
    update->trans_len = qemu_get_be32(f);
    trans = g_malloc(update->trans_len);
    if (!trans) {
        goto err;
    }
    update->trans_uaddr = (unsigned long)trans;
    qemu_get_buffer(f, (uint8_t *)update->trans_uaddr, update->trans_len);

    update->guest_uaddr = (unsigned long) ptr;
    update->guest_len = update->trans_len;

    trace_kvm_sev_receive_update_data(trans, ptr, update->guest_len,
            hdr, update->hdr_len);

    ret = sev_ioctl(KVM_SEV_RECEIVE_UPDATE_DATA, update, &fw_error);
    if (ret) {
        error_report("Error RECEIVE_UPDATE_DATA ret=%d fw_error=%d '%s'",
                ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }
err:
    g_free(trans);
    g_free(update);
    g_free(hdr);
    return ret;
}

int sev_load_incoming_page(void *handle, QEMUFile *f, uint8_t *ptr)
{
    SEVState *s = (SEVState *)handle;

    /* If this is first buffer and SEV is not in recieiving state then
     * use RECEIVE_START command to create a encryption context.
     */
    if (!sev_check_state(SEV_STATE_RUPDATE) &&
        sev_receive_start(s->sev_info, f)) {
        return 1;
    }

    return sev_receive_update_data(f, ptr);
}

static void
sev_register_types(void)
{
    type_register_static(&qsev_guest_info);
}

type_init(sev_register_types);
