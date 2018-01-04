/*
 * QEMU SEV support
 *
 * Copyright Advanced Micro Devices 2016-2017
 *
 * Author:
 *      Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

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
#include "exec/address-spaces.h"

#define DEFAULT_GUEST_POLICY    0x1 /* disable debug */
#define DEFAULT_SEV_DEVICE      "/dev/sev"
#define GUEST_POLICY_DBG_BIT    0x1

static int sev_fd;
static SEVState *sev_state;
static MemoryRegionRAMReadWriteOps  sev_ops;
static Error *sev_mig_blocker;

#define SEV_FW_MAX_ERROR      0x17

static SevGuestState current_sev_guest_state = SEV_STATE_UNINIT;

static char sev_fw_errlist[SEV_FW_MAX_ERROR][100] = {
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

static char *
fw_error_to_str(int code)
{
    if (code > SEV_FW_MAX_ERROR) {
        return NULL;
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

    trace_kvm_sev_change_state(current_sev_guest_state, new_state);
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
qsev_guest_init(Object *obj)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);
    sev->policy = DEFAULT_GUEST_POLICY;
    object_property_add(obj, "policy", "uint32", qsev_guest_get_policy,
                        qsev_guest_set_policy, NULL, NULL, NULL);
    object_property_add(obj, "handle", "uint32", qsev_guest_get_handle,
                        qsev_guest_set_handle, NULL, NULL, NULL);
    object_property_add_link(obj, "send", TYPE_QSEV_SEND_INFO,
                             (Object **)&sev->send_info,
                             object_property_allow_set_link,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);

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
    qapi_event_send_sev_measurement(s->measurement, &error_abort);

free_data:
    g_free(data);
free_measurement:
    g_free(measurement);
}

static Notifier sev_machine_done_notify = {
    .notify = sev_launch_get_measure,
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

static void
sev_vm_state_change(void *opaque, int running, RunState state)
{
    SEVState *s = opaque;

    if (running) {
        if (!sev_check_state(SEV_STATE_RUNNING)) {
            sev_launch_finish(s);
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

    s = g_malloc0(sizeof(SEVState));
    if (!s) {
        return NULL;
    }

    s->sev_info = lookup_sev_guest_info(id);
    if (!s->sev_info) {
        error_report("%s: '%s' is not a valid '%s' object",
                     __func__, id, TYPE_QSEV_GUEST_INFO);
        goto err;
    }

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

    ret = sev_launch_start(s);
    if (ret) {
        error_report("%s: failed to create encryption context", __func__);
        goto err;
    }

    ram_block_notifier_add(&sev_ram_notifier);
    qemu_add_machine_init_done_notifier(&sev_machine_done_notify);
    qemu_add_vm_change_state_handler(sev_vm_state_change, s);

    sev_state = s;

    return s;
err:
    g_free(s);
    return NULL;
}

int
sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len)
{
    assert (handle);

    /* if SEV is in update state then encrypt the data else do nothing */
    if (sev_check_state(SEV_STATE_LUPDATE)) {
        return sev_launch_update_data(ptr, len);
    }

    return 0;
}

void
sev_set_memory_region(void *handle, MemoryRegion *mr)
{
    int policy;
    SEVState *s = (SEVState *)handle;

    policy = object_property_get_int(OBJECT(s->sev_info),
                                     "policy", &error_abort);

    /* indicate that memory region contains encrypted data */
    memory_region_set_encrypted(mr);

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

static void
qsev_launch_secret_finalize(Object *obj)
{
}

static void *gpa2hva(hwaddr addr, uint64_t size)
{
    MemoryRegionSection mrs = memory_region_find(get_system_memory(),
                                                 addr, size);

    if (!mrs.mr) {
        error_report("No memory is mapped at address 0x%" HWADDR_PRIx, addr);
        return NULL;
    }

    if (!memory_region_is_ram(mrs.mr) && !memory_region_is_romd(mrs.mr)) {
        error_report("Memory at address 0x%" HWADDR_PRIx "is not RAM", addr);
        memory_region_unref(mrs.mr);
        return NULL;
    }

    return qemu_map_ram_ptr(mrs.mr->ram_block, mrs.offset_within_region);
}

static void
sev_launch_secret(QSevLaunchSecret *secret)
{
    struct kvm_sev_launch_secret *input;
    guchar *data, *hdr;
    int error, ret;
    gsize hdr_sz = 0, data_sz = 0;

    if (!secret->hdr || !secret->data) {
        return;
    }

    hdr = g_base64_decode(secret->hdr, &hdr_sz);
    if (!hdr || !hdr_sz) {
        error_report("SEV: Failed to decode sequence header");
        return;
    }

    data = g_base64_decode(secret->data, &data_sz);
    if (!data || !data_sz) {
        error_report("SEV: Failed to decode data");
        return;
    }

    input = g_malloc0(sizeof(*input));
    if (!input) {
        return;
    }

    input->hdr_uaddr = (unsigned long)hdr;
    input->hdr_len = hdr_sz;

    input->trans_uaddr = (unsigned long)data;
    input->trans_len = data_sz;

    input->guest_uaddr = (unsigned long)gpa2hva(secret->gpa, data_sz);
    input->guest_len = data_sz;

    trace_kvm_sev_launch_secret(secret->gpa, input->guest_uaddr,
                                input->trans_uaddr, input->trans_len);

    ret = sev_ioctl(KVM_SEV_LAUNCH_SECRET, input, &error);
    if (ret) {
        error_report("SEV: failed to inject secret ret=%d fw_error=%d '%s'",
                     ret, error, fw_error_to_str(error));
    }

    g_free(data);
    g_free(hdr);
    g_free(input);
}

static char *
qsev_launch_secret_get_hdr(Object *obj, Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);

    return g_strdup(s->hdr);
}

static void
qsev_launch_secret_set_hdr(Object *obj, const char *value, Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);

    s->hdr = g_strdup(value);
}

static char *
qsev_launch_secret_get_data(Object *obj, Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);

    return g_strdup(s->data);
}

static void
qsev_launch_secret_set_data(Object *obj, const char *value, Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);

    s->data = g_strdup(value);
}

static void
qsev_launch_secret_set_loaded(Object *obj, bool value, Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);

    if (!sev_check_state(SEV_STATE_SECRET)) {
        error_report("SEV: failed to inject secret,"
                     " invalid state (expected %d got %d)",
                     SEV_STATE_SECRET, current_sev_guest_state);
        return;
    }

    sev_launch_secret(s);
}

static bool
qsev_launch_secret_get_loaded(Object *obj G_GNUC_UNUSED,
                              Error **errp G_GNUC_UNUSED)
{
    return false;
}

static void
qsev_launch_secret_complete(UserCreatable *uc, Error **errp)
{
    object_property_set_bool(OBJECT(uc), true, "loaded", errp);
}

static void
qsev_launch_secret_get_gpa(Object *obj, Visitor *v,
                           const char *name, void *opaque,
                           Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);
    uint64_t value = s->gpa;

    visit_type_uint64(v, name, &value, errp);
}

static void
qsev_launch_secret_set_gpa(Object *obj, Visitor *v,
                           const char *name, void *opaque,
                           Error **errp)
{
    QSevLaunchSecret *s = QSEV_LAUNCH_SECRET(obj);
    Error *error = NULL;
    uint64_t value;

    visit_type_uint64(v, name, &value, &error);
    if (error) {
        error_propagate(errp, error);
        return;
    }

    s->gpa = value;
}

static void
qsev_launch_secret_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = qsev_launch_secret_complete;

    object_class_property_add_bool(oc, "loaded",
                                   qsev_launch_secret_get_loaded,
                                   qsev_launch_secret_set_loaded,
                                   NULL);

    object_class_property_add(oc, "gpa", "uint64",
                                   qsev_launch_secret_get_gpa,
                                   qsev_launch_secret_set_gpa,
                                   NULL, NULL, NULL);
    object_class_property_set_description(oc, "gpa",
            "Guest physical address to inject the secret", NULL);

    object_class_property_add_str(oc, "hdr",
                                  qsev_launch_secret_get_hdr,
                                  qsev_launch_secret_set_hdr,
                                  NULL);
    object_class_property_set_description(oc, "hdr",
            "Launch secret data header (encoded in base64) ", NULL);
    object_class_property_add_str(oc, "data",
                                  qsev_launch_secret_get_data,
                                  qsev_launch_secret_set_data,
                                  NULL);
    object_class_property_set_description(oc, "data",
            "Secret data to be injected (encoded in base64) ", NULL);
}

static void
qsev_launch_secret_init(Object *obj)
{
}

static const TypeInfo qsev_launch_secret = {
    .parent = TYPE_OBJECT,
    .name = TYPE_QSEV_LAUNCH_SECRET,
    .instance_size = sizeof(QSevLaunchSecret),
    .instance_finalize = qsev_launch_secret_finalize,
    .class_size = sizeof(QSevLaunchSecretClass),
    .class_init = qsev_launch_secret_class_init,
    .instance_init = qsev_launch_secret_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static char *
qsev_send_get_plat_cert_file(Object *obj, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    return g_strdup(s->plat_cert_file);
}

static void
qsev_send_set_plat_cert_file(Object *obj, const char *value, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    s->plat_cert_file = g_strdup(value);
}

static char *
qsev_send_get_pdh_cert_file(Object *obj, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    return g_strdup(s->pdh_cert_file);
}

static void
qsev_send_set_pdh_cert_file(Object *obj, const char *value, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    s->pdh_cert_file = g_strdup(value);
}

static char *
qsev_send_get_amd_cert_file(Object *obj, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    return g_strdup(s->amd_cert_file);
}

static void
qsev_send_set_amd_cert_file(Object *obj, const char *value, Error **errp)
{
    QSevSendInfo *s = QSEV_SEND_INFO(obj);

    s->amd_cert_file = g_strdup(value);
}

static void
qsev_send_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "pdh-cert-file",
                                  qsev_send_get_pdh_cert_file,
                                  qsev_send_set_pdh_cert_file,
                                  NULL);
    object_class_property_set_description(oc, "pdh-cert-file",
            "guest owners PDH certificate", NULL);
    object_class_property_add_str(oc, "plat-cert-file",
                                  qsev_send_get_plat_cert_file,
                                  qsev_send_set_plat_cert_file,
                                  NULL);
    object_class_property_set_description(oc, "plat-cert-file",
            "guest owners platform certificate", NULL);
    object_class_property_add_str(oc, "amd-cert-file",
                                  qsev_send_get_amd_cert_file,
                                  qsev_send_set_amd_cert_file,
                                  NULL);
    object_class_property_set_description(oc, "amd-cert-file",
            "Amd certificate chain", NULL);
}

static void
qsev_send_init(Object *obj)
{
}

static void
qsev_send_finalize(Object *obj)
{
}

/* guest send */
static const TypeInfo qsev_send_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_QSEV_SEND_INFO,
    .instance_size = sizeof(QSevSendInfo),
    .instance_finalize = qsev_send_finalize,
    .class_size = sizeof(QSevSendInfoClass),
    .class_init = qsev_send_class_init,
    .instance_init = qsev_send_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void
sev_register_types(void)
{
    type_register_static(&qsev_guest_info);
    type_register_static(&qsev_launch_secret);
    type_register_static(&qsev_send_info);
}

type_init(sev_register_types);
