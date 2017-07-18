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

#define DEBUG_SEV
#ifdef DEBUG_SEV
#define DPRINTF(fmt, ...) \
    do { fprintf(stdout, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define DEFAULT_SEV_DEVICE      "/dev/sev1"

static MemoryRegionRAMReadWriteOps sev_ops;
static int sev_fd;

#define SEV_FW_MAX_ERROR      0x17

static char sev_fw_errlist[SEV_FW_MAX_ERROR][100]= {
    "Success",
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

    input.id = cmd;
    input.sev_fd = sev_fd;
    input.data = (__u64)data;

    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &input);
    *error = input.error;
    return r;
}

static char * fw_error_to_str(int code)
{
    if (code > SEV_FW_MAX_ERROR) {
        return NULL;
    }

    return sev_fw_errlist[code];
}

static uint8_t sev_get_current_state(QSevGuestInfo *sev)
{
    return object_property_get_int(OBJECT(sev), "state", &error_abort);
}

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
            "guest owners DH certificate", NULL);
    object_class_property_add_str(oc, "session-file",
                                  qsev_guest_get_session_file,
                                  qsev_guest_set_session_file,
                                  NULL);
    object_class_property_set_description(oc, "session-file",
            "guest owners session parameters", NULL);
}

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

static void qsev_guest_set_handle(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint32_t value;

    visit_type_uint32(v, name, &value, errp);
    sev->handle = value;
}

static void qsev_guest_set_policy(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint32_t value;

    visit_type_uint32(v, name, &value, errp);
    sev->policy = value;
}

static void qsev_guest_get_policy(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    uint32_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->policy;
    visit_type_uint32(v, name, &value, errp);
}

static void qsev_guest_get_handle(Object *obj, Visitor *v, const char *name,
                                  void *opaque, Error **errp)
{
    uint32_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->handle;
    visit_type_uint32(v, name, &value, errp);
}

static void qsev_guest_set_state(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);
    uint8_t value;

    visit_type_uint8(v, name, &value, errp);
    sev->cur_state = value;
}

static void qsev_guest_get_state(Object *obj, Visitor *v, const char *name,
                                 void *opaque, Error **errp)
{
    uint8_t value;
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    value = sev->cur_state;
    visit_type_uint8(v, name, &value, errp);
}

static void
qsev_guest_init(Object *obj)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);
    object_property_add(obj, "policy", "uint32", qsev_guest_get_policy,
                        qsev_guest_set_policy, NULL, NULL, NULL);
    object_property_add(obj, "handle", "uint32", qsev_guest_get_handle,
                        qsev_guest_set_handle, NULL, NULL, NULL);
    object_property_add(obj, "state", "uint8", qsev_guest_get_state,
                        qsev_guest_set_state, NULL, NULL, NULL);
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

static int
sev_launch_start(QSevGuestInfo *sev)
{
    gsize sz;
    int ret = 1;
    int fw_error;
    GError *error = NULL;
    struct kvm_sev_launch_start *start;
    gchar *session = NULL, *dh_cert = NULL;

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    start->policy = sev->policy;
    start->handle = sev->handle;

    if (sev->session_file) {
        if (g_file_get_contents(sev->session_file, &session, &sz, &error)) {
            start->session_address = (unsigned long)session;
            start->session_length = sz;
        }
    }

    if (sev->dh_cert_file) {
        if (g_file_get_contents(sev->dh_cert_file, &dh_cert, &sz, &error)) {
            start->dh_cert_address = (unsigned long)session;
            start->dh_cert_length = sz;
        }
    }

    ret = sev_ioctl(KVM_SEV_LAUNCH_START, start, &fw_error);
    if (ret < 0) {
        error_report("%s: LAUNCH_START ret=%d fw_error=%d '%s'\n",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    object_property_set_int(OBJECT(sev), start->handle, "handle", &error_abort);
    object_property_set_int(OBJECT(sev), SEV_STATE_LUPDATE,
                    "state", &error_abort);

    DPRINTF("SEV: LAUNCH_START\n");
err:
    g_free(start);
    g_free(session);
    g_free(dh_cert);
    return ret;
}

static int
sev_launch_update_data(uint8_t *addr, uint64_t len)
{
    int ret, fw_error;
    struct kvm_sev_launch_update_data *update;

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return 1;
    }

    update->address = (__u64)addr;
    update->length = len;
    ret = sev_ioctl(KVM_SEV_LAUNCH_UPDATE_DATA, update, &fw_error);
    if (ret) {
        error_report("%s: LAUNCH_UPDATE ret=%d fw_error=%d '%s'\n",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    DPRINTF("SEV: LAUNCH_UPDATE_DATA %#lx+%#lx\n", (unsigned long)addr, len);
err:
    g_free(update);
    return ret;
}

static void
print_hex_dump(const char *prefix_str, uint8_t *data, int len)
{
    int i;

    DPRINTF("%s: ", prefix_str);
    for (i = 0; i < len; i++) {
        DPRINTF("%02hhx", *data++);
    }
    DPRINTF("\n");
}

static int
sev_launch_finish(QSevGuestInfo *sev)
{
    int error, ret = 1;
    uint8_t *data = NULL;
    struct kvm_sev_launch_measure *measure;

    measure = g_malloc0(sizeof(*measure));
    if (!measure) {
        return 1;
    }

    /* query measurement blob length */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measure, &error);
    if (!measure->length) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'\n",
                __func__, ret, error, fw_error_to_str(error));
        ret = 1;
        goto err;
    }
    object_property_set_int(OBJECT(sev), SEV_STATE_SECRET, "state",
                        &error_abort);

    data = g_malloc0(measure->length);
    if (!data) {
        ret = 1;
        goto err;
    }
    measure->address = (unsigned long)data;

    /* get measurement */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measure, &error);
    if (ret) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'\n",
                __func__, ret, error, fw_error_to_str(error));
        goto err;
    }

    print_hex_dump("SEV: MEASUREMENT", data, measure->length);

    /* finalize the launch */
    ret = sev_ioctl(KVM_SEV_LAUNCH_FINISH, 0, &error);
    if (ret) {
        error_report("%s: LAUNCH_FINISH ret=%d fw_error=%d '%s'\n",
                __func__, ret, error, fw_error_to_str(error));
        goto err;
    }

    object_property_set_int(OBJECT(sev), SEV_STATE_RUNNING, "state",
                        &error_abort);
    DPRINTF("SEV: LAUNCH_FINISH\n");
err:
    g_free(data);
    g_free(measure);
    return ret;
}

static int
sev_debug_decrypt(SEVState *s, uint8_t *dst, const uint8_t *src, uint32_t len)
{
    int ret, error;
    struct kvm_sev_dbg *dbg;

    if (!s) {
        return 1;
    }

    dbg = g_malloc0(sizeof(*dbg));
    if (!dbg) {
        return 1;
    }

    dbg->src_addr = (unsigned long)src;
    dbg->dst_addr = (unsigned long)dst;
    dbg->length = len;

    ret = sev_ioctl(KVM_SEV_DBG_DECRYPT, dbg, &error);
    if (ret) {
        fprintf(stderr, "Error DEBUG_DECRYPT ret=%d fw_error=%d '%s'\n",
                ret, error, fw_error_to_str(error));
        memcpy(dst, src, len);
    }

    g_free(dbg);
    return ret;
}

static int
sev_debug_encrypt(SEVState *s, uint8_t *dst, const uint8_t *src, uint32_t len)
{
    int ret, error;
    struct kvm_sev_dbg *dbg;

    if (!s) {
        return 1;
    }

    dbg = g_malloc0(sizeof(*dbg));
    if (!dbg) {
        return 1;
    }

    dbg->src_addr = (unsigned long)src;
    dbg->dst_addr = (unsigned long)dst;
    dbg->length = len;

    ret = sev_ioctl(KVM_SEV_DBG_ENCRYPT, dbg, &error);
    if (ret) {
        fprintf(stderr, "Error DEBUG_ENCRYPT ret=%d fw_error=%d '%s'\n",
                ret, error, fw_error_to_str(error));
        memcpy(dst, src, len);
    }

    g_free(dbg);
    return ret;
}

static int
sev_mem_write(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    SEVState *s = kvm_memcrypt_get_handle();

    if (attrs.debug) {
        return sev_debug_encrypt(s, dst, src, len);
    } else if (s && sev_get_current_state(s->sev_info) == SEV_STATE_LUPDATE) {
        memcpy(dst, src, len);
        return sev_launch_update_data(dst, len);
    }

    return 0;
}

static int
sev_mem_read(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    SEVState *s = kvm_memcrypt_get_handle();

    assert(attrs.debug);

    return sev_debug_decrypt(s, dst, src, len);
}

bool
sev_object_check(const char *id)
{
    /* check if the given id is sev-guest */
    if (lookup_sev_guest_info(id)) {
        return true;
    }

    return false;
}

static void sev_vm_state_change(void *opaque, int running, RunState state)
{
    SEVState *s = opaque;

    if (running) {
        if (sev_get_current_state(s->sev_info) == SEV_STATE_LUPDATE) {
            sev_launch_finish(s->sev_info);
        }
    }
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
        error_report("%s: '%s' is not a valid '%s' object\n",
                     __func__, id, TYPE_QSEV_GUEST_INFO);
        goto err;
    }

    devname = object_property_get_str(OBJECT(s->sev_info), "sev-device", NULL);
    sev_fd = open(devname, O_RDWR);
    if (sev_fd < 0) {
        error_report("%s: Failed to open %s '%s'\n", __func__,
                     devname, strerror(errno));
        goto err;
    }
    g_free(devname);

    ret = sev_ioctl(KVM_SEV_INIT, NULL, &fw_error);
    if (ret) {
        error_report("%s: failed to initialize ret=%d fw_error=%d '%s'\n",
                     __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    /* create launch context */
    if (sev_launch_start(s->sev_info)) {
        goto err;
    }

    qemu_add_vm_change_state_handler(sev_vm_state_change, s);
    return s;
err:
    g_free(s);
    return NULL;
}

void
sev_set_debug_ops(void *handle, MemoryRegion *mr)
{
    sev_ops.read = sev_mem_read;
    sev_ops.write = sev_mem_write;

    memory_region_set_ram_debug_ops(mr, &sev_ops);
}

int
sev_encrypt_launch_buffer(void *handle, uint8_t *ptr, uint64_t len)
{
    SEVState *s = (SEVState *)handle;

    if (s && sev_get_current_state(s->sev_info) == SEV_STATE_LUPDATE) {
        return sev_launch_update_data(ptr, len);
    }

    return 0;
}

static void
sev_register_types(void)
{
    type_register_static(&qsev_guest_info);
}

type_init(sev_register_types);
