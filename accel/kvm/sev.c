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
sev_mem_write(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    return 0;
}

static int
sev_mem_read(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    return 0;
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

static void
sev_register_types(void)
{
    type_register_static(&qsev_guest_info);
}

type_init(sev_register_types);
