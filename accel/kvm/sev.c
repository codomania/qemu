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

static void
qsev_guest_finalize(Object *obj)
{
}

static struct kvm_sev_guest_status *sev_get_status(int *error)
{
    struct kvm_sev_guest_status *status;

    status = g_malloc(sizeof(*status));
    if (!status) {
        return NULL;
    }

    if (sev_ioctl(KVM_SEV_GUEST_STATUS, status, error)) {
        goto err;
    }

    return status;
err:
    g_free(status);
    return NULL;
}

static int
sev_get_current_state(SEVState *s)
{
    int error;
    int ret = SEV_STATE_INVALID;
    struct kvm_sev_guest_status *status;

    status = sev_get_status(&error);
    if (!status) {
        return ret;
    }

    ret = status->state;
    g_free(status);
    return ret;
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
}

static QSevGuestInfo *
lookup_sev_guest_info(const char *id)
{
    Object *obj;
    QSevGuestInfo *info;

    obj = object_resolve_path_component(
        object_get_objects_root(), id);
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

static void
qsev_guest_init(Object *obj)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    object_property_add_link(obj, "launch", TYPE_QSEV_LAUNCH_INFO,
                             (Object **)&sev->launch_info,
                             object_property_allow_set_link,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);

    object_property_add(obj, "policy", "uint32", qsev_guest_get_policy,
                        qsev_guest_set_policy, NULL, NULL, NULL);
    object_property_add(obj, "handle", "uint32", qsev_guest_get_handle,
                        qsev_guest_set_handle, NULL, NULL, NULL);
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

static void
qsev_launch_finalize(Object *obj)
{
}

static char *
qsev_launch_get_session_file(Object *obj, Error **errp)
{
    QSevLaunchInfo *l = QSEV_LAUNCH_INFO(obj);

    return l->session_file ? g_strdup(l->session_file) : NULL;
}

static void
qsev_launch_set_session_file(Object *obj, const char *value, Error **errp)
{
    QSevLaunchInfo *l = QSEV_LAUNCH_INFO(obj);

    l->session_file = g_strdup(value);
}

static char *
qsev_launch_get_dh_cert_file(Object *obj, Error **errp)
{
    QSevLaunchInfo *l = QSEV_LAUNCH_INFO(obj);

    return g_strdup(l->dh_cert_file);
}

static void
qsev_launch_set_dh_cert_file(Object *obj, const char *value, Error **errp)
{
    QSevLaunchInfo *l = QSEV_LAUNCH_INFO(obj);

    l->dh_cert_file = g_strdup(value);
}

static void
qsev_launch_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "dh-cert-file",
                                  qsev_launch_get_dh_cert_file,
                                  qsev_launch_set_dh_cert_file,
                                  NULL);
    object_class_property_set_description(oc, "dh-cert-file",
            "guest owners DH certificate", NULL);
    object_class_property_add_str(oc, "session-file",
                                  qsev_launch_get_session_file,
                                  qsev_launch_set_session_file,
                                  NULL);
    object_class_property_set_description(oc, "session-file",
            "guest owners session parameters", NULL);
}

static void
qsev_launch_init(Object *obj)
{
}

/* guest launch */
static const TypeInfo qsev_launch_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_QSEV_LAUNCH_INFO,
    .instance_size = sizeof(QSevLaunchInfo),
    .instance_finalize = qsev_launch_finalize,
    .class_size = sizeof(QSevLaunchInfoClass),
    .class_init = qsev_launch_class_init,
    .instance_init = qsev_launch_init,
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
    Object *obj;
    int fw_error;
    GError *error = NULL;
    QSevLaunchInfo *launch;
    struct kvm_sev_launch_start *start;
    gchar *session = NULL, *dh_cert = NULL;

    obj = object_property_get_link(OBJECT(sev), "launch", &error_abort);
    if (!obj) {
        fprintf(stderr, "sev-launch-info object not found\n");
        return 1;
    }

    launch = QSEV_LAUNCH_INFO(obj);

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    start->policy = object_property_get_int(OBJECT(sev), "policy",&error_abort);
    start->handle = object_property_get_int(OBJECT(sev), "handle",&error_abort);

    if (launch->session_file) {
        if (g_file_get_contents(launch->session_file, &session, &sz, &error)) {
            start->session_data = (unsigned long)session;
            start->session_length = sz;
        }
    }

    if (launch->dh_cert_file) {
        if (g_file_get_contents(launch->dh_cert_file, &dh_cert, &sz, &error)) {
            start->dh_cert_data = (unsigned long)session;
            start->dh_cert_length = sz;
        }
    }

    ret = sev_ioctl(KVM_SEV_LAUNCH_START, start, &fw_error);
    if (ret < 0) {
        fprintf(stderr, "failed LAUNCH_START %d (%#x)\n", ret, fw_error);
        goto err;
    }

    object_property_set_int(OBJECT(sev), start->handle, "handle", &error_abort);
    DPRINTF("SEV: LAUNCH_START\n");
err:
    g_free(start);
    g_free(session);
    g_free(dh_cert);
    return ret;
}

static int
sev_launch_update_data(SEVState *s, uint8_t *addr, uint64_t len)
{
    int ret, error;
    struct kvm_sev_launch_update_data *update;

    if (!s) {
        return 1;
    }

    /* if we are not in launching state then do nothing */
    if (sev_get_current_state(s) != SEV_STATE_LUPDATE) {
        return 0;
    }

    update = g_malloc0(sizeof(*update));
    if (!update) {
        return 1;
    }

    update->address = (__u64)addr;
    update->length = len;
    ret = sev_ioctl(KVM_SEV_LAUNCH_UPDATE_DATA, update, &error);
    if (ret) {
        fprintf(stderr, "failed LAUNCH_UPDATE_DATA %d (%#x)\n", ret, error);
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
sev_launch_finish(SEVState *s)
{
    uint8_t *data;
    int error, ret;
    struct kvm_sev_launch_measure *measure;

    measure = g_malloc0(sizeof(*measure));
    if (!measure) {
        return 1;
    }

    /* query measurement blob length */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measure, &error);
    if (!measure->length) {
        fprintf(stderr, "Error: failed to get launch measurement length\n");
        ret = 1;
        goto err_1;
    }

    data = g_malloc0(measure->length);
    if (!data) {
        goto err_1;
    }
    measure->address = (unsigned long)data;
    /* get measurement */
    ret = sev_ioctl(KVM_SEV_LAUNCH_MEASURE, measure, &error);
    if (ret) {
        fprintf(stderr, "failed LAUNCH_MEASURE %d (%#x)\n", ret, error);
        goto err_2;
    }

    print_hex_dump("SEV: MEASUREMENT", data, measure->length);

    /* finalize the launch */
    ret = sev_ioctl(KVM_SEV_LAUNCH_FINISH, 0, &error);
    if (ret) {
        fprintf(stderr, "failed LAUNCH_FINISH %d (%#x)\n", ret, error);
        goto err_2;
    }

    DPRINTF("SEV: LAUNCH_FINISH\n");
err_2:
    g_free(data);
err_1:
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
        /* If failed to decrypt guest memory then memcpy the data */
        DPRINTF("Error: DBG_DECRYPT %d(%#x)\n", ret, error);
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
        DPRINTF("Error: DBG_ENCRYPT %d(%#x)\n", ret, error);
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
    } else if (sev_get_current_state(s) == SEV_STATE_LUPDATE) {
        memcpy(dst, src, len);
        return sev_launch_update_data(s, dst, len);
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

static void sev_vm_state_change(void *opaque, int running, RunState state)
{
    SEVState *s = opaque;

    if (running) {
        /* if SEV guest is in LUPDATE state then finialize the launch context
         * so that we can transition into RUNNING state.
         */
        if (sev_get_current_state(s) == SEV_STATE_LUPDATE) {
            sev_launch_finish(s);
        }
    }
}

void *
sev_guest_init(const char *id)
{
    Object *obj;
    SEVState *s;
    char *sev_device_name;

    s = g_malloc0(sizeof(SEVState));
    if (!s) {
        return NULL;
    }

    s->sev_info = lookup_sev_guest_info(id);
    if (!s->sev_info) {
        fprintf(stderr, "'%s' not a valid '%s' object\n",
                id, TYPE_QSEV_GUEST_INFO);
        goto err;
    }

    sev_device_name = object_property_get_str(OBJECT(s->sev_info),
                                              "sev-device", NULL);
    sev_fd = open(sev_device_name, O_RDWR);
    if (sev_fd < 0) {
        fprintf(stderr, "%s:%s\n", sev_device_name, strerror(errno));
        goto err;
    }
    g_free(sev_device_name);

    obj = object_resolve_path_type("", TYPE_QSEV_LAUNCH_INFO, NULL);
    if (obj) {
        object_property_set_link(OBJECT(s->sev_info), obj, "launch",
            &error_abort);
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

bool
sev_enabled(void *handle)
{
    if (!handle) {
        return false;
    }

    if (sev_get_current_state((SEVState *)handle) != SEV_STATE_INVALID) {
        return true;
    }

    return false;
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
    return sev_launch_update_data((SEVState *)handle, ptr, len);
}

static void
sev_register_types(void)
{
    type_register_static(&qsev_guest_info);
    type_register_static(&qsev_launch_info);
}

type_init(sev_register_types);
