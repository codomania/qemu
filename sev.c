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
static bool sev_allowed;
static int sev_fd;

static void
qsev_guest_finalize(Object *obj)
{
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
            "device to use for SEV command", NULL);
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

static void
qsev_guest_init(Object *obj)
{
    QSevGuestInfo *sev = QSEV_GUEST_INFO(obj);

    object_property_add_link(obj, "launch", TYPE_QSEV_LAUNCH_INFO,
                             (Object **)&sev->launch_info,
                             object_property_allow_set_link,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);
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

static void
qsev_launch_class_init(ObjectClass *oc, void *data)
{
    /* add launch properties */
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

static int
sev_launch_start(SEVState *s)
{
    int ret = 1;
    Object *obj;
    int fw_error;
    struct kvm_sev_launch_start *start;

    if (!s) {
        return 1;
    }

    start = g_malloc0(sizeof(*start));
    if (!start) {
        return 1;
    }

    obj = object_property_get_link(OBJECT(s->sev_info), "launch", &error_abort);
    if (!obj) {
        goto err;
    }

    ret = sev_ioctl(KVM_SEV_LAUNCH_START, start, &fw_error);
    if (ret < 0) {
        fprintf(stderr, "failed LAUNCH_START %d (%#x)\n", ret, fw_error);
        goto err;
    }

    DPRINTF("SEV: LAUNCH_START\n");
err:
    g_free(start);
    return ret;
}

static int
sev_get_current_state(SEVState *s)
{
    int error;
    int ret = SEV_STATE_INVALID;
    struct kvm_sev_guest_status *status;

    if (!s) {
        return ret;
    }

    status = g_malloc(sizeof(*status));
    if (!status) {
        return ret;
    }

    ret = sev_ioctl(KVM_SEV_GUEST_STATUS, status, &error);
    if (ret) {
        fprintf(stderr, "failed GUEST_STATUS %d (%#x)\n", ret, error);
        goto err;
    }

    ret = status->state;
err:
    g_free(status);
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

    if (!s) {
        return 1;
    }

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
        fprintf(stderr, "failed DBG_DECRYPT %d (%#x)\n", ret, error);
        goto err;
    }

err:
    g_free(dbg);
    return ret;
}

static int
sev_mem_write(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    SEVState *s = kvm_memcrypt_get_handle();

    if (sev_get_current_state(s) == SEV_STATE_LAUNCHING) {
        memcpy(dst, src, len);
        return sev_launch_update_data(s, dst, len);
    }

    return 1;
}

static int
sev_mem_read(uint8_t *dst, const uint8_t *src, uint32_t len, MemTxAttrs attrs)
{
    SEVState *s = kvm_memcrypt_get_handle();

    assert(attrs.debug);

    return sev_debug_decrypt(s, dst, src, len);
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

    sev_allowed = true;
    return s;
err:
    g_free(s);
    return NULL;
}

int
sev_create_launch_context(void *handle)
{
    return sev_launch_start((SEVState *)handle);
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

int
sev_release_launch_context(void *handle)
{
    return sev_launch_finish((SEVState *)handle);
}

bool
sev_enabled(void)
{
    return sev_allowed;
}

static void
sev_policy_register_types(void)
{
    type_register_static(&qsev_guest_info);
    type_register_static(&qsev_launch_info);
}

type_init(sev_policy_register_types);
