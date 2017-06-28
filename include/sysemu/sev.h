/*
 * QEMU Secure Encrypted Virutualization (SEV) support
 *
 * Copyright: Advanced Micro Devices, 2016-2017
 *
 * Authors:
 *  Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_SEV_H
#define QEMU_SEV_H

#include <linux/kvm.h>

#include "qom/object.h"
#include "qapi/error.h"
#include "sysemu/kvm.h"

#define TYPE_QSEV_LAUNCH_INFO "sev-launch-info"
#define QSEV_LAUNCH_INFO(obj)                  \
    OBJECT_CHECK(QSevLaunchInfo, (obj), TYPE_QSEV_LAUNCH_INFO)

typedef struct QSevLaunchInfo QSevLaunchInfo;
typedef struct QSevLaunchInfoClass QSevLaunchInfoClass;

/**
 * QSevLaunchInfo:
 *
 * The QSevLaunchInfo object provides parameters to create a SEV
 * guest from unnencrypted boot images.
 *
 * # $QEMU -object sev-launch-info,id=launch0
 *         ....
 */
struct QSevLaunchInfo {
    Object parent_obj;

    char *dh_cert_file;
    char *session_file;
};

struct QSevLaunchInfoClass {
    ObjectClass parent_class;
};

#define TYPE_QSEV_GUEST_INFO "sev-guest"
#define QSEV_GUEST_INFO(obj)                  \
    OBJECT_CHECK(QSevGuestInfo, (obj), TYPE_QSEV_GUEST_INFO)

typedef struct QSevGuestInfo QSevGuestInfo;
typedef struct QSevGuestInfoClass QSevGuestInfoClass;

/**
 * QSevGuestInfo:
 *
 * The QSevGuestInfo object is used for creating a SEV guest.
 *
 * e.g to launch a SEV guest from unencrypted boot images
 *
 * # $QEMU -object sev-launch-info,id=launch0 \
 *         -object sev-guest,id=sev0,sev-device=/dev/sev \
 *         -machine ...,memory-encryption=sev0
 */
struct QSevGuestInfo {
    Object parent_obj;

    char *sev_device;
    uint32_t policy;
    uint32_t handle;

    QSevLaunchInfo *launch_info;
};

struct QSevGuestInfoClass {
    ObjectClass parent_class;
};

struct SEVState {
    QSevGuestInfo *sev_info;
};

typedef struct SEVState SEVState;

bool sev_enabled(void *handle);
void *sev_guest_init(const char *keyid);
void sev_set_debug_ops(void *handle, MemoryRegion *mr);

#endif

