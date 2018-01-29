/*
 * QEMU Secure Encrypted Virutualization (SEV) support
 *
 * Copyright: Advanced Micro Devices, 2016-2018
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
#include "qemu/error-report.h"

#define TYPE_QSEV_SEND_INFO "sev-send-info"
#define QSEV_SEND_INFO(obj)                  \
    OBJECT_CHECK(QSevSendInfo, (obj), TYPE_QSEV_SEND_INFO)

typedef struct QSevSendInfo QSevSendInfo;
typedef struct QSevSendInfoClass QSevSendInfoClass;

/**
 * QSevSendInfo:
 *
 * The QSevSendInfo object provides parameters to create a encryption
 * context for outgoing guest.
 *
 * # $QEMU -object sev-send-info,id=sev-send0,dh-cert-file=<file>
 *         ....
 */
struct QSevSendInfo {
    Object parent_obj;

    char *pdh_cert_file;
    char *plat_cert_file;
    char *amd_cert_file;

    uint8_t *packet_hdr;
    int packet_hdr_len;
};

struct QSevSendInfoClass {
    ObjectClass parent_class;
};

#define TYPE_QSEV_LAUNCH_SECRET "sev-launch-secret"
#define QSEV_LAUNCH_SECRET(obj)                  \
    OBJECT_CHECK(QSevLaunchSecret, (obj), TYPE_QSEV_LAUNCH_SECRET)

typedef struct QSevLaunchSecret QSevLaunchSecret;
typedef struct QSevLaunchSecretClass QSevLaunchSecretClass;

struct QSevLaunchSecret {
    Object parent_obj;

    uint64_t gpa;
    char *hdr;
    char *data;
};

struct QSevLaunchSecretClass {
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
 * # $QEMU \
 *         -object sev-guest,id=sev0 \
 *         -machine ...,memory-encryption=sev0
 */
struct QSevGuestInfo {
    Object parent_obj;

    char *sev_device;
    uint32_t policy;
    uint32_t handle;
    char *dh_cert_file;
    char *session_file;

    QSevSendInfo *send_info;
};

struct QSevGuestInfoClass {
    ObjectClass parent_class;
};

typedef enum {
    SEV_STATE_UNINIT = 0,
    SEV_STATE_LUPDATE,
    SEV_STATE_SECRET,
    SEV_STATE_RUNNING,
    SEV_STATE_SUPDATE,
    SEV_STATE_RUPDATE,
    SEV_STATE_MAX
} SevGuestState;

struct SEVState {
    QSevGuestInfo *sev_info;
    gchar *measurement;
};

typedef struct SEVState SEVState;

void *sev_guest_init(const char *id);
int sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len);
void sev_set_debug_ops(void *handle, MemoryRegion *mr);

#endif

