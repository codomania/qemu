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

#define TYPE_QSEV_GUEST_INFO "sev-guest"
#define QSEV_GUEST_INFO(obj)                  \
    OBJECT_CHECK(QSevGuestInfo, (obj), TYPE_QSEV_GUEST_INFO)

extern bool sev_enabled(void);
extern void sev_get_fw_version(uint8_t *major, uint8_t *minor, uint8_t *build);
extern uint64_t sev_get_policy(void);
extern char * sev_get_launch_measurement(void);
extern void sev_get_migration_info(char **pdh, char **plat_cert);
extern void sev_set_migration_info(const char *pdh, const char *plat_cert,
                                   const char *amd_cert);

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
    uint32_t cbitpos;
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
    guchar *remote_pdh;
    size_t remote_pdh_len;
    guchar *remote_plat_cert;
    size_t remote_plat_cert_len;
    guchar *amd_cert;
    size_t amd_cert_len;
    guchar *send_packet_hdr;
    int send_packet_hdr_len;
};

typedef struct SEVState SEVState;

void *sev_guest_init(const char *id);
int sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len);
void sev_set_debug_ops(void *handle, MemoryRegion *mr);
int sev_save_outgoing_page(void *handle, QEMUFile *f, uint8_t *ptr,
                           uint32_t sz, uint64_t *bytes_sent);

#endif

