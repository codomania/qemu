/*
 * QEMU SEV stub
 *
 * Copyright Advanced Micro Devices 2018
 *
 * Authors:
 *      Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/sev.h"

int sev_inject_launch_secret(const char *hdr, const char *secret,
                             uint64_t gpa)
{
    return 1;
}

int sev_save_outgoing_page(void *handle, QEMUFile *f, uint8_t *ptr,
                           uint32_t sz, uint64_t *bytes_sent)
{
    return 1;
}

void
sev_set_migration_info(const char *pdh, const char *plat_cert,
                       const char *amd_cert)
{
}

void
sev_get_migration_info(char **pdh, char **plat_cert)
{
}

void sev_set_debug_ops(void *handle, MemoryRegion *mr)
{
}

int sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len)
{
    return 1;
}

void sev_get_current_state(char **state)
{
}

bool sev_enabled(void)
{
    return false;
}

void *sev_guest_init(const char *id)
{
    return NULL;
}

uint64_t sev_get_me_mask(void)
{
    return ~0UL;
}

void sev_get_fw_version(uint8_t *major, uint8_t *minor, uint8_t *build)
{
}

void sev_get_policy(uint32_t *policy)
{
}

char *sev_get_launch_measurement(void)
{
    return NULL;
}
