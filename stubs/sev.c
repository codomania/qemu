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

int sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len)
{
    return 1;
}

SevState sev_get_current_state(void)
{
    return SEV_STATE_UNINIT;
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

uint32_t sev_get_cbit_position(void)
{
    return 0;
}

uint32_t sev_get_reduced_phys_bits(void)
{
    return 0;
}

void sev_get_fw_version(uint8_t *major, uint8_t *minor, uint8_t *build)
{
}

void sev_get_policy(uint32_t *policy)
{
}
