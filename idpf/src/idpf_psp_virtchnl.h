/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_VIRTCHNL_H_
#define _IDPF_PSP_VIRTCHNL_H_

#include "idpf_psp.h"

int idpf_send_get_crypto_caps(struct idpf_adapter *adapter,
			      struct virtchnl2_crypto_get_caps *caps);
int idpf_send_get_psp_caps(struct idpf_adapter *adapter,
			   struct virtchnl2_psp_get_caps *caps);
int idpf_send_get_fips_compliance_status(struct idpf_adapter *adapter);
int idpf_send_allocate_psp_key(struct idpf_adapter *adapter,
			       struct idpf_psp_rx_key *key);
int idpf_psp_rotation_request(struct idpf_adapter *adapter);
int idpf_send_get_psp_stats(struct idpf_adapter *adapter,
			    struct virtchnl2_psp_stats_response *stats);
bool idpf_send_delete_psp_keys(struct idpf_adapter *adapter);
void idpf_psp_insert_check_timeout(struct idpf_adapter *adapter);
void idpf_send_insert_psp_keys(struct idpf_adapter *adapter);

#endif /* !_IDPF_PSP_VIRTCHNL_H_ */
