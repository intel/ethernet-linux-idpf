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

#endif /* !_IDPF_PSP_VIRTCHNL_H_ */
