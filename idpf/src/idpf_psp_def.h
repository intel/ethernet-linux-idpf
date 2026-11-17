/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_DEF_H_
#define _IDPF_PSP_DEF_H_

#if IS_ENABLED(CONFIG_INET_PSP)
#include <net/psp.h>
#endif

/**
 * struct idpf_adapter_psp - PSP offload state of an adapter
 * @enabled: PSP was negotiated with the CP in the last core init, see
 *	     idpf_is_psp_ena()
 * @psp_dev: the PSP device, see idpf_psp_register()
 * @caps: capabilities of @psp_dev
 */
struct idpf_adapter_psp {
	bool enabled;
	struct psp_dev *psp_dev;
#if IS_ENABLED(CONFIG_INET_PSP)
	struct psp_dev_caps caps;
#endif
};

#endif /* !_IDPF_PSP_DEF_H_ */
