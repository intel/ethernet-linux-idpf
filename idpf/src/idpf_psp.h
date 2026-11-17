/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_H_
#define _IDPF_PSP_H_

#include "idpf.h"

#if IS_ENABLED(CONFIG_INET_PSP)

void idpf_psp_init(struct idpf_adapter *adapter);
void idpf_psp_free(struct idpf_adapter *adapter);
void idpf_psp_register(struct idpf_adapter *adapter);
void idpf_psp_unregister(struct idpf_adapter *adapter);

#else /* !CONFIG_INET_PSP */

static inline void idpf_psp_init(struct idpf_adapter *adapter) { }
static inline void idpf_psp_free(struct idpf_adapter *adapter) { }
static inline void idpf_psp_register(struct idpf_adapter *adapter) { }
static inline void idpf_psp_unregister(struct idpf_adapter *adapter) { }

#endif /* CONFIG_INET_PSP */

#endif /* !_IDPF_PSP_H_ */
