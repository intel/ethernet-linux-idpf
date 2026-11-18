/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _IDPF_PSP_VIRTCHNL_DEF_H_
#define _IDPF_PSP_VIRTCHNL_DEF_H_

/* PSP key insertion and deletion requests must fit in one mailbox buffer,
 * which limits the number of TX keys and SA indexes per request.
 */
#define IDPF_PSP_DELETE_KEYS_MAX					\
	((IDPF_CTLQ_MAX_BUF_LEN -					\
	  offsetof(struct virtchnl2_psp_delete_keys_request, sa_indexes)) / \
	 sizeof(__le32))

#endif /* !_IDPF_PSP_VIRTCHNL_DEF_H_ */
