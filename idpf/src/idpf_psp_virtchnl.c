/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2026 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0-only

#include "idpf_psp_virtchnl.h"
#include "idpf_virtchnl.h"

/**
 * idpf_psp_vc_send - Send a PSP virtchnl request and capture the reply
 * @adapter: Driver specific private structure
 * @vc_op: virtchnl2 opcode
 * @timeout_ms: transaction timeout in milliseconds
 * @send_buf: request payload
 * @send_sz: request payload size
 * @recv_mem: filled with the reply buffer, released by idpf_psp_release_rx_buf()
 *
 * Return: 0 on success, negative on failure.
 */
static int idpf_psp_vc_send(struct idpf_adapter *adapter, u32 vc_op,
			    int timeout_ms, void *send_buf, size_t send_sz,
			    struct kvec *recv_mem)
{
	struct idpf_vc_xn_params xn_params = {
		.send_buf = { .iov_base = send_buf, .iov_len = send_sz },
		.timeout_ms = timeout_ms,
		.vc_op = vc_op,
	};
	ssize_t reply_sz;
	void *buf;

	recv_mem->iov_base = NULL;
	recv_mem->iov_len = 0;

	buf = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	xn_params.recv_buf.iov_base = buf;
	xn_params.recv_buf.iov_len = IDPF_CTLQ_MAX_BUF_LEN;

	reply_sz = idpf_vc_xn_exec(adapter, &xn_params);
	if (reply_sz < 0) {
		kfree(buf);
		return reply_sz;
	}

	recv_mem->iov_base = buf;
	recv_mem->iov_len = min_t(size_t, reply_sz, IDPF_CTLQ_MAX_BUF_LEN);

	return 0;
}

/* Release the reply buffer filled by idpf_psp_vc_send(). */
static void idpf_psp_release_rx_buf(struct kvec *recv_mem)
{
	kfree(recv_mem->iov_base);
	recv_mem->iov_base = NULL;
	recv_mem->iov_len = 0;
}

/**
 * idpf_print_crypto_caps - Print values inside virtchnl2_crypto_get_caps
 * @adapter: Driver specific private structure
 * @caps: Pointer to virtchnl2_crypto_get_caps structure
 */
static void idpf_print_crypto_caps(struct idpf_adapter *adapter,
				   const struct virtchnl2_crypto_get_caps *caps)
{
	u32 num_sadb_entries = le32_to_cpu(caps->num_sadb_entries);
	u32 crypto_caps = le32_to_cpu(caps->crypto_caps);

	dev_dbg(&adapter->pdev->dev,
		"virtchnl2_crypto_get_caps: crypto_caps=0x%08x (PSP=%u), num_sadb_entries=%u, saidx_width=%u\n",
		crypto_caps, !!(crypto_caps & VIRTCHNL2_CAP_CRYPTO_PSP),
		num_sadb_entries, caps->saidx_width);
}

/**
 * idpf_send_get_crypto_caps - Send VIRTCHNL2_OP_CRYPTO_GET_CAPS request to CP
 * @adapter: Driver specific private structure
 * @caps: Output buffer for virtchnl2_crypto_get_caps
 *
 * Request the PSP crypto offload. Must only be sent if VIRTCHNL2_CAP_CRYPTO
 * was granted.
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_send_get_crypto_caps(struct idpf_adapter *adapter,
			      struct virtchnl2_crypto_get_caps *caps)
{
	struct virtchnl2_crypto_get_caps *send_caps;
	struct kvec recv_mem = { };
	int err;

	/* Too large to be sent from the stack */
	send_caps = kzalloc(sizeof(*send_caps), GFP_KERNEL);
	if (!send_caps)
		return -ENOMEM;

	send_caps->crypto_caps = cpu_to_le32(VIRTCHNL2_CAP_CRYPTO_PSP);

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_CRYPTO_GET_CAPS,
			       idpf_get_vc_xn_default_timeout(adapter),
			       send_caps, sizeof(*send_caps), &recv_mem);
	kfree(send_caps);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to get crypto caps: %d\n",
			err);
		return err;
	}

	if (recv_mem.iov_len < sizeof(*caps)) {
		dev_err(&adapter->pdev->dev, "Invalid crypto caps reply size: %zu\n",
			recv_mem.iov_len);
		err = -EIO;
		goto release_rx;
	}

	memcpy(caps, recv_mem.iov_base, sizeof(*caps));
	idpf_print_crypto_caps(adapter, caps);

release_rx:
	idpf_psp_release_rx_buf(&recv_mem);
	return err;
}
