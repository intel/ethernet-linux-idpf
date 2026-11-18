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

/**
 * idpf_print_psp_caps - Print values inside virtchnl2_psp_get_caps
 * @adapter: Driver specific private structure
 * @caps: Pointer to virtchnl2_psp_get_caps structure
 */
static void idpf_print_psp_caps(struct idpf_adapter *adapter,
				const struct virtchnl2_psp_get_caps *caps)
{
	u32 psp_caps = le32_to_cpu(caps->psp_caps);

	dev_dbg(&adapter->pdev->dev,
		"virtchnl2_psp_get_caps: psp_caps=0x%08x (PROTO_V0=%u, PROTO_V1=%u, REQUEST_ROTATION=%u, DOMAIN=%u)\n",
		psp_caps,
		!!(psp_caps & VIRTCHNL2_CAP_PSP_PROTO_V0),
		!!(psp_caps & VIRTCHNL2_CAP_PSP_PROTO_V1),
		!!(psp_caps & VIRTCHNL2_CAP_PSP_REQUEST_ROTATION),
		!!(psp_caps & VIRTCHNL2_CAP_PSP_DOMAIN));
}

/**
 * idpf_send_get_psp_caps - Send VIRTCHNL2_OP_PSP_GET_CAPS request to CP
 * @adapter: Driver specific private structure
 * @caps: Output buffer for virtchnl2_psp_get_caps
 *
 * Request all PSP capabilities, PSP capabilities that are not requested are
 * not available.
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_send_get_psp_caps(struct idpf_adapter *adapter,
			   struct virtchnl2_psp_get_caps *caps)
{
	struct virtchnl2_psp_get_caps send_caps = {
		.psp_caps = cpu_to_le32(VIRTCHNL2_CAP_PSP_PROTO_V0 |
					VIRTCHNL2_CAP_PSP_PROTO_V1 |
					VIRTCHNL2_CAP_PSP_REQUEST_ROTATION |
					VIRTCHNL2_CAP_PSP_DOMAIN),
	};
	struct kvec recv_mem = { };
	int err;

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_PSP_GET_CAPS,
			       idpf_get_vc_xn_default_timeout(adapter),
			       &send_caps, sizeof(send_caps), &recv_mem);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to get PSP caps: %d\n",
			err);
		return err;
	}

	if (recv_mem.iov_len < sizeof(*caps)) {
		dev_err(&adapter->pdev->dev, "Invalid PSP caps reply size: %zu\n",
			recv_mem.iov_len);
		err = -EIO;
		goto release_rx;
	}

	memcpy(caps, recv_mem.iov_base, sizeof(*caps));
	idpf_print_psp_caps(adapter, caps);

release_rx:
	idpf_psp_release_rx_buf(&recv_mem);
	return err;
}

/**
 * idpf_send_get_fips_compliance_status - Get the FIPS compliance status
 * @adapter: Driver specific private structure
 *
 * Query the FIPS compliance status of the crypto offload with
 * VIRTCHNL2_OP_GET_FIPS_COMPLIANCE_STATUS and log it in the legacy
 * "compliant@cmvp_cert_<a>_and_<b>" form, or as "noncompliant".
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_send_get_fips_compliance_status(struct idpf_adapter *adapter)
{
	const struct virtchnl2_get_fips_compliance_status_resp *resp;
	struct device *dev = &adapter->pdev->dev;
	struct kvec recv_mem = { };
	char status[128];
	size_t reply_sz;
	u32 num_certs;
	int len, err;
	/* The request has no payload, but empty messages can't be sent */
	u8 dummy = 0;
	u32 i;

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_GET_FIPS_COMPLIANCE_STATUS,
			       idpf_get_vc_xn_default_timeout(adapter),
			       &dummy, sizeof(dummy), &recv_mem);
	if (err)
		return err;

	reply_sz = recv_mem.iov_len;
	resp = (const struct virtchnl2_get_fips_compliance_status_resp *)
	       recv_mem.iov_base;
	if (reply_sz < sizeof(*resp)) {
		err = -EIO;
		goto release_rx;
	}

	num_certs = le32_to_cpu(resp->num_certs);
	if (struct_size(resp, certs, num_certs) > reply_sz) {
		err = -EIO;
		goto release_rx;
	}

	if (!num_certs) {
		dev_info(dev, "PSP FIPS compliance: noncompliant\n");
		goto release_rx;
	}

	len = scnprintf(status, sizeof(status), "compliant@cmvp_cert_");
	for (i = 0; i < num_certs; i++)
		len += scnprintf(status + len, sizeof(status) - len, "%s%u",
				 i ? "_and_" : "", le32_to_cpu(resp->certs[i]));
	dev_info(dev, "PSP FIPS compliance: %s\n", status);

release_rx:
	idpf_psp_release_rx_buf(&recv_mem);
	return err;
}

/**
 * idpf_send_allocate_psp_key - Allocate a PSP RX key
 * @adapter: Driver specific private structure
 * @key: filled with the allocated SPI and key and their master key generation
 *
 * Allocate one RX key with a synchronous VIRTCHNL2_OP_PSP_ALLOCATE_KEYS
 * request. The caller must be allowed to sleep.
 *
 * Return: 0 on success, negative error code on failure.
 */
int idpf_send_allocate_psp_key(struct idpf_adapter *adapter,
			       struct idpf_psp_rx_key *key)
{
	const struct virtchnl2_psp_allocate_keys_response *vc_reply;
	struct virtchnl2_psp_allocate_keys_request key_req = { };
	const struct virtchnl2_allocate_psp_key_v0 *v0_key;
	struct kvec recv_mem = { };
	size_t reply_sz;
	u32 spi;
	int err;

	BUILD_BUG_ON(sizeof(key->key) != sizeof(v0_key->v0_key));

	key_req.vport_id = cpu_to_le32(READ_ONCE(adapter->psp.vport_id));
	key_req.num_keys = cpu_to_le32(1);
	key_req.key_type = VIRTCHNL2_PSP_KEY_TYPE_V0;
	/* key_req.domain stays zeroed: VIRTCHNL2_PSP_DOMAIN_NONE */

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_PSP_ALLOCATE_KEYS,
			       idpf_get_vc_xn_default_timeout(adapter),
			       &key_req, sizeof(key_req), &recv_mem);
	if (err)
		return err;

	reply_sz = recv_mem.iov_len;
	vc_reply = (const struct virtchnl2_psp_allocate_keys_response *)
		   recv_mem.iov_base;
	if (reply_sz < offsetof(typeof(*vc_reply), keys) + sizeof(*v0_key) ||
	    vc_reply->key_type != VIRTCHNL2_PSP_KEY_TYPE_V0 ||
	    le32_to_cpu(vc_reply->keys_size_bytes) != sizeof(*v0_key)) {
		net_warn_ratelimited("%s: invalid reply of %zu bytes\n",
				     __func__, reply_sz);
		err = -EIO;
		goto release_rx;
	}

	v0_key = (const struct virtchnl2_allocate_psp_key_v0 *)vc_reply->keys;
	spi = le32_to_cpu(v0_key->spi);
	if (!(spi & PSP_SPI_KEY_ID)) {
		net_warn_ratelimited("%s: invalid SPI %#x\n", __func__, spi);
		err = -EIO;
		goto release_rx;
	}

	key->spi = cpu_to_be32(spi);
	key->generation = le32_to_cpu(vc_reply->master_key_generation);
	memcpy(key->key, v0_key->v0_key, sizeof(key->key));
	atomic_inc(&adapter->psp.keys_allocated);

release_rx:
	/* Don't leave the RX key in the freed reply buffer */
	memzero_explicit(recv_mem.iov_base, reply_sz);
	idpf_psp_release_rx_buf(&recv_mem);
	return err;
}

/**
 * idpf_psp_rotation_request - Request a PSP master key rotation
 * @adapter: Driver specific private structure
 *
 * Return: 0 on success, -EOPNOTSUPP if VIRTCHNL2_CAP_PSP_REQUEST_ROTATION was
 * not granted, other negative error code on failure.
 */
int idpf_psp_rotation_request(struct idpf_adapter *adapter)
{
	const struct virtchnl2_psp_rotate_keygen_response *resp;
	struct virtchnl2_psp_rotate_keygen_request req = { };
	struct kvec recv_mem = { };
	int err;

	if (!(adapter->psp.psp_caps & VIRTCHNL2_CAP_PSP_REQUEST_ROTATION))
		return -EOPNOTSUPP;

	req.vport_id = cpu_to_le32(READ_ONCE(adapter->psp.vport_id));
	/* req.domain stays zeroed: VIRTCHNL2_PSP_DOMAIN_NONE */

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_PSP_ROTATE_KEYGEN_REQUEST,
			       idpf_get_vc_xn_default_timeout(adapter),
			       &req, sizeof(req), &recv_mem);
	if (err) {
		net_warn_ratelimited("%s: err %d\n", __func__, err);
		return err;
	}

	resp = (const struct virtchnl2_psp_rotate_keygen_response *)
	       recv_mem.iov_base;
	if (recv_mem.iov_len >= sizeof(*resp))
		dev_dbg(&adapter->pdev->dev,
			"PSP master key generation %u after rotation\n",
			le32_to_cpu(resp->master_key_generation_id));
	idpf_psp_release_rx_buf(&recv_mem);

	return 0;
}

/**
 * idpf_psp_rotation_event - Handle a VIRTCHNL2_EVENT_PSP_ROTATE_KEY event
 * @adapter: Driver specific private structure
 * @ctlq_msg: event message, its receive buffer is posted back by the caller
 *
 * The CP rotated the master keys, it reports the generation of the new active
 * master key. The driver tracks the master keys of the RX SPIs it allocates,
 * see idpf_psp_rx_gen_update(): the next SPIs of the new master key are
 * reported with the PSP device generation of their associations.
 *
 * The PSP core is not told about a rotation that it didn't request: the
 * associations whose master key the rotation discarded can't receive anymore,
 * but they aren't marked stale and no key rotation notification is sent. mlx5
 * has the same limitation, see "no support for protecting against external
 * rotations" in mlx5e_psp_key_rotate(). The PSP device lock can't be taken
 * here, as it is held across synchronous mailbox requests that are completed
 * by the mailbox task running this handler.
 *
 * A possible solution, not implemented: a PSP core helper for drivers, e.g.
 * psp_dev_key_rotated(psd, generation), doing what psp_nl_key_rotate_doit()
 * does after the ->key_rotate() op succeeded: set the generation, mark the
 * associations of the discarded master key stale with psp_assocs_key_rotated()
 * and send the key rotation notification. idpf would call it with the PSP
 * device lock held from a work item queued here, for the events whose
 * generation is not the one returned by idpf_psp_rotation_request(): the CP
 * also sends the event for the rotations the driver requested.
 */
void idpf_psp_rotation_event(struct idpf_adapter *adapter,
			     const struct idpf_ctlq_msg *ctlq_msg)
{
	const struct virtchnl2_psp_rotation_event *rt_event;
	u32 gen;

	if (!idpf_is_psp_ena(adapter)) {
		net_warn_ratelimited("PSP not enabled, ignoring PSP rotation event.\n");
		return;
	}

	if (ctlq_msg->data_len < sizeof(*rt_event)) {
		net_warn_ratelimited("Invalid payload size for PSP rotation event, payload size: %u, expected min: %zu\n",
				     ctlq_msg->data_len, sizeof(*rt_event));
		return;
	}

	rt_event = (const struct virtchnl2_psp_rotation_event *)
		   ctlq_msg->ctx.indirect.payload->va;
	gen = le32_to_cpu(rt_event->psp_rotate_event.active_master_key_generation_id);

	net_info_ratelimited("PSP Rotation Event processed, active master key generation %u.\n",
			     gen);
}

/**
 * idpf_send_get_psp_stats - Send VIRTCHNL2_OP_GET_PSP_STATS
 * @adapter: Driver specific private structure
 * @stats: Output buffer for virtchnl2_psp_stats_response
 *
 * Request the common and add-on PSP statistics. Only the stat groups set in
 * @stats->supported_stats are valid: a group is only reported as supported if
 * it was requested and is present in the reply, which may leave out trailing
 * groups that are not supported.
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_send_get_psp_stats(struct idpf_adapter *adapter,
			    struct virtchnl2_psp_stats_response *stats)
{
	const u32 requested = VIRTCHNL2_PSP_STAT_COMMON | VIRTCHNL2_PSP_STAT_ADDON;
	struct virtchnl2_psp_stats_request req = {
		.requested_stats = cpu_to_le32(requested),
	};
	struct kvec recv_mem = { };
	size_t reply_sz;
	u32 supported;
	int err;

	err = idpf_psp_vc_send(adapter, VIRTCHNL2_OP_GET_PSP_STATS,
			       idpf_get_vc_xn_default_timeout(adapter),
			       &req, sizeof(req), &recv_mem);
	if (err)
		return err;

	reply_sz = recv_mem.iov_len;
	if (reply_sz < offsetof(typeof(*stats), common_stats)) {
		err = -EIO;
		goto release_rx;
	}

	memset(stats, 0, sizeof(*stats));
	memcpy(stats, recv_mem.iov_base, min(reply_sz, sizeof(*stats)));

	supported = le32_to_cpu(stats->supported_stats) & requested;
	if (reply_sz < offsetofend(typeof(*stats), common_stats))
		supported &= ~VIRTCHNL2_PSP_STAT_COMMON;
	if (reply_sz < offsetofend(typeof(*stats), addon_stats))
		supported &= ~VIRTCHNL2_PSP_STAT_ADDON;
	stats->supported_stats = cpu_to_le32(supported);

release_rx:
	idpf_psp_release_rx_buf(&recv_mem);
	return err;
}

/**
 * idpf_psp_recv_reply - Wipe the RX keys of a reply from the mailbox buffer
 * @adapter: Driver specific private structure
 * @ctlq_msg: reply, its receive buffer is posted back by the caller
 *
 * Called by idpf_recv_mb_msg() for all the replies, including the late
 * replies to requests that timed out, after they were copied to the waiting
 * transaction.
 */
void idpf_psp_recv_reply(struct idpf_adapter *adapter,
			 const struct idpf_ctlq_msg *ctlq_msg)
{
	const struct idpf_dma_mem *dma_mem = ctlq_msg->ctx.indirect.payload;

	switch (ctlq_msg->cookie.mbx.chnl_opcode) {
	case VIRTCHNL2_OP_PSP_ALLOCATE_KEYS:
		if (ctlq_msg->data_len && dma_mem && dma_mem->va)
			memzero_explicit(dma_mem->va, dma_mem->size);
		break;
	default:
		break;
	}
}
