/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_
#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>

void idpf_get_xsk_pool(struct idpf_queue *q, bool xdp_txq);
bool idpf_xsk_is_zc_bufq(struct idpf_queue *rxbufq);
int idpf_xsk_pool_setup(struct net_device *netdev, struct xsk_buff_pool *pool,
			u16 qid);
int idpf_xsk_handle_pool_change(struct idpf_vport *vport);
int idpf_rx_splitq_clean_zc(struct idpf_queue *rxq, int budget);
int idpf_rx_singleq_clean_zc(struct idpf_queue *rxq, int budget);
void idpf_rx_buf_hw_alloc_zc_all(struct idpf_vport *vport,
				 struct idpf_q_grp *q_grp,
				 struct idpf_queue *rxq);
int idpf_rx_update_bufq_desc_zc(struct idpf_rx_buf *buf,
				struct idpf_queue *bufq,
				struct idpf_page_info *page_info,
				struct virtchnl2_splitq_rx_buf_desc *buf_desc,
				u16 buf_id);
void idpf_rx_buf_rel_zc(struct idpf_rx_buf *buf);
void idpf_tx_splitq_clean_zc(struct idpf_queue *xdpq, u16 compl_tag,
			     struct idpf_cleaned_stats *cleaned);
bool idpf_tx_singleq_clean_zc(struct idpf_queue *xdpq, int *cleaned);
bool idpf_tx_splitq_xmit_zc(struct idpf_queue *xdpq);
void idpf_xsk_cleanup_xdpq(struct idpf_queue *xdpq);
bool idpf_xsk_any_rxq_ena(struct idpf_vport *vport);
#ifdef HAVE_NDO_XSK_WAKEUP
int idpf_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
int idpf_xsk_singleq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
#else
int idpf_xsk_splitq_async_xmit(struct net_device *netdev, u32 q_id);
int idpf_xsk_singleq_async_xmit(struct net_device *netdev, u32 q_id);
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* !_IDPF_XSK_H_ */
