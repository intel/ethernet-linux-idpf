/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2025 Intel Corporation */

#ifndef _IDPF_TXRX_H_
#define _IDPF_TXRX_H_

#ifdef HAVE_CONFIG_DIMLIB
#include <linux/dim.h>
#else
#include "kcompat_dim.h"
#endif /* HAVE_CONFIG_DIMLIB */
#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
#include <linux/indirect_call_wrapper.h>
#endif
#include <net/tcp.h>
#ifdef HAVE_NETIF_SUBQUEUE_MAYBE_STOP
#include <net/netdev_queues.h>
#endif /* HAVE_NETIF_SUBQUEUE_MAYBE_STOP */
#ifdef HAVE_XDP_SUPPORT
#include <net/xdp.h>
#endif /* HAVE_XDP_SUPPORT */
#include "libeth_tx.h"
#include "idpf_lan_txrx.h"
#include "virtchnl2_lan_desc.h"

#define idpf_tx_buf_next(buf)      (*(u32 *)&(buf)->priv)
#define idpf_tx_buf_compl_tag(buf)      (*(u32 *)&(buf)->priv)
LIBETH_SQE_CHECK_PRIV(u32);

#define IDPF_LARGE_MAX_Q			256
#define IDPF_MAX_TXQ				IDPF_LARGE_MAX_Q
#define IDPF_MAX_RXQ				64
#define IDPF_MIN_Q				2
#define IDPF_DFLT_NUM_Q				16
/* Mailbox Queue */
#define IDPF_MAX_MBXQ				1

#ifdef DEVLINK_ENABLED
#define IDPF_MAX_DYNAMIC_VPORT			925
#endif /* DEVLINK_ENABLED */
#define IDPF_MIN_TXQ_DESC			64
#define IDPF_MIN_RXQ_DESC			64
#define IDPF_MIN_TXQ_COMPLQ_DESC		256
/* Number of descriptors in a queue should be a multiple of 32. RX queue
 * descriptors alone should be a multiple of IDPF_REQ_RXQ_DESC_MULTIPLE
 * to achieve BufQ descriptors aligned to 32
 */
#define IDPF_REQ_DESC_MULTIPLE			32
#define IDPF_REQ_RXQ_DESC_MULTIPLE \
	(IDPF_MAX_BUFQS_PER_RXQ_GRP * IDPF_REQ_DESC_MULTIPLE)
#define IDPF_MIN_TX_DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define IDPF_TX_WAKE_THRESH ((u16)IDPF_MIN_TX_DESC_NEEDED * 2)

#define IDPF_MAX_DESCS				8160
#define IDPF_MAX_TXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_DESC_MULTIPLE)
#define IDPF_MAX_RXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_RXQ_DESC_MULTIPLE)
#define MIN_SUPPORT_TXDID (\
	VIRTCHNL2_TXDID_FLEX_FLOW_SCHED |\
	VIRTCHNL2_TXDID_FLEX_TSO_CTX)

#define IDPF_DFLT_SINGLEQ_TX_Q_GROUPS		1
#define IDPF_DFLT_SINGLEQ_RX_Q_GROUPS		1

#define IDPF_COMPLQ_PER_GROUP			1
#define IDPF_SINGLE_BUFQ_PER_RXQ_GRP		1

/* HW can map multiple RX queues to a set of buffer queues in an N:M
 * configuration with N RX queues and M buffer queues. For now there is only
 * the 1:M case accounted for until there is a benefit otherwise.
 */
#define IDPF_DFLT_SPLITQ_RXQ_PER_BUFQ		1

#define IDPF_MAX_BUFQS_PER_RXQ_GRP		2
#define IDPF_NUMQ_PER_CHUNK			1

#define IDPF_DFLT_SPLITQ_TXQ_PER_GROUP		1
#define IDPF_DFLT_SPLITQ_RXQ_PER_GROUP		1

/* Default vector sharing */
#define IDPF_MBX_Q_VEC		1
#define IDPF_MIN_Q_VEC		1
#define IDPF_MIN_RDMA_VEC	2 /* Minimum vectors to be shared with RDMA */

#define IDPF_DFLT_TX_Q_DESC_COUNT		512
#define IDPF_DFLT_TX_COMPLQ_DESC_COUNT		512
#define IDPF_DFLT_RX_Q_DESC_COUNT		512

/* IMPORTANT: We absolutely _cannot_ have more buffers in the system than a
 * given RX completion queue has descriptors. This includes _ALL_ buffer
 * queues. E.g.: If you have two buffer queues of 512 descriptors and buffers,
 * you have a total of 1024 buffers so your RX queue _must_ have at least that
 * many descriptors. This macro divides a given number of RX descriptors by
 * number of buffer queues to calculate how many descriptors each buffer queue
 * can have without overrunning the RX queue.
 *
 * If you give hardware more buffers than completion descriptors what will
 * happen is that if hardware gets a chance to post more than ring wrap of
 * descriptors before SW gets an interrupt and overwrites SW head, the gen bit
 * in the descriptor will be wrong. Any overwritten descriptors' buffers will
 * be gone forever and SW has no reasonable way to tell that this has happened.
 * From SW perspective, when we finally get an interrupt, it looks like we're
 * still waiting for descriptor to be done, stalling forever.
 */
#define IDPF_RX_BUFQ_DESC_COUNT(RXD, NUM_BUFQ)	((RXD) / (NUM_BUFQ))

#define IDPF_RX_BUFQ_WORKING_SET(rxq)		((rxq)->desc_count - 1)
#define IDPF_RX_BUFQ_NON_WORKING_SET(rxq)	((rxq)->desc_count - \
						 IDPF_RX_BUFQ_WORKING_SET(rxq))

/* If we are ever running on a kernel where, for example, MAX_SKB_FRAGS is
 * sufficiently larger than the default, sizeof(struct skb_shared_info) can put
 * us beyond the 1024 byte skb->head limitation required to use the dedicated
 * order-0 page frag allocator introduced in "net: skb: introduce and use a
 * single page frag cache".  If using the a static RX header size of 256 in the
 * above example:
 * NET_SKB_PAD(64) + RX_HDR_SIZE(256) + sizeof(struct skb_shared_info) > 1024
 *
 * Define the default RX header size based on sizeof(struct skb_shared_info),
 * NET_SKB_PAD, and NET_IP_ALIGN to ensure we never allocate more than 1024 for
 * skb->head.
 */
#define IDPF_SKB_HEAD_SIZE			SKB_WITH_OVERHEAD(1024 - \
								  NET_SKB_PAD - \
								  NET_IP_ALIGN)
#define IDPF_RX_HDR_SIZE			min(256, (int)IDPF_SKB_HEAD_SIZE)
#define IDPF_MIN_RX_HDR_SIZE			192
#define IDPF_RX_BUF_2048			2048
#define IDPF_RX_BUF_4096			4096
#define IDPF_RX_BUF_STRIDE			32
#define IDPF_RX_BUF_POST_STRIDE			16
#define IDPF_LOW_WATERMARK			64
/* Size of header buffer specifically for header split */
#define IDPF_HDR_BUF_SIZE			256
#define IDPF_PACKET_HDR_PAD	\
	(ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN * 2)
#define IDPF_TX_TSO_MIN_MSS			88

/* Minimum number of descriptors between 2 descriptors with the RE bit set;
 * only relevant in flow scheduling mode
 */
#define IDPF_TX_SPLITQ_RE_MIN_GAP	64

#define IDPF_RFL_BI_GEN_M		BIT(16)
#define IDPF_RFL_BI_BUFID_M		GENMASK(15, 0)

#define IDPF_RXD_EOF_SPLITQ		VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_EOF_M
#define IDPF_RXD_EOF_SINGLEQ		VIRTCHNL2_RX_BASE_DESC_STATUS_EOF_M

#define IDPF_SINGLEQ_RX_BUF_DESC(rxq, i)	\
	(&(((struct virtchnl2_singleq_rx_buf_desc *)((rxq)->desc_ring))[i]))
#define IDPF_SPLITQ_RX_BUF_DESC(rxq, i)	\
	(&(((struct virtchnl2_splitq_rx_buf_desc *)((rxq)->desc_ring))[i]))
#define IDPF_SPLITQ_RX_BI_DESC(rxq, i)	((((rxq)->ring))[i])

#define IDPF_BASE_TX_DESC(txq, i)	\
	(&(((struct idpf_base_tx_desc *)((txq)->desc_ring))[i]))
#define IDPF_BASE_TX_CTX_DESC(txq, i) \
	(&(((struct idpf_base_tx_ctx_desc *)((txq)->desc_ring))[i]))
#define IDPF_SPLITQ_TX_COMPLQ_DESC(txcq, i)	\
	(&(((struct idpf_splitq_tx_compl_desc *)((txcq)->desc_ring))[i]))

#define IDPF_FLEX_TX_DESC(txq, i)	\
	(&(((union idpf_tx_flex_desc *)((txq)->desc_ring))[i]))
#define IDPF_FLEX_TX_CTX_DESC(txq, i)	\
	(&(((union idpf_flex_tx_ctx_desc *)((txq)->desc_ring))[i]))

#define IDPF_DESC_UNUSED(txq)	\
	((((txq)->next_to_clean > (txq)->next_to_use) ? \
	0 : (txq)->desc_count) + \
	(txq)->next_to_clean - (txq)->next_to_use - 1)

#define IDPF_TX_COMPLQ_OVERFLOW_THRESH(txcq)	((txcq)->desc_count >> 1)
/* Determine the absolute number of completions pending, i.e. the number of
 * completions that are expected to arrive on the TX completion queue.  This
 * number should never be more than ~IDPF_TX_COMPLQ_OVERFLOW_THRESH. That is
 * because once the delta hits IDPF_TX_COMPLQ_OVERFLOW_THRESH, the txq is
 * stopped, i.e. num_completions_pending won't increment. Meanwhile,
 * num_completions should continue incrementing as completions are processed.
 * Eventually the delta will become small enough that the txq can be restarted.
 */
#define IDPF_TX_COMPLQ_PENDING(txq)	\
	((txq)->num_completions_pending - (txq)->complq->tx.num_completions)

#define IDPF_TX_SPLITQ_MISS_COMPL_TAG  BIT(15)

#define IDPF_TXBUF_NULL			U32_MAX

#define IDPF_TXD_LAST_DESC_CMD (IDPF_TX_DESC_CMD_EOP | IDPF_TX_DESC_CMD_RS)

#define IDPF_TX_FLAGS_TSO			BIT(0)
#define IDPF_TX_FLAGS_IPV4			BIT(1)
#define IDPF_TX_FLAGS_IPV6			BIT(2)
#define IDPF_TX_FLAGS_TUNNEL			BIT(3)
#define IDPF_TX_FLAGS_TSYN			BIT(4)
#ifdef HAVE_XDP_SUPPORT
#define IDPF_XDP_PASS		0
#define IDPF_XDP_CONSUMED	BIT(0)
#define IDPF_XDP_TX		BIT(1)
#define IDPF_XDP_REDIR		BIT(2)

#define IDPF_XDP_MAX_MTU        3046
#endif /* HAVE_XDP_SUPPORT */

/**
 * union idpf_tx_flex_desc
 * @q: Queue based scheduling
 * @flow: Flow based scheduling
 */
union idpf_tx_flex_desc {
	struct idpf_flex_tx_desc q;
	struct idpf_flex_tx_sched_desc flow;
};

#define IDPF_TX_TSTAMP_INVALID_IDX 0xFF

/**
 * enum libeth_sqe_type_ext - extended SQE types
 * @LIBETH_SQE_TSTAMP_SKB: SQE type for PTP SKBs
 * @LIBETH_SQE_MISS: SQE exception path packet, only unmap DMA
 * @LIBETH_SQE_REINJECT: exception path packet, napi_consume_skb(), update stats
 */
enum libeth_sqe_type_ext {
	LIBETH_SQE_SKB_TSTAMP = 1000,
	LIBETH_SQE_MISS,
	LIBETH_SQE_REINJECT,
};

#define idpf_tx_buf libeth_sqe

/**
 * struct idpf_tx_offload_params - Offload parameters for a given packet
 * @tx_flags: Feature flags enabled for this packet
 * @hdr_offsets: Offset parameter for single queue model
 * @cd_tunneling: Type of tunneling enabled for single queue model
 * @tso_len: Total length of payload to segment
 * @mss: Segment size
 * @tso_segs: Number of segments to be sent
 * @tso_hdr_len: Length of headers to be duplicated
 * @td_cmd: Command field to be inserted into descriptor
 * @desc_ts: Flow scheduling offload timestamp, formatting as hw expects it
 *	     timestamp = bits[0:22], overflow = bit[23]
 */
struct idpf_tx_offload_params {
	u32 tx_flags;
	u32 hdr_offsets;
	u32 cd_tunneling;
	u32 tso_len;
	u16 mss;
	u16 tso_segs;
	u16 tso_hdr_len;
	u16 td_cmd;
	u8 desc_ts[3];
};

/**
 * struct idpf_tx_splitq_params
 * @dtype: General descriptor info
 * @eop_cmd: Type of EOP
 * @compl_tag: Associated tag for completion
 * @td_tag: Descriptor tunneling tag
 * @offload: Offload parameters
 * @prev_ntu: stored TxQ next_to_use in case of rollback
 * @prev_refill_ntc: stored refillq next_to_clean in case of packet rollback
 * @prev_refill_gen: stored refillq generation bit in case of packet rollback
 */
struct idpf_tx_splitq_params {
	enum idpf_tx_desc_dtype_value dtype;
	u16 eop_cmd;
	union {
		u32 compl_tag;
		u16 td_tag;
	};
	struct idpf_tx_offload_params offload;

	u16 prev_ntu;
	u16 prev_refill_ntc;
	bool prev_refill_gen;
};

/**
 * struct idpf_reinject_timer
 * @timer: Timer to bound how long a pkt can be on the exception path
 * @txq: Pointer to the TX queue that this packet belongs to
 * @skb: Pointer to the skb that is being reinjected
 * @bytes: Number of bytes in the skb
 * @gso_segs: Number of segments in the skb
 */
struct idpf_reinject_timer {
	struct timer_list timer;
	struct idpf_queue *txq;
	struct sk_buff *skb;
	u32 bytes;
	u16 gso_segs;
};

enum idpf_tx_ctx_desc_eipt_offload {
	IDPF_TX_CTX_EXT_IP_NONE         = 0x0,
	IDPF_TX_CTX_EXT_IP_IPV6         = 0x1,
	IDPF_TX_CTX_EXT_IP_IPV4_NO_CSUM = 0x2,
	IDPF_TX_CTX_EXT_IP_IPV4         = 0x3
};

/* Checksum offload bits decoded from the receive descriptor. */
struct idpf_rx_csum_decoded {
	u32 l3l4p : 1;
	u32 ipe : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 ipv6exadd : 1;
	u32 l4e : 1;
	u32 pprs : 1;
	u32 nat : 1;
	u32 raw_csum_inv : 1;
	u32 raw_csum : 16;
};

struct idpf_rx_extracted {
	unsigned int size;
	u16 rx_ptype;
};

#define IDPF_TX_COMPLQ_CLEAN_BUDGET	256
#define IDPF_TX_MIN_PKT_LEN		17
#define IDPF_TX_DESCS_FOR_SKB_DATA_PTR	1
#define IDPF_TX_DESCS_PER_CACHE_LINE	(L1_CACHE_BYTES  / \
					sizeof(struct idpf_flex_tx_desc))
#define IDPF_TX_DESCS_FOR_CTX		1
/* TX descriptors needed, worst case: */
#define IDPF_TX_DESC_NEEDED (MAX_SKB_FRAGS + IDPF_TX_DESCS_FOR_CTX + \
			     IDPF_TX_DESCS_PER_CACHE_LINE + \
			     IDPF_TX_DESCS_FOR_SKB_DATA_PTR)

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define IDPF_TX_MAX_READ_REQ_SIZE	SZ_4K
#define IDPF_TX_MAX_DESC_DATA		(SZ_16K - 1)
#define IDPF_TX_MAX_DESC_DATA_ALIGNED \
	ALIGN_DOWN(IDPF_TX_MAX_DESC_DATA, IDPF_TX_MAX_READ_REQ_SIZE)

#define IDPF_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)
#define IDPF_RX_DESC(rxq, i)	\
	(&(((union virtchnl2_rx_desc *)((rxq)->desc_ring))[i]))

struct idpf_page_info {
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	unsigned int default_offset;
	u16 pagecnt_bias;
	u8 reuse_bias;
};

struct idpf_rx_buf {
#define IDPF_RX_BUF_MAX_PAGES 2
	struct idpf_page_info page_info[IDPF_RX_BUF_MAX_PAGES];
	u8 page_indx;
	u16 buf_size;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	union {
		struct sk_buff *skb;
		struct xdp_buff *xdp;
	};
#else
	struct sk_buff *skb;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
};

#define IDPF_RX_MAX_PTYPE_PROTO_IDS	32
#define IDPF_RX_MAX_PTYPE_SZ	(sizeof(struct virtchnl2_ptype) + \
				 (sizeof(u16) * \
				 (IDPF_RX_MAX_PTYPE_PROTO_IDS - 1)))
#define IDPF_RX_PTYPE_HDR_SZ	(sizeof(struct virtchnl2_get_ptype_info))
#define IDPF_RX_MAX_PTYPES_PER_BUF	\
	DIV_ROUND_DOWN_ULL((IDPF_CTLQ_MAX_BUF_LEN - IDPF_RX_PTYPE_HDR_SZ), \
			   IDPF_RX_MAX_PTYPE_SZ)

#define IDPF_GET_PTYPE_SIZE(p) struct_size((p), proto_id, (p)->proto_id_count)

#define IDPF_TUN_IP_GRE (\
	IDPF_PTYPE_TUNNEL_IP |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT)

#define IDPF_TUN_IP_GRE_MAC (\
	IDPF_TUN_IP_GRE |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC)

#define IDPF_RX_MAX_PTYPE	1024
#define IDPF_RX_MAX_BASE_PTYPE	256
#define IDPF_INVALID_PTYPE_ID	0xFFFF

/* Packet type non-ip values */
enum idpf_rx_ptype_l2 {
	IDPF_RX_PTYPE_L2_RESERVED	= 0,
	IDPF_RX_PTYPE_L2_MAC_PAY2	= 1,
	IDPF_RX_PTYPE_L2_TIMESYNC_PAY2	= 2,
	IDPF_RX_PTYPE_L2_FIP_PAY2	= 3,
	IDPF_RX_PTYPE_L2_OUI_PAY2	= 4,
	IDPF_RX_PTYPE_L2_MACCNTRL_PAY2	= 5,
	IDPF_RX_PTYPE_L2_LLDP_PAY2	= 6,
	IDPF_RX_PTYPE_L2_ECP_PAY2	= 7,
	IDPF_RX_PTYPE_L2_EVB_PAY2	= 8,
	IDPF_RX_PTYPE_L2_QCN_PAY2	= 9,
	IDPF_RX_PTYPE_L2_EAPOL_PAY2	= 10,
	IDPF_RX_PTYPE_L2_ARP		= 11,
};

enum idpf_rx_ptype_outer_ip {
	IDPF_RX_PTYPE_OUTER_L2	= 0,
	IDPF_RX_PTYPE_OUTER_IP	= 1,
};

#define IDPF_RX_PTYPE_TO_IPV(ptype, ipv)			\
	(((ptype)->outer_ip == IDPF_RX_PTYPE_OUTER_IP) &&	\
	 ((ptype)->outer_ip_ver == (ipv)))

enum idpf_rx_ptype_outer_ip_ver {
	IDPF_RX_PTYPE_OUTER_NONE	= 0,
	IDPF_RX_PTYPE_OUTER_IPV4	= 1,
	IDPF_RX_PTYPE_OUTER_IPV6	= 2,
};

enum idpf_rx_ptype_outer_fragmented {
	IDPF_RX_PTYPE_NOT_FRAG	= 0,
	IDPF_RX_PTYPE_FRAG	= 1,
};

enum idpf_rx_ptype_tunnel_type {
	IDPF_RX_PTYPE_TUNNEL_NONE		= 0,
	IDPF_RX_PTYPE_TUNNEL_IP_IP		= 1,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT		= 2,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC	= 3,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN	= 4,
};

enum idpf_rx_ptype_tunnel_end_prot {
	IDPF_RX_PTYPE_TUNNEL_END_NONE	= 0,
	IDPF_RX_PTYPE_TUNNEL_END_IPV4	= 1,
	IDPF_RX_PTYPE_TUNNEL_END_IPV6	= 2,
};

enum idpf_rx_ptype_inner_prot {
	IDPF_RX_PTYPE_INNER_PROT_NONE		= 0,
	IDPF_RX_PTYPE_INNER_PROT_UDP		= 1,
	IDPF_RX_PTYPE_INNER_PROT_TCP		= 2,
	IDPF_RX_PTYPE_INNER_PROT_SCTP		= 3,
	IDPF_RX_PTYPE_INNER_PROT_ICMP		= 4,
	IDPF_RX_PTYPE_INNER_PROT_TIMESYNC	= 5,
};

enum idpf_rx_ptype_payload_layer {
	IDPF_RX_PTYPE_PAYLOAD_LAYER_NONE	= 0,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2	= 1,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY3	= 2,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY4	= 3,
};

enum idpf_tunnel_state {
	IDPF_PTYPE_TUNNEL_IP                    = BIT(0),
	IDPF_PTYPE_TUNNEL_IP_GRENAT             = BIT(1),
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC         = BIT(2),
};

struct idpf_ptype_state {
	bool outer_ip;
	bool outer_frag;
	u8 tunnel_state;
};

struct idpf_rx_ptype_decoded {
	u32 ptype:10;
	u32 known:1;
	u32 outer_ip:1;
	u32 outer_ip_ver:2;
	u32 outer_frag:1;
	u32 tunnel_type:3;
	u32 tunnel_end_prot:2;
	u32 tunnel_end_frag:1;
	u32 inner_prot:4;
	u32 payload_layer:3;
};

/**
 * enum idpf_queue_flags_t
 * @__IDPF_Q_GEN_CHK: Queues operating in splitq mode use a generation bit to
 *		      identify new descriptor writebacks on the ring. HW sets
 *		      the gen bit to 1 on the first writeback of any given
 *		      descriptor. After the ring wraps, HW sets the gen bit of
 *		      those descriptors to 0, and continues flipping
 *		      0->1 or 1->0 on each ring wrap. SW maintains its own
 *		      gen bit to know what value will indicate writebacks on
 *		      the next pass around the ring. E.g. it is initialized
 *		      to 1 and knows that reading a gen bit of 1 in any
 *		      descriptor on the initial pass of the ring indicates a
 *		      writeback. It also flips on every ring wrap.
 * @__IDPF_Q_RFL_GEN_CHK: Refill queues are SW only, so Q_GEN acts as the HW bit
 *			 and RFLGQ_GEN is the SW bit.
 * @__IDPF_Q_FLOW_SCH_EN: Enable flow scheduling
 * @__IDPF_Q_ETF_EN: Enable ETF
 * @__IDPF_Q_SW_MARKER: Used to indicate TX queue marker completions
 * @__IDPF_Q_POLL_MODE: Enable poll mode
#ifdef HAVE_XDP_SUPPORT
 * @__IDPF_Q_XDP: Enable XDP queues
#endif
 * @__IDPF_Q_MISS_TAG_EN: Enable miss completion tag
 * @__IDPF_Q_FLAGS_NBITS: Must be last
 */
enum idpf_queue_flags_t {
	__IDPF_Q_GEN_CHK,
	__IDPF_Q_RFL_GEN_CHK,
	__IDPF_Q_FLOW_SCH_EN,
	__IDPF_Q_ETF_EN,
	__IDPF_Q_SW_MARKER,
	__IDPF_Q_POLL_MODE,
#ifdef HAVE_XDP_SUPPORT
	__IDPF_Q_XDP,
#endif /* HAVE_XDP_SUPPORT */
	__IDPF_Q_MISS_TAG_EN,
	__IDPF_Q_FLAGS_NBITS,
};

#define idpf_queue_set(f, q)            __set_bit(__IDPF_Q_##f, (q)->flags)
#define idpf_queue_clear(f, q)          __clear_bit(__IDPF_Q_##f, (q)->flags)
#define idpf_queue_change(f, q)         __change_bit(__IDPF_Q_##f, (q)->flags)
#define idpf_queue_has(f, q)            test_bit(__IDPF_Q_##f, (q)->flags)

#define idpf_queue_has_clear(f, q)                      \
	test_and_clear_bit(__IDPF_Q_##f, (q)->flags)
#define idpf_queue_assign(f, q, v)                      \
	__assign_bit(__IDPF_Q_##f, (q)->flags, v)

/**
 * struct idpf_vec_regs
 * @dyn_ctl_reg: Dynamic control interrupt register offset
 * @itrn_reg: Interrupt Throttling Rate register offset
 * @itrn_index_spacing: Register spacing between ITR registers of the same
 *			vector
 */
struct idpf_vec_regs {
	u32 dyn_ctl_reg;
	u32 itrn_reg;
	u32 itrn_index_spacing;
};

/**
 * struct idpf_intr_reg
 * @dyn_ctl: Dynamic control interrupt register
 * @rx_itr: RX ITR register
 * @tx_itr: TX ITR register
 * @icr_ena: Interrupt cause register offset
 * @icr_ena_ctlq_m: Mask for ICR
 * @dyn_ctl_intena_msk_m: Mask to disable interrupt enable settings. When set,
 *			  interrupt enable settings doesn't have any impact.
 * @dyn_ctl_wb_on_itr_m: When set, the associated vector is processed without
 *			 triggering an interrupt
 * @dyn_ctl_itridx_m: Mask for ITR index
 * @dyn_ctl_itridx_s: Register bit offset for ITR index
 * @dyn_ctl_intena_m: Mask for dyn_ctl interrupt enable
 */
struct idpf_intr_reg {
	void __iomem *dyn_ctl;
	void __iomem *rx_itr;
	void __iomem *tx_itr;
	void __iomem *icr_ena;
	u32 icr_ena_ctlq_m;
	u32 dyn_ctl_intena_msk_m;
	u32 dyn_ctl_wb_on_itr_m;
	u32 dyn_ctl_sw_itridx_ena_m;
	u8 dyn_ctl_swint_trig_m:3;
	u8 dyn_ctl_itridx_m:5;
	u8 dyn_ctl_intrvl_s:3;
	u8 dyn_ctl_itridx_s:2;
	u8 dyn_ctl_intena_m:1;
};

/**
 * struct idpf_q_vector
 * @vport: Vport back pointer
 * @napi: napi handler
 * @v_idx: Vector index
 * @intr_reg: See struct idpf_intr_reg
 * @wb_on_itr: Write back on ITR
 * @num_txq: Number of TX queues
 * @tx: Array of TX queues to service
 * @tx_dim: Data for TX net_dim algorithm
 * @tx_itr_value: TX interrupt throttling rate
 * @tx_intr_mode: Dynamic ITR or not
 * @tx_itr_idx: TX ITR index
 * @num_rxq: Number of RX queues
 * @rx: Array of RX queues to service
 * @rx_dim: Data for RX net_dim algorithm
 * @rx_itr_value: RX interrupt throttling rate
 * @rx_intr_mode: Dynamic ITR or not
 * @rx_itr_idx: RX ITR index
 * @num_bufq: Number of buffer queues
 * @bufq: Array of buffer queues to service
 * @total_events: Number of interrupts processed
 * @name: Queue vector name
 */
struct idpf_q_vector {
	struct idpf_vport *vport;
	struct napi_struct napi;
	u16 v_idx;
	struct idpf_intr_reg intr_reg;
	bool wb_on_itr;
	u16 num_txq;
	struct idpf_queue **tx;
	struct dim tx_dim;
	u32 tx_itr_value;
	bool tx_intr_mode;
	u32 tx_itr_idx;
	u16 num_rxq;
	struct idpf_queue **rx;
	struct dim rx_dim;
	u32 rx_itr_value;
	bool rx_intr_mode;
	u32 rx_itr_idx;
	u16 num_bufq;
	struct idpf_queue **bufq;
	u16 total_events;
	char *name;
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	u64 sharedrxq_clean_incomplete;
	u64 complq_clean_incomplete;
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
};

/* Maximum number of segments supported by RSC and TSO */
#define IDPF_MAX_SEGS 16

struct idpf_rx_queue_stats {
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t rsc_pkts;
	u64_stats_t hw_csum_err;
	u64_stats_t hsplit_pkts;
	u64_stats_t hsplit_buf_ovf;
	u64_stats_t bad_descs;
	u64_stats_t page_recycles;
	u64_stats_t page_reallocs;
	u64_stats_t rsc_bytes;
	u64_stats_t rsc_segs_tot;
	u64_stats_t segs[IDPF_MAX_SEGS];
};

struct idpf_tx_queue_stats {
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t lso_pkts;
	u64_stats_t linearize;
	u64_stats_t q_busy;
	u64_stats_t skb_drops;
	u64_stats_t dma_map_errs;
#ifdef CONFIG_TX_TIMEOUT_VERBOSE
	u64_stats_t busy_q_restarts;
	u64_stats_t busy_low_txq_descs;
	u64_stats_t busy_too_many_pend_compl;
	u64_stats_t complq_clean_incomplete;
	u64_stats_t sharedrxq_clean_incomplete;
#endif /* CONFIG_TX_TIMEOUT_VERBOSE */
	u64_stats_t lso_bytes;
	u64_stats_t lso_segs_tot;
	u64_stats_t segs[IDPF_MAX_SEGS];
};

union idpf_queue_stats {
	struct idpf_rx_queue_stats rx;
	struct idpf_tx_queue_stats tx;
};

#define IDPF_ITR_DYNAMIC	1
#define IDPF_ITR_MAX		0x1FE0
#define IDPF_ITR_20K		0x0032
#define IDPF_ITR_GRAN_S		1	/* Assume ITR granularity is 2us */
#define IDPF_ITR_MASK		0x1FFE	/* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & IDPF_ITR_MASK)
#define IDPF_ITR_IS_DYNAMIC(itr_mode) (itr_mode)
#define IDPF_ITR_TX_DEF		IDPF_ITR_20K
#define IDPF_ITR_RX_DEF		IDPF_ITR_20K
/* Index used for 'No ITR' update in DYN_CTL register */
#define IDPF_SW_ITR_UPDATE_IDX	2
#define IDPF_NO_ITR_UPDATE_IDX	3
#define IDPF_ITR_IDX_SPACING(spacing, dflt)	(spacing ? spacing : dflt)
#define IDPF_DIM_DEFAULT_PROFILE_IX		1

/**
 * struct idpf_sw_queue
 * @ring: Pointer to the ring
 * @flags: See enum idpf_queue_flags_t
 * @desc_count: Descriptor count
 * @next_to_use: Buffer to allocate at
 * @next_to_clean: Next descriptor to clean
 *
 * Software queues are used in splitq mode to manage buffers between rxq
 * producer and the bufq consumer. These are required in order to maintain a
 * lockless buffer management system and are strictly software only constructs.
 */
struct idpf_sw_queue {
	u32 *ring;

	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS);
	u32 desc_count;

	u32 next_to_use;
	u32 next_to_clean;
} ____cacheline_internodealigned_in_smp;

/**
 * struct idpf_queue
 * @dev: Device back pointer for DMA mapping
 * @vport: Back pointer to associated vport
 * @netdev: &net_device corresponding to this queue
 * @tx: Structure with TX descriptor and TX completion queue related members
 * @tx.refillq: Pointer to refill queue
 * @tx.bufs: See struct idpf_tx_buf
 * @tx.num_completions: Only relevant for TX completion queue. It tracks the
 *			number of completions received to compare against the
 *			number of completions pending, as accumulated by the
 *			TX queues.
 * @tx.rel_qid: Relative completion queue id
 * @tx.num_txq: Number of TX queues mapped to the completion queue
 * @rx: Structure with RX completion and RX buffer queue related members
 * @rx.bufs: Array of buffers. Used in both splitq and singleq model and
 *	     relevant only for buffer queues in splitq model.
 * @rx.hdr_buf_pa: DMA handle, relevant only for buffer queues
 * @rx.hdr_buf_va: Virtual address, relevant only for buffer queues
 * @rx.bufq_bufs: Array of buffer queue buffers mapped to the RX queue
 * @rx.bufq_hdr_bufs: Array of buffer queue header buffers mapped to the RX
 *		      queue
 * @rx.skb: Used only in splitq model for the RX clean routine to store the skb
 *	    pointer of the partially processed packet because of the napi budget
 * @rx.refillqs: Array of refill queues
 * @rx.num_refillq: Number of refill queues associated with the each RX/bufferq
 * @rx.rxq_idx: Index of the RX queue mapped to the buffer queue
 * @rx.vlan_proto: VLAN protocol to be passed in the skb
 * @cached_phc_time: Pointer to the cached PHC time for Tx/Rx timestamp
 *		     extension
 * @tstamp_task: Work that handles TX timestamp read
 * @cached_tstamp_caps: TX timestamp capabilities negotiated with the CP
 * @tstmp_en: Indicates whether the timestamping is enabled for the queue
 * @idx: For buffer queue, it is used as group id, either 0 or 1. On clean,
 *	 buffer queue uses this index to determine which group of refill queues
 *	 to clean.
 *	 For TX queue, it is used as index to map between TX queue group and
 *	 hot path TX pointers stored in vport. Used in both singleq/splitq.
 *	 For RX queue, it is used to index to total RX queue across groups and
 *	 used for skb reporting.
 * @tail: Tail offset. Used for both queue models single and split. In splitq
 *	  model relevant only for TX queue and RX queue.
 * @q_type: Queue type (TX, RX, TX completion, RX buffer)
 * @q_id: Queue id
 * @desc_count: Number of descriptors
 * @next_to_use: Next descriptor to use. Relevant in both split & single txq
 *		 and bufq.
 * @next_to_clean: Next descriptor to clean. In split queue model, only
 *		   relevant to TX completion queue and RX queue.
 * @next_to_alloc: RX buffer to allocate at. Used only for RX. In splitq model
 *		   only relevant to RX queue.
 * @flags: See enum idpf_queue_flags_t
 * @q_stats: See union idpf_queue_stats
 * @stats_sync: See struct u64_stats_sync
 * @cleaned_bytes: Splitq only, TXQ only: When a TX completion is received on
 *		   the TX completion queue, it can be for any TXQ associated
 *		   with that completion queue. This means we can clean up to
 *		   N TXQs during a single call to clean the completion queue.
 *		   cleaned_bytes|pkts tracks the clean stats per TXQ during
 *		   that single call to clean the completion queue. By doing so,
 *		   we can update BQL with aggregate cleaned stats for each TXQ
 *		   only once at the end of the cleaning routine.
 * @cleaned_pkts: Number of packets cleaned for the above said case
 * @rx_hsplit_en: RX headsplit enable
 * @rx_hbuf_size: Header buffer size
 * @rx_buf_size: Buffer size
 * @rx_max_pkt_size: RX max packet size
 * @rx_buf_stride: RX buffer stride
 * @rx_buffer_low_watermark: RX buffer low watermark
 * @rxdids: Supported RX descriptor ids
 * @q_vector: Backreference to associated vector
 * @size: Length of descriptor ring in bytes
 * @dma: Physical address of ring
 * @desc_ring: Descriptor ring memory
 * @buf_pool_size: Total number of idpf_tx_buf
 * @xdp_prog: BPF program. Used only for RX completion queue
#ifdef HAVE_XDP_BUFF_RXQ
 * @xdp_rxq: XDP RX queue. Used for XDP memory model setting
#endif
#ifdef HAVE_NETDEV_BPF_XSK_POOL
 * @xsk_pool: XSK pool
 * @xdp_tx_active: XDP TX queue active
 * @xdp_next_rs_idx: Used to track the next descriptor which has RS bit set.
 *		     This is a performance optimization for single queue mode
 *		     to reduce the number of descriptor writebacks with XDP
 *		     transmits.
#endif
 * @tx_max_bufs: Max buffers that can be transmitted with scatter-gather
 * @crc_enable: Enable CRC insertion offload
 * @tx_min_pkt_len: Min supported packet length
 */
struct idpf_queue {
	struct device *dev;
	struct idpf_vport *vport;
	struct net_device *netdev;
	union {
		struct idpf_txq_group *txq_grp;
		struct idpf_rxq_group *rxq_grp;
	};
	union {
		struct {
			struct idpf_tx_buf *bufs;
			struct idpf_sw_queue *refillq;
			u32 num_completions;
			u32 rel_qid;
			u16 num_txq;
			u16 last_re;
			u8 cmpl_tstamp_ns_s;
		} tx;
		struct {
			union {
				struct {
					struct idpf_rx_buf *bufs;
					dma_addr_t hdr_buf_pa;
					void *hdr_buf_va;
				};
				struct {
					struct idpf_rx_buf **bufq_bufs;
					u64 **bufq_hdr_bufs;
					struct sk_buff *skb;
				};
			};
			struct idpf_sw_queue *refillqs;
			int num_refillq;
			u16 rxq_idx;
			__be16 vlan_proto;
		} rx;
	};

	u64 *cached_phc_time;
	struct work_struct *tstamp_task;
	struct idpf_ptp_vport_tx_tstamp_caps *cached_tstamp_caps;
	bool tstmp_en;
	u16 idx;
	u8 gen_rxcsum_status;
	void __iomem *tail;
	u16 q_type;
	u32 q_id;
	u16 desc_count;
	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_alloc;
	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS);

	union idpf_queue_stats q_stats;
	struct u64_stats_sync stats_sync;

	u32 cleaned_bytes;
	u16 cleaned_pkts;
	bool rx_hsplit_en;
	u16 rx_hbuf_size;
	u16 rx_buf_size;
	u16 rx_max_pkt_size;
	u16 rx_buf_stride;
	u8 rx_buffer_low_watermark;
	u64 rxdids;
	struct idpf_q_vector *q_vector;
	unsigned int size;
	dma_addr_t dma;
	void *desc_ring;
	u32 buf_pool_size;

	struct bpf_prog *xdp_prog;
#ifdef HAVE_XDP_BUFF_RXQ
	struct xdp_rxq_info xdp_rxq;
#endif /* HAVE_XDP_BUFF_RXQ */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *xsk_pool;
	u16 xdp_tx_active;
	u16 xdp_next_rs_idx;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	u16 tx_max_bufs;
	bool crc_enable;
	u8 tx_min_pkt_len;

	struct xarray reinject_timers;
} ____cacheline_internodealigned_in_smp;

/**
 * struct idpf_rxq_set
 * @rxq: RX queue
 * @refillq: pointers to refill queues
 *
 * Splitq only.  idpf_rxq_set associates an rxq with at an array of refillqs.
 * Each rxq needs a refillq to return used buffers back to the respective bufq.
 * Bufqs then clean these refillqs for buffers to give to hardware.
 */
struct idpf_rxq_set {
	struct idpf_queue rxq;
	struct idpf_sw_queue *refillq[IDPF_MAX_BUFQS_PER_RXQ_GRP];
};

/**
 * struct idpf_bufq_set
 * @bufq: Buffer queue
 * @num_refillqs: Number of refill queues. This is always equal to num_rxq_sets
 *               in idpf_rxq_group.
 * @refillqs: Pointer to refill queues array.
 *
 * Splitq only. idpf_bufq_set associates a bufq to an array of refillqs.
 * In this bufq_set, there will be one refillq for each rxq in this rxq_group.
 * Used buffers received by rxqs will be put on refillqs which bufqs will
 * clean to return new buffers back to hardware.
 *
 * Buffers needed by some number of rxqs associated in this rxq_group are
 * managed by at most two bufqs (depending on performance configuration).
 */
struct idpf_bufq_set {
	struct idpf_queue bufq;
	int num_refillqs;
	struct idpf_sw_queue *refillqs;
};

/**
 * struct idpf_rxq_group
 * @vport: Vport back pointer
 * @singleq: Struct with single queue related members
 * @singleq.num_rxq: Number of RX queues associated
 * @singleq.rxqs: Array of RX queue pointers
 * @splitq: Struct with split queue related members
 * @splitq.num_rxq_sets: Number of RX queue sets
 * @splitq.rxq_sets: Array of RX queue sets
 * @splitq.bufq_sets: Buffer queue set pointer
 *
 * In singleq mode, an rxq_group is simply an array of rxqs.  In splitq, a
 * rxq_group contains all the rxqs, bufqs and refillqs needed to
 * manage buffers in splitq mode.
 */
struct idpf_rxq_group {
	struct idpf_vport *vport;

	union {
		struct {
			u16 num_rxq;
			struct idpf_queue *rxqs[IDPF_LARGE_MAX_Q];
		} singleq;
		struct {
			u16 num_rxq_sets;
			struct idpf_rxq_set *rxq_sets[IDPF_LARGE_MAX_Q];
			struct idpf_bufq_set *bufq_sets;
		} splitq;
	};
};

/**
 * struct idpf_txq_group
 * @vport: Vport back pointer
 * @num_txq: Number of TX queues associated
 * @txqs: Array of TX queue pointers
 * @complq: Associated completion queue pointer, split queue only
 * @num_completions_pending: Total number of completions pending for the
 *			     completion queue, acculumated for all TX queues
 *			     associated with that completion queue.
 *
 * Between singleq and splitq, a txq_group is largely the same except for the
 * complq. In splitq a single complq is responsible for handling completions
 * for some number of txqs associated in this txq_group.
 */
struct idpf_txq_group {
	struct idpf_vport *vport;

	u16 num_txq;
	struct idpf_queue **txqs;

	struct idpf_queue *complq;
	u32 num_completions_pending __aligned(L1_CACHE_BYTES);
};

/**
 * idpf_rx_bump_ntc - Bump and wrap q->next_to_clean value
 * @rxq: queue to bump
 * @ntc: current next_to_clean
 *
 * Returns updated next_to_clean
 */
static inline u16 idpf_rx_bump_ntc(struct idpf_queue *rxq, u16 ntc)
{
	if (unlikely(++ntc == rxq->desc_count)) {
		ntc = 0;
		change_bit(__IDPF_Q_GEN_CHK, (rxq)->flags);
	}

	return ntc;
}

/**
 * idpf_singleq_bump_desc_idx - Bump and wrap queue descriptor index
 * @q: queue to bump
 * @idx: current descriptor index
 *
 * Returns updated next_to_clean or next_to_use
 */
static inline u16 idpf_singleq_bump_desc_idx(struct idpf_queue *q, u16 idx)
{
	if (unlikely(++idx == q->desc_count))
		idx = 0;

	return idx;
}

/**
 * idpf_rx_singleq_test_staterr - tests bits in Rx descriptor
 * status and error fields
 * @rx_desc: pointer to receive descriptor (in le64 format)
 * @stat_err_bits: value to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_ptype_len doesn't need to be shifted because it begins
 * at offset zero.
 */
static inline bool
idpf_rx_singleq_test_staterr(const union virtchnl2_rx_desc *rx_desc,
			     const u64 stat_err_bits)
{
	return !!(rx_desc->base_wb.qword1.status_error_ptype_len &
		  cpu_to_le64(stat_err_bits));
}

/**
 * idpf_size_to_txd_count - Get number of descriptors needed for large TX frag
 * @size: transmit request size in bytes
 *
 * In the case where a large frag (>= 16K) needs to be split across multiple
 * descriptors, we need to assume that we can have no more than 12K of data
 * per descriptor due to hardware alignment restrictions (4K alignment).
 */
static inline u32 idpf_size_to_txd_count(unsigned int size)
{
	return DIV_ROUND_UP(size, IDPF_TX_MAX_DESC_DATA_ALIGNED);
}

/**
 * idpf_tx_singleq_build_ctob - populate command tag offset and size
 * @td_cmd: Command to be filled in desc
 * @td_offset: Offset to be filled in desc
 * @size: Size of the buffer
 * @td_tag: td tag to be filled
 *
 * Returns the 64 bit value populated with the input parameters
 */
static inline __le64 idpf_tx_singleq_build_ctob(u64 td_cmd, u64 td_offset,
						unsigned int size, u64 td_tag)
{
	return cpu_to_le64(IDPF_TX_DESC_DTYPE_DATA |
			   (td_cmd << IDPF_TXD_QW1_CMD_S) |
			   (td_offset << IDPF_TXD_QW1_OFFSET_S) |
			   ((u64)size << IDPF_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag << IDPF_TXD_QW1_L2TAG1_S));
}

/**
 * idpf_tx_get_free_buf_id - get a free buffer ID from the refill queue
 * @refillq: refill queue to get buffer ID from
 * @buf_id: return buffer ID
 *
 * Return: true if a buffer ID was found, false if not
 */
static inline bool idpf_tx_get_free_buf_id(struct idpf_sw_queue *refillq,
					   u32 *buf_id)
{
	u32 ntc = refillq->next_to_clean;
	u32 refill_desc;

	refill_desc = refillq->ring[ntc];

	if (unlikely(idpf_queue_has(RFL_GEN_CHK, refillq) !=
		     !!(refill_desc & IDPF_RFL_BI_GEN_M)))
		return false;

	*buf_id = FIELD_GET(IDPF_RFL_BI_BUFID_M, refill_desc);

	if (unlikely(++ntc == refillq->desc_count)) {
		idpf_queue_change(RFL_GEN_CHK, refillq);
		ntc = 0;
	}

	refillq->next_to_clean = ntc;

	return true;
}

void idpf_tx_splitq_build_ctb(union idpf_tx_flex_desc *desc,
			      struct idpf_tx_splitq_params *params,
			      u16 td_cmd, u16 size);
void idpf_tx_splitq_build_flow_desc(union idpf_tx_flex_desc *desc,
				    struct idpf_tx_splitq_params *params,
				    u16 td_cmd, u16 size);
/**
 * idpf_tx_splitq_build_desc - determine which type of data descriptor to build
 * @desc: descriptor to populate
 * @params: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
static inline void
idpf_tx_splitq_build_desc(union idpf_tx_flex_desc *desc,
			  struct idpf_tx_splitq_params *params,
			  u16 td_cmd, u16 size)
{
	if (params->dtype == IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2)
		idpf_tx_splitq_build_ctb(desc, params, td_cmd, size);
	else
		idpf_tx_splitq_build_flow_desc(desc, params, td_cmd, size);
}

/**
 * idpf_tx_splitq_get_free_bufs - get number of free buf_ids in refillq
 * @refillq: pointer to refillq containing buf_ids
 */
static inline u32 idpf_tx_splitq_get_free_bufs(struct idpf_sw_queue *refillq)
{
	return (refillq->next_to_use > refillq->next_to_clean ?
		0 : refillq->desc_count) +
	       refillq->next_to_use - refillq->next_to_clean - 1;
}

int idpf_vport_singleq_napi_poll(struct napi_struct *napi, int budget);
void idpf_vport_init_num_qs(struct idpf_vport *vport,
			    struct virtchnl2_create_vport *vport_msg,
			    struct idpf_q_grp *q_grp);
void idpf_vport_calc_num_q_desc(struct idpf_vport *vport,
				struct idpf_q_grp *q_grp);
void idpf_vport_calc_total_qs(struct idpf_adapter *adapter, u16 vport_index,
			      struct virtchnl2_create_vport *vport_msg,
			      struct idpf_vport_max_q *max_q);
void idpf_vport_calc_num_q_groups(struct idpf_q_grp *q_grp);
int idpf_vport_queue_alloc_all(struct idpf_vport *vport,
			       struct idpf_q_grp *q_grp);
void idpf_vport_queues_rel(struct idpf_vport *vport,
			   struct idpf_q_grp *q_grp);
void idpf_post_buf_refill(struct idpf_sw_queue *refillq, u16 buf_id);
int idpf_rx_bufs_init_all(struct idpf_q_grp *q_grp);
void idpf_vport_intr_rel(struct idpf_vgrp *vgrp);
int idpf_vport_intr_alloc(struct idpf_vport *vport, struct idpf_vgrp *vgrp);
void idpf_vport_intr_update_itr_ena_irq(struct idpf_q_vector *q_vector);
void idpf_vport_intr_deinit(struct idpf_vport *vport,
			    struct idpf_intr_grp *intr_grp);
int idpf_vport_intr_init(struct idpf_vport *vport, struct idpf_vgrp *vgrp);
void idpf_vport_intr_ena(struct idpf_vport *vport, struct idpf_vgrp *vgrp);
void idpf_vport_intr_set_wb_on_itr(struct idpf_q_vector *q_vector);
enum
pkt_hash_types idpf_ptype_to_htype(const struct idpf_rx_ptype_decoded *decoded);
int idpf_config_rss(struct idpf_vport *vport, struct idpf_rss_data *rss_data);
int idpf_init_rss(struct idpf_vport *vport, struct idpf_rss_data *rss_data,
		  struct idpf_q_grp *q_grp);
void idpf_deinit_rss(struct idpf_rss_data *rss_data);
bool idpf_rx_can_reuse_page(struct idpf_rx_buf *rx_buf);
#ifdef HAVE_XDP_SUPPORT
void idpf_rx_buf_adjust_pg(struct idpf_rx_buf *rx_buf, unsigned int size);
#endif /* CONFIG_XDP */
void idpf_rx_get_buf_page(struct device *dev, struct idpf_rx_buf *rx_buf,
			  const unsigned int size);
void idpf_rx_add_frag(struct idpf_rx_buf *rx_buf, struct sk_buff *skb,
		      unsigned int size);
struct sk_buff *idpf_rx_construct_skb(struct idpf_queue *rxq,
				      struct idpf_rx_buf *rx_buf,
				      unsigned int size);
int idpf_alloc_page(struct device *dev, struct idpf_page_info *page_info);
void idpf_rx_buf_hw_update(struct idpf_queue *rxq, u32 val);
void idpf_tx_buf_hw_update(struct idpf_queue *tx_q, u32 val,
			   bool xmit_more);
int idpf_rx_process_skb_fields(struct idpf_queue *rxq, struct sk_buff *skb,
			       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc);
void idpf_rx_singleq_process_skb_fields(struct idpf_queue *rx_q, struct sk_buff *skb,
					union virtchnl2_rx_desc *rx_desc, u16 ptype);
void idpf_rx_singleq_extract_fields(struct idpf_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct idpf_rx_extracted *fields);
bool idpf_rx_singleq_is_non_eop(struct idpf_queue *rxq,
				union virtchnl2_rx_desc *rx_desc,
				struct sk_buff *skb);
#ifdef HAVE_XDP_FRAME_STRUCT
int idpf_xmit_xdpq(struct xdp_frame *xdp, struct idpf_queue *xdpq);
#else
int idpf_xmit_xdpq(struct xdp_buff *xdp, struct idpf_queue *xdpq);
#endif /* HAVE_XDP_FRAME_STRUCT */
u32 idpf_size_to_txd_count(unsigned int size);
netdev_tx_t idpf_tx_drop_skb(struct idpf_queue *tx_q, struct sk_buff *skb);
unsigned int idpf_tx_res_count_required(struct idpf_queue *txq,
					struct sk_buff *skb, u32 *buf_count);
#ifdef HAVE_TX_TIMEOUT_TXQUEUE
void idpf_tx_timeout(struct net_device *netdev, unsigned int txqueue);
#else
void idpf_tx_timeout(struct net_device *netdev);
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
netdev_tx_t idpf_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev);
netdev_tx_t idpf_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev);
#ifdef IDPF_ADD_PROBES
void idpf_tx_extra_counters(struct idpf_queue *txq, struct idpf_tx_buf *skb,
			    struct idpf_tx_offload_params *off);
void idpf_rx_extra_counters(struct idpf_queue *rxq, u32 inner_prot,
			    bool ipv4, struct idpf_rx_csum_decoded *csum_bits,
			    bool splitq);
#endif /* IDPF_ADD_PROBES */
bool idpf_rx_singleq_buf_hw_alloc_all(struct idpf_queue *rxq,
				      u16 cleaned_count);
#ifdef HAVE_XDP_SUPPORT
int idpf_rx_xdp(struct idpf_queue *rxq, struct idpf_queue *xdpq,
		struct idpf_rx_buf *rx_buf, unsigned int size);
INDIRECT_CALLABLE_DECLARE(void idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq,
							       dma_addr_t dma, u16 idx,
							       u32 size,
							       struct idpf_tx_splitq_params *params));
void idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				     u16 idx, u32 size,
				     struct idpf_tx_splitq_params *params);

INDIRECT_CALLABLE_DECLARE(void idpf_prepare_xdp_tx_singleq_desc(struct idpf_queue *xdpq,
								dma_addr_t dma, u16 idx,
								u32 size,
								struct idpf_tx_splitq_params *params));
void idpf_prepare_xdp_tx_singleq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				      u16 idx, u32 size,
				      struct idpf_tx_splitq_params *params);
int idpf_xdp_rxq_init(struct idpf_queue *q);
#endif /* HAVE_XDP_SUPPORT */
int idpf_tso(struct sk_buff *skb, struct idpf_tx_offload_params *off);

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_xdpq_update_tail - Updates the XDP Tx queue tail register
 * @xdpq: XDP Tx queue
 *
 * This function updates the XDP Tx queue tail register.
 */
static inline void idpf_xdpq_update_tail(struct idpf_queue *xdpq)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdpq->next_to_use, xdpq->tail);
}

/**
 * idpf_finalize_xdp_rx - Bump XDP Tx tail and/or flush redirect map
 * @xdpq: XDP Tx queue
 * @xdp_res: Result of the receive batch
 *
 * This function bumps XDP Tx tail and/or flush redirect map, and
 * should be called when a batch of packets has been processed in the
 * napi loop.
 */
static inline void idpf_finalize_xdp_rx(struct idpf_queue *xdpq, unsigned int xdp_res)
{
	if (xdp_res & IDPF_XDP_REDIR)
		xdp_do_flush();

	if (xdp_res & IDPF_XDP_TX)
		idpf_xdpq_update_tail(xdpq);
}
#endif /* HAVE_XDP_SUPPORT */
#endif /* !_IDPF_TXRX_H_ */
