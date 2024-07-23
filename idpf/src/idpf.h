/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#ifndef _IDPF_H_
#define _IDPF_H_

/* Forward declaration */
struct idpf_adapter;
struct idpf_vport;
struct idpf_vport_max_q;
struct idpf_vgrp;
struct idpf_q_grp;
struct idpf_intr_grp;
struct idpf_rss_data;

/* Because of the header files order dependency in OOT, include kcompat.h first.
 * This applies to all other files which include kcompat.h
 */
#include "kcompat.h"
#include <net/pkt_sched.h>
#ifdef __TC_MQPRIO_MODE_MAX
#include <net/pkt_cls.h>
#endif /* __TC_MQPRIO_MODE_MAX */
#include <linux/bitfield.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/sctp.h>
#include <linux/uio.h>
#include <net/ip6_checksum.h>
#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GRE_ENCAP_OFFLOAD
#include <net/gre.h>
#endif /* HAVE_GRE_ENCAP_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#include <net/udp_tunnel.h>
#endif
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
#include <linux/iommu.h>
#include <linux/platform_device.h>
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */

#define IDPF_DRV_NAME "idpf"
#define IDPF_DRV_VER "0.0.756"

#define IDPF_M(m, s)	((m) << (s))

#include "iidc.h"
#include <linux/idr.h>
#include "virtchnl2.h"
#include "idpf_txrx.h"
#include "idpf_controlq.h"
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#include "idpf_xsk.h"
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#ifdef DEVLINK_ENABLED
#include "idpf_devlink.h"
#endif /* DEVLINK_ENABLED */
#include "idpf_ptp.h"
#include "idpf_adi.h"

#define GETMAXVAL(num_bits)		GENMASK((num_bits) - 1, 0)

#define IDPF_NO_FREE_SLOT		0xffff

/* Default Mailbox settings */
#define IDPF_CTLQ_MAX_BUF_LEN		SZ_4K
#define IDPF_NUM_FILTERS_PER_MSG	20
#define IDPF_NUM_DFLT_MBX_Q             2       /* One TX and RX MBX queue */
#define IDPF_DFLT_MBX_Q_LEN		64
#define IDPF_DFLT_MBX_ID		-1
/* maximum number of times to try before resetting mailbox */
#define IDPF_MB_MAX_ERR			20
#define IDPF_NUM_CHUNKS_PER_MSG(struct_sz, chunk_sz)   \
	((IDPF_CTLQ_MAX_BUF_LEN - (struct_sz)) / (chunk_sz))

#define IDPF_VC_XN_MIN_TIMEOUT_MSEC	6000
#define IDPF_VC_XN_DEFAULT_TIMEOUT_MSEC	(60 * 1000)
#define IDPF_VC_XN_IDX_M		GENMASK(7, 0)
#define IDPF_VC_XN_SALT_M		GENMASK(15, 8)

#define IDPF_HARD_RESET_TIMEOUT_MSEC	(120 * 1000)
#define IDPF_CORER_TIMEOUT_MSEC		(120 * 1000)
#define IDPF_RESET_POLL_COUNT		(2 * 1000)

/* available message levels */
#define IDPF_AVAIL_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define IDPF_RSTAT_COMPLETE		0x01

#define IDPF_DIM_PROFILE_SLOTS	5

#define IDPF_VIRTCHNL_VERSION_MAJOR VIRTCHNL2_VERSION_MAJOR_2
#define IDPF_VIRTCHNL_VERSION_MINOR VIRTCHNL2_VERSION_MINOR_0

#define IDPF_P2P_NUM_OF_VGRPS		2
#define IDPF_P2P_TXQ_PER_VGRP		1
#define IDPF_P2P_RXQ_PER_VGRP		1
#define IDPF_P2P_COMPLQ_PER_VGRP	1
#define IDPF_P2P_BUFQ_PER_VGRP		1
#define IDPF_P2P_QGRP_INFO_OFFSET	(sizeof(struct virtchnl2_add_queue_groups))

/**
 * struct idpf_mac_filter
 * @list: list member field
 * @macaddr: MAC address
 * @remove: filter should be removed (virtchnl)
 * @add: filter should be added (virtchnl)
 */
struct idpf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	bool remove;
	bool add;
};

struct idpf_rdma_data {
	struct iidc_core_dev_info *cdev_info;
	int aux_idx;
	u16 num_vecs;
};

/**
 * enum idpf_state - State machine to handle bring up
 * @__IDPF_VER_CHECK: Negotiate virtchnl version
 * @__IDPF_GET_CAPS: Negotiate capabilities
 * @__IDPF_INIT_SW: Init based on given capabilities
 * @__IDPF_STATE_LAST: Must be last, used to determine size
 */
enum idpf_state {
	__IDPF_VER_CHECK,
	__IDPF_GET_CAPS,
	__IDPF_INIT_SW,
	__IDPF_STATE_LAST,
};

/**
 * enum idpf_flags - Hard reset causes.
 * @IDPF_HR_FUNC_RESET: Hard reset when TxRx timeout
 * @IDPF_HR_DRV_LOAD: Set on driver load for a clean HW
 * @IDPF_HR_RESET_IN_PROG: Reset in progress
 * @IDPF_REMOVE_IN_PROG: Driver remove in progress
 * @IDPF_MB_INTR_MODE: Mailbox in interrupt mode
 * @IDPF_CORER_IN_PROG: CORER is in progress
 * @IDPF_FLAGS_NBITS: Must be last
 */
enum idpf_flags {
	IDPF_HR_FUNC_RESET,
	IDPF_HR_DRV_LOAD,
	IDPF_HR_RESET_IN_PROG,
	IDPF_REMOVE_IN_PROG,
	IDPF_MB_INTR_MODE,
	IDPF_CORER_IN_PROG,
	IDPF_FLAGS_NBITS,
};

/**
 * enum idpf_cap_field - Offsets into capabilities struct for specific caps
 * @IDPF_BASE_CAPS: generic base capabilities
 * @IDPF_CSUM_CAPS: checksum offload capabilities
 * @IDPF_SEG_CAPS: segmentation offload capabilities
 * @IDPF_RSS_CAPS: RSS offload capabilities
 * @IDPF_HSPLIT_CAPS: Header split capabilities
 * @IDPF_RSC_CAPS: RSC offload capabilities
 * @IDPF_OTHER_CAPS: miscellaneous offloads
 *
 * Used when checking for a specific capability flag since different capability
 * sets are not mutually exclusive numerically, the caller must specify which
 * type of capability they are checking for.
 */
enum idpf_cap_field {
	IDPF_BASE_CAPS		= -1,
	IDPF_CSUM_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   csum_caps),
	IDPF_SEG_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   seg_caps),
	IDPF_RSS_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rss_caps),
	IDPF_HSPLIT_CAPS	= offsetof(struct virtchnl2_get_capabilities,
					   hsplit_caps),
	IDPF_RSC_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rsc_caps),
	IDPF_OTHER_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   other_caps),
};

/**
 * struct idpf_netdev_priv - Struct to store vport back pointer
 * @adapter: Adapter back pointer
 * @vport: Vport back pointer
 * @vport_id: Vport identifier
 * @link_speed_mbps: Link speed in mbps
 * @vport_idx: Relative vport index
 * @active: vport is open or stopped
 * @stats_lock: Lock to protect stats update
 * @netstats: Packet and byte stats
 */
struct idpf_netdev_priv {
	struct idpf_adapter *adapter;
	struct idpf_vport *vport;
	u32 vport_id;
	u32 link_speed_mbps;
	u16 vport_idx;
	bool active;
	spinlock_t stats_lock;
	struct rtnl_link_stats64 netstats;
};

/**
 * struct idpf_reset_reg - Reset register offsets/masks
 * @rstat: Reset status register
 * @oicr_cause: OICR cause register
 * @rstat_m: Reset status mask
 * @oicr_cause_m: OICR cause mask
 */
struct idpf_reset_reg {
	void __iomem *rstat;
	void __iomem *oicr_cause;
	u32 rstat_m;
	u32 oicr_cause_m;
};

/**
 * struct idpf_vport_max_q - Queue limits
 * @max_rxq: Maximum number of RX queues supported
 * @max_txq: Maixmum number of TX queues supported
 * @max_bufq: In splitq, maximum number of buffer queues supported
 * @max_complq: In splitq, maximum number of completion queues supported
 */
struct idpf_vport_max_q {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/**
 * struct idpf_reg_ops - Device specific register operation function pointers
 * @ctlq_reg_init: Mailbox control queue register initialization
 * @intr_reg_init: Traffic interrupt register initialization
 * @mb_intr_reg_init: Mailbox interrupt register initialization
 * @reset_reg_init: Reset register initialization
 * @trigger_reset: Trigger a reset to occur
 * @read_master_time: Read master time
 * @ptp_reg_init: PTP register initialization
 */
struct idpf_reg_ops {
	void (*ctlq_reg_init)(struct idpf_hw *hw,
			      struct idpf_ctlq_create_info *cq);
	int (*intr_reg_init)(struct idpf_vport *vport,
			     struct idpf_intr_grp *intr_grp);
	void (*mb_intr_reg_init)(struct idpf_adapter *adapter);
	void (*reset_reg_init)(struct idpf_adapter *adapter);
	void (*trigger_reset)(struct idpf_adapter *adapter,
			      enum idpf_flags trig_cause);
	u64 (*read_master_time)(const struct idpf_hw *hw);
	void (*ptp_reg_init)(struct idpf_adapter *adapter);
};

/**
 * struct idpf_idc_ops - IDC specific function pointers
 * @idc_init: IDC initialization
 * @idc_deinit: IDC deinitialization
 */
struct idpf_idc_ops {
	int (*idc_init)(struct idpf_adapter *adapter);
	void (*idc_deinit)(struct idpf_adapter *adapter);
};

/**
 * struct idpf_dev_ops - Device specific operations
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
 * vdcm_init: VDCM initialization
 * vdcm_deinit: VDCM deinitialization
#endif
 * notify_adi_reset: Notify ADI reset
 * @reg_ops: Register operations
 * @idc_ops: IDC operations
 * bar0_region1_size: Non-cached BAR0 region 1 size
 * bar0_region2_start: Non-cached BAR0 region 2 start address
 */
struct idpf_dev_ops {
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	int (*vdcm_init)(struct pci_dev *pdev);
	void (*vdcm_deinit)(struct pci_dev *pdev);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	void (*notify_adi_reset)(struct idpf_adapter *adapter,
				 u16 adi_id, bool reset);
	struct idpf_reg_ops reg_ops;
	struct idpf_idc_ops idc_ops;
	resource_size_t bar0_region1_size;
	resource_size_t bar0_region2_start;
};

/**
 * enum idpf_vport_reset_cause - Vport soft reset causes
 * @IDPF_SR_Q_CHANGE: Soft reset queue change
 * @IDPF_SR_Q_DESC_CHANGE: Soft reset descriptor change
 * @IDPF_SR_Q_SCH_CHANGE: Scheduling mode change in queue context
 * @IDPF_SR_MTU_CHANGE: Soft reset MTU change
 * @IDPF_SR_RSC_CHANGE: Soft reset RSC change
 * @IDPF_SR_HSPLIT_CHANGE: Soft reset header split change
#ifdef HAVE_XDP_SUPPORT
 * @IDPF_SR_XDP_CHANGE: XDP soft reset
#endif
 * @IDPF_HR_WARN_RESET: Hard reset warning event to IDC
 */
enum idpf_vport_reset_cause {
	IDPF_SR_Q_CHANGE,
	IDPF_SR_Q_DESC_CHANGE,
	IDPF_SR_Q_SCH_CHANGE,
	IDPF_SR_MTU_CHANGE,
	IDPF_SR_RSC_CHANGE,
	IDPF_SR_HSPLIT_CHANGE,
#ifdef HAVE_XDP_SUPPORT
	IDPF_SR_XDP_CHANGE,
#endif /* HAVE_XDP_SUPPORT */
	IDPF_HR_WARN_RESET,
};

/**
 * enum idpf_vport_flags - vport flags
 * @IDPF_VPORT_DEL_QUEUES: To send delete queues message
 * @IDPF_VPORT_SW_MARKER: Indicate TX pipe drain software marker packets
 * 			  processing is done
 * @IDPF_VPORT_PORT2PORT_ENABLED: True if P2P feature is enabled
 * @IDPF_VPORT_PORT2PORT_OPENED: Indicates if P2P queues are configured and
 *				 enabled
 * @IDPF_VPORT_FLAGS_NBITS: Must be last
 */
enum idpf_vport_flags {
	IDPF_VPORT_DEL_QUEUES,
	IDPF_VPORT_SW_MARKER,
	IDPF_VPORT_PORT2PORT_ENABLED,
	IDPF_VPORT_PORT2PORT_OPENED,
	IDPF_VPORT_FLAGS_NBITS,
};

#ifdef IDPF_ADD_PROBES
struct idpf_extra_stats {
	u64_stats_t tx_tcp_segs;
	u64_stats_t tx_udp_segs;
	u64_stats_t tx_tcp_cso;
	u64_stats_t tx_udp_cso;
	u64_stats_t tx_sctp_cso;
	u64_stats_t tx_ip4_cso;
	u64_stats_t rx_tcp_cso;
	u64_stats_t rx_udp_cso;
	u64_stats_t rx_sctp_cso;
	u64_stats_t rx_ip4_cso;
	u64_stats_t rx_tcp_cso_err;
	u64_stats_t rx_udp_cso_err;
	u64_stats_t rx_sctp_cso_err;
	u64_stats_t rx_ip4_cso_err;
	u64_stats_t rx_csum_complete;
	u64_stats_t rx_csum_unnecessary;
};

#endif /* IDPF_ADD_PROBES */
struct idpf_port_stats {
	struct u64_stats_sync stats_sync;
	u64_stats_t rx_hw_csum_err;
	u64_stats_t rx_hsplit;
	u64_stats_t rx_hsplit_hbo;
	u64_stats_t rx_bad_descs;
	u64_stats_t tx_linearize;
	u64_stats_t tx_busy;
	u64_stats_t tx_drops;
	u64_stats_t tx_dma_map_errs;
	u64_stats_t tx_reinjection_timeouts;
	struct virtchnl2_vport_stats vport_stats;
	struct virtchnl2_phy_port_stats *phy_port_stats;
#ifdef IDPF_ADD_PROBES
	struct idpf_extra_stats extra_stats;
#endif /* IDPF_ADD_PROBES */
};

/**
 * enum idpf_vc_xn_state - Virtchnl transaction status
 * @IDPF_VC_XN_IDLE: not expecting a reply, ready to be used
 * @IDPF_VC_XN_WAITING: expecting a reply, not yet received
 * @IDPF_VC_XN_COMPLETED_SUCCESS: a reply was expected and received,
 *				  buffer updated
 * @IDPF_VC_XN_COMPLETED_FAILED: a reply was expected and received, but there
 *				 was an error, buffer not updated
 * @IDPF_VC_XN_SHUTDOWN: transaction object cannot be used, VC torn down
 * @IDPF_VC_XN_ASYNC: transaction sent asynchronously and doesn't have return
 *		      context, a callback may have been provide
 */
enum idpf_vc_xn_state {
	IDPF_VC_XN_IDLE = 1,
	IDPF_VC_XN_WAITING,
	IDPF_VC_XN_COMPLETED_SUCCESS,
	IDPF_VC_XN_COMPLETED_FAILED,
	IDPF_VC_XN_SHUTDOWN,
	IDPF_VC_XN_ASYNC,
};

struct idpf_vc_xn;
/* Callback for asynchronous messages */
typedef int (*async_vc_cb) (struct idpf_adapter *, struct idpf_vc_xn *,
			    const struct idpf_ctlq_msg *);

/**
 * struct idpf_vc_xn - Data structure representing virtchnl transactions
 * @vc_op: corresponding opcode sent with this transaction
 * @idx: index used as retrieval on reply receive, used for cookie
 * @salt: changed every message to make unique, used for cookie
 * @completed: virtchnl event loop uses that to signal when a reply is
 *	       available, uses kernel completion API
 * @state: virtchnl event loop stores the data below, protected by the
 *	   completion's lock.
 * @reply_sz: Original size of reply, may be > reply_buf.iov_len; it will be
 *	      truncated on its way to the receiver thread according to
 *	      reply_buf.iov_len.
 * @reply: Reference to the buffer(s) where the reply data should be written
 *	   to. May be 0-length (then NULL address permitted) if the reply data
 *	   should be ignored.
 * @free_list: list member field to insert into linked list
 * @async_handler: if sent asynchronously, a callback can be provided to handle
 *		   the reply when it's received
 */
struct idpf_vc_xn {
	u32 vc_op;
	u8 idx;
	u8 salt;
	struct completion completed;
	enum idpf_vc_xn_state state;
	size_t reply_sz;
	struct kvec reply;
	struct list_head free_list;
	async_vc_cb async_handler;
};

/**
 * struct idpf_vc_xn_params - Parameters for executing transaction
 * @vc_op: virtchnl op to send
 * @send_buf: kvec for send buffer
 * @recv_buf: kvec for recv buffer, may be NULL, must then have zero length
 * @timeout_ms: timeout to wait for reply
 * @async: send message asynchronously, will not wait on completion
 * @async_handler: if sent asynchronously, optional callback handler
 */
struct idpf_vc_xn_params {
	u32 vc_op;
	struct kvec send_buf;
	struct kvec recv_buf;
	int timeout_ms;
	bool async;
	async_vc_cb async_handler;
};

/**
 * struct idpf_vc_xn_manager - Manager for tracking transactions
 * @salt: used to make cookie unique every message
 * @xn_list_lock: used to protect integrity of list
 * @free_xns: list of free transactions
 * @ring: backing and lookup for transactions
 */
struct idpf_vc_xn_manager {
	/* has this been initialized */
	bool active;
	u8 salt;
	spinlock_t xn_list_lock;
	struct list_head free_xns;
	struct idpf_vc_xn ring[U8_MAX];
};

/**
 * struct idpf_q_grp - Queue resource group
 * @num_txq: Number of allocated TX queues
 * @num_complq: Number of allocated completion queues
 * @txq_desc_count: TX queue descriptor count
 * @complq_desc_count: Completion queue descriptor count
 * @txq_model: Split queue or single queue queuing model
 * @txqs: Array of TX queues
 * @complqs: Array of completion queues
 * @bufq_per_rxq: Number of buffer queues per RX queue
 * @num_bufq: Number of allocated buffer queues
 * @num_rxq: Number of allocated RX queues
 * @rxq_desc_count: RX queue descriptor count. *MUST* have enough descriptors
 *                  to complete all buffer descriptors for all buffer queues in
 *                  the worst case.
 * @bufq_desc_count: Buffer queue descriptor count
 * @bufq_size: Size of buffers in ring (e.g. 2K, 4K, etc)
 * @rxq_model: Splitq queue or single queue queuing model
 * @base_rxd: True if the driver should use base descriptors instead of flex
 * @rxqs: Array of RX queues
 * @bufqs: Array of buffer queues
 * @refillqs: Array of refill queues
 * @req_qs_chunks: Queue chunk data for requested queues
 * @type: Resource group type
 */
struct idpf_q_grp {
	u16 num_txq;
	u16 num_complq;
	u32 txq_desc_count;
	u32 complq_desc_count;
	u16 txq_model;
	struct idpf_queue **txqs;
	struct idpf_queue *complqs;
	u16 bufq_per_rxq;
	u16 num_bufq;
	u16 num_rxq;
	u32 rxq_desc_count;
	u32 bufq_desc_count[IDPF_MAX_BUFQS_PER_RXQ];
	u32 bufq_size[IDPF_MAX_BUFQS_PER_RXQ];
	u16 rxq_model;
	bool base_rxd;
	struct idpf_queue **rxqs;
	struct idpf_queue *bufqs;
	struct idpf_sw_queue *refillqs;
	struct virtchnl2_add_queue_groups *req_qs_chunks;
	enum idpf_grp_type type;
};

/**
 * struct idpf_intr_grp - Interrupt resource group
 * @num_q_vectors: Number of IRQ vectors allocated
 * @q_vectors: Array of queue vectors
 * @q_vector_idxs: Starting index of queue vectors
 * @type: Resource group type
 */
struct idpf_intr_grp {
	u16 num_q_vectors;
	struct idpf_q_vector *q_vectors;
	u16 *q_vector_idxs;
	enum idpf_grp_type type;
};

/**
 * struct idpf_vgrp - Handle for queue and vector resources
 * @q_grp: Queue resources
 * @intr_grp: Interrupt resources
 * @type: Resource group type
 */
struct idpf_vgrp {
	struct idpf_q_grp q_grp;
	struct idpf_intr_grp intr_grp;
	enum idpf_grp_type type;
};

/**
 * struct idpf_vport - Handle for netdevices and queue resources
 * @dflt_grp: Queue and interrupt resource group
 * @txqs: Array to store the copy of TX queues for the fast path access
 * @num_txq: Number of allocated TX queues for fast path access
 * @compln_clean_budget: Work budget for completion clean
 * @tw_ts_gran_s: TX timing wheel granularity
 * @tw_horizon: TX timing wheel horizon
 * @crc_enable: Enable CRC insertion offload
#ifdef HAVE_XDP_SUPPORT
 * @num_xdp_txq: Number of XDP TX queues
 * @num_xdp_rxq: Number of XDP RX queues
 * @num_xdp_complq: Number of XDP completion queues
 * @xdp_txq_offset: XDP TX queue offset
 * @xdp_rxq_offset: XDP RX queue offset
 * @xdp_complq_offset: XDP completion queue offset
#ifdef HAVE_NETDEV_BPF_XSK_POOL
 * @req_xsk_pool: Requested XSK pool
 * @xsk_enable_req: XSK enable request
#endif
 * @xdp_prepare_tx_desc: Prepare XDP TX descriptor
#endif
 * @rx_ptype_lkup: Lookup table for ptypes on RX
#ifdef IDPF_ADD_PROBES
 * @ptype_stats: Ptype statistics
#endif
 * @adapter: back pointer to associated adapter
 * @netdev: Associated net_device. Each vport should have one and only one
 *          associated netdev.
 * @flags: See enum idpf_vport_flags
 * @vport_type: Default SRIOV, SIOV, etc.
 * @vport_id: Device given vport identifier
 * @idx: Software index in adapter vports struct
 * @default_vport: Use this vport if one isn't specified
 * @max_mtu: device given max possible MTU
 * @default_mac_addr: device will give a default MAC to use
 * @rx_itr_profile: RX profiles for Dynamic Interrupt Moderation
 * @tx_itr_profile: TX profiles for Dynamic Interrupt Moderation
 * @port_stats: Per port csum, header split, and other offload stats
 * @link_up: True if link is up
 * @p2p_vgrps: P2P resource group
 * @sw_marker_wq: Workqueue for marker packets
 * @tstamp_config: The Tx tstamp config
 * @tx_tstamps_caps: The capabilities negotiated for Tx timestamping
 * @tstamp_task: Tx timestamping task
 * @tstamp_wq: Workqueue for Tx timestamping task
 */
struct idpf_vport {
	struct idpf_vgrp dflt_grp;
	struct idpf_queue **txqs;
	u16 num_txq;
	u32 compln_clean_budget;
	u16 tw_ts_gran_s;
	u64 tw_horizon;
	bool crc_enable;
#ifdef HAVE_XDP_SUPPORT
	int num_xdp_txq;
	int num_xdp_rxq;
	int num_xdp_complq;
	int xdp_txq_offset;
	int xdp_rxq_offset;
	int xdp_complq_offset;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *req_xsk_pool;
	bool xsk_enable_req;
#endif
	void (*xdp_prepare_tx_desc)(struct idpf_queue *xdpq, dma_addr_t dma,
				    u16 idx, u32 size);
#endif /* HAVE_XDP_SUPPORT */
	struct idpf_rx_ptype_decoded rx_ptype_lkup[IDPF_RX_MAX_PTYPE];
#ifdef IDPF_ADD_PROBES
	u64_stats_t ptype_stats[IDPF_RX_MAX_PTYPE];
#endif /* IDPF_ADD_PROBES */
	struct idpf_adapter *adapter;
	struct net_device *netdev;
	DECLARE_BITMAP(flags, IDPF_VPORT_FLAGS_NBITS);
	u16 vport_type;
	u32 vport_id;
	u16 idx;
	bool default_vport;
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];
	u16 rx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	u16 tx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	struct idpf_port_stats port_stats;
	bool link_up;
	struct idpf_vgrp p2p_vgrps[IDPF_P2P_NUM_OF_VGRPS];
	/* Everything below this will NOT be copied during soft reset */
	wait_queue_head_t sw_marker_wq;
	struct hwtstamp_config tstamp_config;
	struct idpf_ptp_vport_tx_tstamp_caps *tx_tstamp_caps;
	struct delayed_work tstamp_task;
	struct workqueue_struct *tstamp_wq;
};

/**
 * enum idpf_user_flags
 * @__IDPF_PRIV_FLAGS_HDR_SPLIT: Private flag to toggle header split
 * @__IDPF_PROMISC_UC: Unicast promiscuous mode
 * @__IDPF_PROMISC_MC: Multicast promiscuous mode
 * @__IDPF_USER_FLAGS_NBITS: Must be last
 */
enum idpf_user_flags {
	__IDPF_PRIV_FLAGS_HDR_SPLIT = 0,
	__IDPF_PROMISC_UC = 32,
	__IDPF_PROMISC_MC,
	__IDPF_USER_FLAGS_NBITS,
};

/**
 * struct idpf_rss_data - Associated RSS data
 * @rss_hash: RSS hash
 * @rss_key_size: Size of RSS hash key
 * @rss_key: RSS hash key
 * @rss_lut_size: Size of RSS lookup table
 * @rss_lut: RSS lookup table
 * @cached_lut: Used to restore previously init RSS lut
 */
struct idpf_rss_data {
	u64 rss_hash;
	u16 rss_key_size;
	u8 *rss_key;
	u16 rss_lut_size;
	u32 *rss_lut;
	u32 *cached_lut;
};

/**
 * struct idpf_vport_user_config_data - User defined configuration values for
 *                                      each vport.
 * @rss_data: See struct idpf_rss_data
 * @num_req_tx_qs: Number of user requested TX queues through ethtool
 * @num_req_rx_qs: Number of user requested RX queues through ethtool
 * @num_req_txq_desc: Number of user requested TX queue descriptors through
 *                    ethtool
 * @num_req_rxq_desc: Number of user requested RX queue descriptors through
 *                    ethtool
 * @user_flags: User toggled config flags
 * @mac_filter_list: List of MAC filters
 * @p2p_rss_data: P2P rss data. See struct idpf_rss_data.
 *
 * Used to restore configuration after a reset as the vport will get wiped.
 */
struct idpf_vport_user_config_data {
	struct idpf_rss_data rss_data;
	u16 num_req_tx_qs;
	u16 num_req_rx_qs;
	u32 num_req_txq_desc;
	u32 num_req_rxq_desc;
#ifdef HAVE_XDP_SUPPORT
	/* Duplicated in queue structure for performance reasons */
	struct bpf_prog *xdp_prog;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	DECLARE_BITMAP(af_xdp_zc_qps, IDPF_LARGE_MAX_Q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
	DECLARE_BITMAP(user_flags, __IDPF_USER_FLAGS_NBITS);
#ifdef HAVE_ETF_SUPPORT
	DECLARE_BITMAP(etf_qenable, IDPF_LARGE_MAX_Q);
#endif /* HAVE_ETF_SUPPORT */
	struct list_head mac_filter_list;
	struct idpf_rss_data p2p_rss_data[IDPF_P2P_NUM_OF_VGRPS];
};

/**
 * enum idpf_vport_config_flags - vport config flags
 * @IDPF_VPORT_REG_NETDEV: Register netdev
 * @IDPF_VPORT_UP_REQUESTED:  Set if interface up is requested on core reset
 * @IDPF_VPORT_UPLINK_PORT: Set if vport is attached to uplink port
 * @IDPF_VPORT_CONFIG_FLAGS_NBITS: Must be last
 */
enum idpf_vport_config_flags {
	IDPF_VPORT_REG_NETDEV,
	IDPF_VPORT_UP_REQUESTED,
	IDPF_VPORT_UPLINK_PORT,
	IDPF_VPORT_CONFIG_FLAGS_NBITS,
};

/**
 * struct idpf_avail_queue_info
 * @avail_rxq: Available RX queues
 * @avail_txq: Available TX queues
 * @avail_bufq: Available buffer queues
 * @avail_complq: Available completion queues
 *
 * Maintain total queues available after allocating max queues to each vport.
 */
struct idpf_avail_queue_info {
	u16 avail_rxq;
	u16 avail_txq;
	u16 avail_bufq;
	u16 avail_complq;
};

/**
 * struct idpf_vector_info - Utility structure to pass function arguments as a
 *                           structure
 * @num_req_vecs: Vectors required based on the number of queues updated by the
 *                user via ethtool
 * @num_curr_vecs: Current number of vectors, must be >= @num_req_vecs
 * @index: Relative starting index for vectors
 * @default_vport: Vectors are for default vport
 */
struct idpf_vector_info {
	u16 num_req_vecs;
	u16 num_curr_vecs;
	u16 index;
	bool default_vport;
};

/**
 * struct idpf_vector_lifo - Stack to maintain vector indexes used for vector
 *                           distribution algorithm
 * @top: Points to stack top i.e. next available vector index
 * @base: Always points to start of the free pool
 * @size: Total size of the vector stack
 * @vec_idx: Array to store all the vector indexes
 *
 * Vector stack maintains all the relative vector indexes at the *adapter*
 * level. This stack is divided into 2 parts, first one is called as 'default
 * pool' and other one is called 'free pool'.  Vector distribution algorithm
 * gives priority to default vports in a way that at least IDPF_MIN_Q_VEC
 * vectors are allocated per default vport and the relative vector indexes for
 * those are maintained in default pool. Free pool contains all the unallocated
 * vector indexes which can be allocated on-demand basis.
 * Mailbox vector index is maintained in the default pool of the stack
 * and also the RDMA vectors.
 */
struct idpf_vector_lifo {
	u16 top;
	u16 base;
	u16 size;
	u16 *vec_idx;
};

/**
 * struct idpf_vport_config - Vport configuration data
 * @user_config: see struct idpf_vport_user_config_data
 * @max_q: Maximum possible queues
 * @req_qs_chunks: Queue chunk data for requested queues
 * @mac_filter_list_lock: Lock to protect mac filters
 * @flags: See enum idpf_vport_config_flags
 */
struct idpf_vport_config {
	struct idpf_vport_user_config_data user_config;
	struct idpf_vport_max_q max_q;
	struct virtchnl2_add_queues *req_qs_chunks;
	spinlock_t mac_filter_list_lock;
	DECLARE_BITMAP(flags, IDPF_VPORT_CONFIG_FLAGS_NBITS);
};

#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
struct idpf_iommu_bypass {
	struct iommu_domain *iodom;
	struct device *ddev;
	u64 bypass_iova_addr;
	phys_addr_t bypass_phys_addr;
	size_t bypass_size;
};

#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */

#define idpf_for_each_vport(adapter, i) \
	for ((i) = 0; (i) < (adapter)->num_alloc_vports; (i)++)

/**
 * struct idpf_adapter - Device data struct generated on probe
 * @pdev: PCI device struct given on probe
 * @virt_ver_maj: Virtchnl version major
 * @virt_ver_min: Virtchnl version minor
 * @msg_enable: Debug message level enabled
 * @mb_wait_count: Number of times mailbox was attempted initialization
 * @state: Init state machine
 * @flags: See enum idpf_flags
 * @reset_reg: See struct idpf_reset_reg
 * @hw: Device access data
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
 * @adi_info: ADI info
#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
 * @parent: MDEV parent
#endif
#endif
 * @num_req_msix: Requested number of MSIX vectors
 * @num_avail_msix: Available number of MSIX vectors
 * @num_msix_entries: Number of entries in MSIX table
 * @msix_entries: MSIX table
 * @req_vec_chunks: Requested vector chunk data
 * @mb_vector: Mailbox vector data
 * @vector_stack: Stack to store the msix vector indexes
 * @irq_mb_handler: Handler for hard interrupt for mailbox
 * @tx_timeout_count: Number of TX timeouts that have occurred
 * @avail_queues: Device given queue limits
 * @vports: Array to store vports created by the driver
 * @netdevs: Associated Vport netdevs
 * @vport_params_reqd: Vport params requested
 * @vport_params_recvd: Vport params received
 * @vport_ids: Array of device given vport identifiers
 * @vcxn_mngr: Virtchnl transaction manager
 * @vport_config: Vport config parameters
 * @max_vports: Maximum vports that can be allocated
 * @num_alloc_vports: Current number of vports allocated
 * @next_vport: Next free slot in pf->vport[] - 0-based!
 * @init_task: Initialization task
 * @init_wq: Workqueue for initialization task
 * @serv_task: Periodically recurring maintenance task
 * @serv_wq: Workqueue for service task
 * @mbx_task: Task to handle mailbox interrupts
 * @mbx_wq: Workqueue for mailbox responses
 * @vc_event_task: Task to handle out of band virtchnl event notifications
 * @vc_event_wq: Workqueue for virtchnl events
 * @stats_task: Periodic statistics retrieval task
 * @stats_wq: Workqueue for statistics task
 * @caps: Negotiated capabilities with device
 * @edt_caps: EDT capabilities
 * @dev_ops: See idpf_dev_ops
 * @rdma_data: RDMA data
 * @num_vfs: Number of allocated VFs through sysfs. PF does not directly talk
 *           to VFs but is used to initialize them
 * @req_tx_splitq: TX split or single queue model to request
 * @req_rx_splitq: RX split or single queue model to request
 * @crc_enable: Enable CRC insertion offload
 * @vport_ctrl_lock: Lock to protect access to vports during alloc/dealloc/reset
 * @vector_lock: Lock to protect vector distribution
 * @queue_lock: Lock to protect queue distribution
#ifdef DEVLINK_ENABLED
 * @cleanup_task: Deferred execution of destroy
 * @sf_mutex: To control access to subfunction list
 * @sf_list: List of active and deleted subfunctions
 * @sf_id: Unique integer corresponding to a subfunc
 * @sf_cnt: Count of active subfunctions
#endif
 * @ptp: PTP structure
 * @corer_done: Used to track the completion of CORER
 */
struct idpf_adapter {
	struct pci_dev *pdev;
#ifdef CONFIG_IOMMU_BYPASS
#ifdef CONFIG_ARM64
	struct idpf_iommu_bypass iommu_byp;
#endif /* CONFIG_ARM64 */
#endif /* CONFIG_IOMMU_BYPASS */
	const char *drv_name;
	const char *drv_ver;
	u32 virt_ver_maj;
	u32 virt_ver_min;
	u32 msg_enable;
	u32 mb_wait_count;
	enum idpf_state state;
	DECLARE_BITMAP(flags, IDPF_FLAGS_NBITS);
	struct idpf_reset_reg reset_reg;
	struct idpf_hw hw;
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	struct idpf_adi_info adi_info;
#if defined(HAVE_MDEV_REGISTER_PARENT) && defined(ENABLE_ACC_PASID_WA)
	struct mdev_parent parent;
#endif /* HAVE_MDEV_REGISTER_PARENT && ENABLE_ACC_PASID_WA */
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	u16 num_req_msix;
	u16 num_avail_msix;
	u16 num_msix_entries;
	struct msix_entry *msix_entries;
	struct virtchnl2_alloc_vectors *req_vec_chunks;
	struct idpf_q_vector mb_vector;
	struct idpf_vector_lifo vector_stack;
	irqreturn_t (*irq_mb_handler)(int irq, void *data);
	u32 tx_timeout_count;
	struct idpf_avail_queue_info avail_queues;
	struct idpf_vport **vports;
	struct net_device **netdevs;
	struct virtchnl2_create_vport **vport_params_reqd;
	struct virtchnl2_create_vport **vport_params_recvd;
	u32 *vport_ids;
	struct idpf_vc_xn_manager vcxn_mngr;
	struct idpf_vport_config **vport_config;
	u16 max_vports;
	u16 num_alloc_vports;
	u16 next_vport;
	struct delayed_work init_task;
	struct workqueue_struct *init_wq;
	struct delayed_work serv_task;
	struct workqueue_struct *serv_wq;
	struct delayed_work mbx_task;
	struct workqueue_struct *mbx_wq;
	struct delayed_work vc_event_task;
	struct workqueue_struct *vc_event_wq;
	struct delayed_work stats_task;
	struct workqueue_struct *stats_wq;
	struct virtchnl2_get_capabilities caps;
	struct virtchnl2_edt_caps edt_caps;
	struct virtchnl2_oem_caps oem_caps;
	struct idpf_dev_ops dev_ops;
	struct idpf_rdma_data rdma_data;
	int num_vfs;
	bool req_tx_splitq;
	bool req_rx_splitq;
	bool crc_enable;
	struct mutex vport_ctrl_lock;
	struct mutex vector_lock;
	struct mutex queue_lock;
#ifdef DEVLINK_ENABLED
	struct delayed_work cleanup_task;
	struct mutex sf_mutex; /* To control access to sf_list */
	struct list_head sf_list;
	unsigned short sf_id;
	unsigned short sf_cnt;
#endif /* DEVLINK_ENABLED */
	struct idpf_ptp ptp;
	struct completion corer_done;
};

/**
 * idpf_is_queue_model_split - check if queue model is split
 * @q_model: queue model single or split
 *
 * Returns true if queue model is split else false
 */
static inline int idpf_is_queue_model_split(u16 q_model)
{
	return (q_model == VIRTCHNL2_QUEUE_MODEL_SPLIT);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_xdp_is_prog_ena - check if there is an XDP program on adapter
 * @vport: vport to check
 */
static inline bool idpf_xdp_is_prog_ena(struct idpf_vport *vport)
{
	if (!vport->adapter)
		return false;

	return vport->adapter->vport_config[vport->idx]->user_config.xdp_prog;
}

/**
 * idpf_get_related_xdp_queue - Get corresponding XDP Tx queue for Rx queue
 * @rxq: Rx queue
 *
 * Returns a pointer to XDP Tx queue linked to a given Rx queue.
 */
static inline struct idpf_queue *idpf_get_related_xdp_queue(struct idpf_queue *rxq)
{
	return rxq->vport->dflt_grp.q_grp.txqs[rxq->idx + rxq->vport->xdp_txq_offset];
}

/**
 * idpf_wait_for_hard_reset - Wait until the hard reset is completed
 * @adapter: pointer to the adapter under hard reset
 *
 * Returns zero if the hard reset is completed, or -EBUSY in case of timeout.
 */
static inline int idpf_wait_for_hard_reset(struct idpf_adapter *adapter)
{
	int timeout = IDPF_HARD_RESET_TIMEOUT_MSEC;
	int delay_msec = 100;

	while (test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags)) {
		if (timeout <= 0)
			return -EBUSY;

		msleep(delay_msec);
		timeout -= delay_msec;
	}

	return 0;
}

#endif /* HAVE_XDP_SUPPORT */

#define idpf_is_cap_ena(adapter, field, flag) \
	idpf_is_capability_ena(adapter, false, field, flag)
#define idpf_is_cap_ena_all(adapter, field, flag) \
	idpf_is_capability_ena(adapter, true, field, flag)

bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag);

/**
 * idpf_is_rdma_cap_ena - Determine if RDMA is supported
 * @adapter: private data struct
 */
static inline bool idpf_is_rdma_cap_ena(struct idpf_adapter *adapter)
{
	return idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_RDMA);
}

#define IDPF_CAP_RSS (\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV4_OTHER	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV6_OTHER)

#define IDPF_CAP_RSC (\
	VIRTCHNL2_CAP_RSC_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV6_TCP)

#define IDPF_CAP_HSPLIT	(\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6)

#define IDPF_CAP_RX_CSUM_L4V4 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP)

#define IDPF_CAP_RX_CSUM_L4V6 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IDPF_CAP_RX_CSUM (\
	VIRTCHNL2_CAP_RX_CSUM_L3_IPV4		|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IDPF_CAP_SCTP_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

#define IDPF_CAP_TUNNEL_TX_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL)

/**
 * idpf_get_reserved_vecs - Get reserved vectors
 * @adapter: private data struct
 */
static inline u16 idpf_get_reserved_vecs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.num_allocated_vectors);
}

/**
 * idpf_get_default_vports - Get default number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_default_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.default_num_vports);
}

/**
 * idpf_get_max_vports - Get max number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_max_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_vports);
}

/**
 * idpf_get_max_tx_bufs - Get max scatter-gather buffers supported by the device
 * @adapter: private data struct
 */
static inline unsigned int idpf_get_max_tx_bufs(struct idpf_adapter *adapter)
{
	return adapter->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_get_min_tx_pkt_len - Get min packet length supported by the device
 * @adapter: private data struct
 */
static inline u8 idpf_get_min_tx_pkt_len(struct idpf_adapter *adapter)
{
	u8 pkt_len = adapter->caps.min_sso_packet_len;

	return pkt_len ? pkt_len : IDPF_TX_MIN_PKT_LEN;
}

/**
 * idpf_get_reg_addr - Get BAR0 register address
 * @adapter: private data struct
 * @reg_offset: register offset value
 *
 * Based on the register offset, return the actual BAR0 register address
 */
static inline void __iomem *idpf_get_reg_addr(struct idpf_adapter *adapter,
					      resource_size_t reg_offset)
{
	struct idpf_hw *hw = &adapter->hw;

	if (reg_offset < adapter->dev_ops.bar0_region1_size)
		return (void __iomem *)(hw->hw_addr + reg_offset);
	else
		return (void __iomem *)(hw->hw_addr_region2 + reg_offset -
					adapter->dev_ops.bar0_region2_start);
}

/**
 * idpf_is_reset_in_prog - check if reset is in progress
 * @adapter: driver specific private structure
 *
 * Returns true if hard reset is in progress, false otherwise
 */
static inline bool idpf_is_reset_in_prog(struct idpf_adapter *adapter)
{
	return (test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags) ||
		test_bit(IDPF_HR_FUNC_RESET, adapter->flags) ||
		test_bit(IDPF_HR_DRV_LOAD, adapter->flags));
}

/**
 * idpf_is_resource_rel_in_prog - Check if resource release is in progress
 * @adapter: Driver specific private structure
 *
 * Returns true if resource release is in progress, false otherwise
 */
static inline bool idpf_is_resource_rel_in_prog(struct idpf_adapter *adapter)
{
	return (test_bit(IDPF_HR_RESET_IN_PROG, adapter->flags) ||
		test_bit(IDPF_HR_FUNC_RESET, adapter->flags) ||
		test_bit(IDPF_REMOVE_IN_PROG, adapter->flags));
}

/**
 * idpf_netdev_to_vport - Get vport handle from a netdev
 * @netdev: network interface device structure
 */
static inline struct idpf_vport *idpf_netdev_to_vport(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->vport;
}

/**
 * idpf_netdev_to_adapter - Get adapter handle from a netdev
 * @netdev: Network interface device structure
 */
static inline struct idpf_adapter *idpf_netdev_to_adapter(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->adapter;
}

/**
 * idpf_adapter_to_dev - Get device pointer from adapter
 * @adapter: driver specific private structure
 */
static inline struct device *idpf_adapter_to_dev(struct idpf_adapter *adapter)
{
	return &adapter->pdev->dev;
}

#ifdef HAVE_NDO_FEATURES_CHECK
/**
 * idpf_get_max_tx_hdr_size -- get the size of tx header
 * @adapter: Driver specific private structure
 */
static inline u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_tx_hdr_size);
}

#endif /* HAVE_NDO_FEATURES_CHECK */
/**
 * idpf_rx_bufq_offset - Translate an RX idx and bufq idx for true offset
 * @q_grp: Queue resources
 * @rx_idx: RX queue index
 * @bufq_idx: Buffer queue index
 */
static inline int idpf_rx_bufq_offset(struct idpf_q_grp *q_grp, int rx_idx,
				      int bufq_idx)
{
	return q_grp->bufq_per_rxq * rx_idx + bufq_idx;
}

/**
 * idpf_txq_from_rel_qid - Translate a relative TX qid to txq
 * @q_grp: Queue resources
 * @complq: Completion queue to base
 * @rel_qid: Relative qid
 */
static inline struct idpf_queue *
idpf_txq_from_rel_qid(struct idpf_q_grp *q_grp, struct idpf_queue *complq,
		      u32 rel_qid)
{
	int offset = complq->idx * IDPF_TXQ_PER_COMPLQ + rel_qid;

	if (unlikely(offset >= q_grp->num_txq))
		return NULL;

	return q_grp->txqs[offset];
}

/**
 * idpf_is_oem_cap_ena - Implementation of oem caps checking
 * @adapter: private data struct
 * @oem_cap: capability to check
 */
static inline bool idpf_is_oem_cap_ena(struct idpf_adapter *adapter,
				       u64 oem_cap)
{
	u64 oem_caps = le64_to_cpu(adapter->oem_caps.oem_caps);

	return !!(oem_caps & oem_cap);
}

/**
 * idpf_is_p2p_enabled - Check if P2P is enabled
 * @vport: Virtual port
 */
static inline bool idpf_is_p2p_enabled(struct idpf_vport *vport)
{
	return (idpf_is_oem_cap_ena(vport->adapter, VIRTCHNL2_CAP_OEM_P2P) &&
		test_bit(IDPF_VPORT_PORT2PORT_ENABLED, vport->flags));
}

/**
 * idpf_get_queue_group_info - Get queue group info pointer
 * @aqg: Pointer from which queue group info to be extracted
 */
static inline struct virtchnl2_queue_group_info *
idpf_get_queue_group_info(struct virtchnl2_add_queue_groups *aqg) {
	return (struct virtchnl2_queue_group_info *)
			((u8 *)aqg + IDPF_P2P_QGRP_INFO_OFFSET);
}

/**
 * idpf_vport_ctrl_lock -Acquire the vport control lock
 * @netdev: Network interface device structure
 *
 * This lock should be used by non-datapath code to protect against vport
 * destruction.
 */
static inline void idpf_vport_ctrl_lock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_lock(&np->adapter->vport_ctrl_lock);
}

/**
 * idpf_vport_ctrl_unlock - Release the vport control lock
 * @netdev: Network interface device structure
 */
static inline void idpf_vport_ctrl_unlock(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	mutex_unlock(&np->adapter->vport_ctrl_lock);
}

void idpf_statistics_task(struct work_struct *work);
void idpf_init_task(struct work_struct *work);
void idpf_service_task(struct work_struct *work);
void idpf_mbx_task(struct work_struct *work);
void idpf_tstamp_task(struct work_struct *work);
void idpf_vc_event_task(struct work_struct *work);
void idpf_dev_ops_init(struct idpf_adapter *adapter);
void idpf_vf_dev_ops_init(struct idpf_adapter *adapter);
void idpf_vc_xn_init(struct idpf_vc_xn_manager *vcxn_mngr);
void idpf_vc_xn_shutdown(struct idpf_vc_xn_manager *vcxn_mngr);
void idpf_vport_adjust_qs(struct idpf_vport *vport);
int idpf_init_dflt_mbx(struct idpf_adapter *adapter);
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter);
int idpf_vc_core_init(struct idpf_adapter *adapter);
void idpf_vc_core_deinit(struct idpf_adapter *adapter);
int idpf_intr_req(struct idpf_adapter *adapter);
void idpf_intr_rel(struct idpf_adapter *adapter);
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals);
#ifdef HAVE_NDO_FEATURES_CHECK
u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter);
#endif /* HAVE_NDO_FEATURES_CHECK */
int idpf_send_delete_queues_msg(struct idpf_vport *vport);
int idpf_send_add_queues_msg(struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq);
int idpf_send_add_queue_grp_msg(const struct idpf_vport *vport, u16 num_tx_q,
				u16 num_complq, u16 num_rx_q, u16 num_rx_bufq,
				struct virtchnl2_add_queue_groups *req_chunks,
				int q_grp_id);
int idpf_send_del_queue_grp_msg(const struct idpf_vport *vport,
				struct virtchnl2_add_queue_groups *req_chunks);
void idpf_vport_vgrp_init_num_qs(struct idpf_vport *vport,
				 struct idpf_q_grp *q_grp);
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_reset_cause reset_cause);
int idpf_send_enable_vport_msg(struct idpf_vport *vport);
int idpf_send_disable_vport_msg(struct idpf_vport *vport);
int idpf_send_destroy_vport_msg(struct idpf_vport *vport);
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport);
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport);
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport,
				  struct idpf_rss_data *rss_data,
				  bool get);
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport,
				  struct idpf_rss_data *rss_data,
				  bool get);
int idpf_send_get_set_rss_hash_msg(struct idpf_vport *vport, bool get);
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter);
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors);
void idpf_deinit_task(struct idpf_adapter *adapter);
void idpf_deinit_vector_stack(struct idpf_adapter *adapter);
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter,
				u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info);
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport,
				 struct idpf_vgrp *vgrp);
void idpf_vport_dealloc_vec_indexes(struct idpf_vport *vport,
				    struct idpf_vgrp *vgrp);
int idpf_send_get_stats_msg(struct idpf_vport *vport);
int idpf_send_get_port_stats_msg(struct idpf_vport *vport);
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks);
int idpf_recv_mb_msg(struct idpf_adapter *adapter);
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg, u16 cookie);
ssize_t idpf_vc_xn_exec(struct idpf_adapter *adapter,
			struct idpf_vc_xn_params params);
void idpf_set_ethtool_ops(struct net_device *netdev);
void idpf_vport_set_hsplit(struct idpf_vport *vport, bool ena);
#ifdef DEVLINK_ENABLED
void idpf_vport_dealloc(struct idpf_vport *vport);
#endif /* DEVLINK_ENABLED */
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q);
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_add_del_mac_filters(struct idpf_vport *vport,
			     struct idpf_netdev_priv *np,
			     bool add, bool async);
int idpf_set_promiscuous(struct idpf_adapter *adapter,
			 struct idpf_vport_user_config_data *config_data,
			 u32 vport_id);
int idpf_send_disable_queues_msg(struct idpf_vport *vport,
				 struct idpf_vgrp *vgrp,
				 struct virtchnl2_queue_reg_chunks *chunks);
struct virtchnl2_queue_reg_chunks *
idpf_get_queue_reg_chunks(struct idpf_vport *vport);
int idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q);
void idpf_netdev_stop_all(struct idpf_adapter *adapter);
void idpf_device_detach(struct idpf_adapter *adapter);
int idpf_check_reset_complete(struct idpf_adapter *adapter);
int idpf_init_hard_reset(struct idpf_adapter *adapter);
void idpf_reset_recover(struct idpf_adapter *adapter);
bool idpf_is_reset_detected(struct idpf_adapter *adapter);
int idpf_vport_queue_ids_init(struct idpf_q_grp *q_grp,
			      struct virtchnl2_queue_reg_chunks *chunks);
int idpf_queue_reg_init(struct idpf_vport *vport, struct idpf_q_grp *q_grp,
			struct virtchnl2_queue_reg_chunks *chunks);
int idpf_send_config_queues_msg(struct idpf_vport *vport,
				struct idpf_q_grp *q_grp);
int idpf_send_enable_queues_msg(struct idpf_vport *vport,
				struct virtchnl2_queue_reg_chunks *chunks);
void idpf_set_vport_state(struct idpf_adapter *adapter);
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_check_supported_desc_ids(struct idpf_vport *vport);
int idpf_send_create_adi_msg(struct idpf_adapter *adapter,
			     struct virtchnl2_non_flex_create_adi *vchnl_adi);
int idpf_send_destroy_adi_msg(struct idpf_adapter *adapter,
			      struct virtchnl2_non_flex_destroy_adi *vchnl_adi);
void idpf_vport_intr_write_itr(struct idpf_q_vector *q_vector,
			       u16 itr, bool tx);
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport,
					 struct idpf_vgrp *vgrp, bool map);
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_FRAME_STRUCT
int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags);
#else
int idpf_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp);
#endif /* HAVE_XDP_FRAME_STRUCT */
#ifndef NO_NDO_XDP_FLUSH
void idpf_xdp_flush(struct net_device *dev);
#endif /* NO_NDO_XDP_FLUSH */
#endif /* HAVE_XDP_SUPPORT */
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs);
int idpf_sriov_configure(struct pci_dev *pdev, int num_vfs);
int idpf_idc_init(struct idpf_adapter *adapter);
void idpf_idc_deinit(struct idpf_adapter *adapter);
int
idpf_idc_init_aux_device(struct idpf_adapter *adapter,
			 enum iidc_function_type ftype);
void idpf_idc_deinit_aux_device(struct idpf_adapter *adapter);
int idpf_idc_vc_receive(struct idpf_adapter *adapter, u32 f_id, const u8 *msg,
			u16 msg_size);
void idpf_idc_event(struct idpf_adapter *adapter,
		    enum idpf_vport_reset_cause reason,
		    bool pre_event);
static inline bool idpf_is_feature_ena(struct idpf_vport *vport,
				       netdev_features_t feature)
{
	return vport->netdev->features & feature;
}

/**
 * idpf_ptp_info_to_adapter - get driver adapter struct from ptp_clock_info
 * @info: pointer to ptp_clock_info struct
 */
static inline
struct idpf_adapter *idpf_ptp_info_to_adapter(struct ptp_clock_info *info)
{
	struct idpf_ptp *ptp = container_of(info, struct idpf_ptp, info);

	return container_of(ptp, struct idpf_adapter, ptp);
}

#endif /* !_IDPF_H_ */
