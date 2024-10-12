/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#ifndef _IDPF_PTP_H_
#define _IDPF_PTP_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/kthread.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>

enum idpf_ptp_access {
	IDPF_PTP_NONE = 0,
	IDPF_PTP_DIRECT,
	IDPF_PTP_MAILBOX,
};

struct idpf_ptp_cmd {
	int exec_cmd_mask;
	int shtime_enable_mask;
};

struct idpf_ptp_secondary_mbx {
	bool valid;
	u16 peer_mbx_q_id;
	u8 secondary_mbx;
	u8 peer_id;
};

struct idpf_ptp_dev_clk_regs {
	/* Main clock */
	u32 dev_clk_ns_l;
	u32 dev_clk_ns_h;

	/* PHY timer */
	u32 phy_clk_ns_l;
	u32 phy_clk_ns_h;

	/* System time */
	u32 sys_time_ns_l;
	u32 sys_time_ns_h;

	/* Main timer adjustments */
	u32 incval_l;
	u32 incval_h;
	u32 shadj_l;
	u32 shadj_h;

	/* PHY timer adjustments */
	u32 phy_incval_l;
	u32 phy_incval_h;
	u32 phy_shadj_l;
	u32 phy_shadj_h;

	/* Command */
	u32 cmd;
	u32 phy_cmd;
	u32 cmd_sync;
};

enum idpf_ptp_tx_tstamp_state {
	IDPF_PTP_FREE = 0,
	IDPF_PTP_REQUEST,
	IDPF_PTP_READ_VALUE,
};

/**
 * struct idpf_ptp_tx_tstamp_status - Parameters to track Tx timestamp
 * @skb: the pointer to the SKB that received the completion tag
 * @state: the state of the Tx timestamp
 */
struct idpf_ptp_tx_tstamp_status {
	struct sk_buff *skb;
	enum idpf_ptp_tx_tstamp_state state;
};

/**
 * struct idpf_ptp_tx_tstamp - Parametrs for Tx timestamping
 * @list_member: the list member strutcure
 * @tx_latch_reg_offset_l: Tx tstamp latch low register offset
 * @tx_latch_reg_offset_h: Tx tstamp latch high register offset
 * @skb: the pointer to the SKB for this timestamp request
 * @tstamp: the Tx tstamp value
 * @idx: the index of the Tx tstamp
 * @valid: the validity of the Tx tstamp
 */
struct idpf_ptp_tx_tstamp {
	struct list_head list_member;
	u32 tx_latch_reg_offset_l;
	u32 tx_latch_reg_offset_h;
	struct sk_buff *skb;
	u64 tstamp;
	u8 idx;
	u8 valid;
};

/**
 * struct idpf_ptp_vport_tx_tstamp_caps - Tx timestamp capabilities
 * @vport_id: the vport id
 * @num_entries: the number of negotiated Tx timestamp entries
 * @tstamp_ns_lo_bit: first bit for nanosecond part of the timestamp
 * @lock_in_use: the lock to the used latches list
 * @lock_free: the lock to free the latches list
 * @latches_free: the list of the free Tx timestamps latches
 * @latches_in_use: the list of the used Tx timestamps latches
 * @tx_tstamp_status: the pointer to the tx tstamp status tracker
 */
struct idpf_ptp_vport_tx_tstamp_caps {
	u32 vport_id;
	u16 num_entries;
	u8 tstamp_ns_lo_bit;
	struct mutex lock_in_use; /* lock to used latches list */
	struct mutex lock_free; /* lock to free latches list */
	struct list_head latches_free;
	struct list_head latches_in_use;
	struct idpf_ptp_tx_tstamp_status *tx_tstamp_status;
};

/**
 * struct idpf_ptp - Data used for integrating with CONFIG_PTP_1588_CLOCK
 * @info: structure defining PTP hardware capabilities
 * @clock: pointer to registered PTP clock device
 * @cmd: HW specific command masks
 * @dev_clk_regs: the set of registers to access the device clock
 * @secondary_mbx: indicates whether the secondary mailbox for PTP is enabled
 * @caps: PTP capabilities negotiated with the CP
 * @base_incval: base increment value of the PTP clock
 * @max_adj: maximum adjustment of the PTP clock
 * @cached_phc_time: a cached copy of the PHC time for timestamp extension
 * @cached_phc_jiffies: jiffies when cached_phc_time was last updated
 * @work: delayed work function for periodic tasks
 * @kworker: kwork thread for handling periodic work
 * @get_dev_clk_time_access: access type for getting the device clock time
 * @get_cross_tstamp_access: access type for the cross timestamping
 * @set_dev_clk_time_access: access type for setting the device clock time
 * @adj_dev_clk_time_access: access type for the adjusting the device clock
 * @tx_tstamp_access: access type for the Tx timestamping
 */
struct idpf_ptp {
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct idpf_ptp_cmd cmd;
	struct idpf_ptp_dev_clk_regs dev_clk_regs;
	struct idpf_ptp_secondary_mbx secondary_mbx;
	u32 caps;
	u64 base_incval;
	u64 max_adj;
	u64 cached_phc_time;
	unsigned long cached_phc_jiffies;
	struct kthread_delayed_work work;
	struct kthread_worker *kworker;
	enum idpf_ptp_access get_dev_clk_time_access;
	enum idpf_ptp_access get_cross_tstamp_access;
	enum idpf_ptp_access set_dev_clk_time_access;
	enum idpf_ptp_access adj_dev_clk_time_access;
	enum idpf_ptp_access tx_tstamp_access;
};

struct idpf_ptp_dev_timers {
	u64 sys_time_ns;
	u64 dev_clk_time_ns;
};

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
int idpf_ptp_get_caps(struct idpf_adapter *adapter);
bool idpf_ptp_is_cap_ena(struct idpf_adapter *adapter, u32 cap);
void idpf_ptp_get_features_access(struct idpf_adapter *adapter);
int idpf_ptp_init(struct idpf_adapter *adpater);
void idpf_ptp_release(struct idpf_adapter *adapter);
int idpf_ptp_get_dev_clk_time(struct idpf_adapter *adapter,
			      struct idpf_ptp_dev_timers *dev_clk_time);
int idpf_ptp_get_cross_time(struct idpf_adapter *adapter,
			    struct idpf_ptp_dev_timers *cross_time);
int idpf_ptp_set_dev_clk_time(struct idpf_adapter *adapter, u64 time);
int idpf_ptp_adj_dev_clk_fine(struct idpf_adapter *adapter, u64 incval);
int idpf_ptp_adj_dev_clk_time(struct idpf_adapter *adapter, s64 delta);
int idpf_ptp_get_tx_tstamp(struct idpf_vport *vport);
int idpf_ptp_get_ts_config(struct idpf_vport *vport, struct ifreq *ifr);
int idpf_ptp_set_ts_config(struct idpf_vport *vport, struct ifreq *ifr);
s8 idpf_ptp_request_ts(struct idpf_vport *vport, struct sk_buff *skb);
u64 idpf_ptp_extend_ts(struct idpf_adapter *adapter, u32 in_tstamp);
u64 idpf_ptp_tstamp_extend_32b_to_64b(u64 cached_phc_time, u32 in_timestamp);
#else /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
static inline int idpf_ptp_get_caps(struct idpf_adapter *adapter)
{
	return -EOPNOTSUPP;
}

static inline bool idpf_ptp_is_cap_ena(struct idpf_adapter *adapter, u32 cap)
{
	return false;
}

static inline void idpf_ptp_get_features_access(struct idpf_adapter *adapter) { }

static inline int idpf_ptp_init(struct idpf_adapter *adpater)
{
	dev_err(&adapter->pdev->dev, "PTP not supported when CONFIG_PTP_1588_CLOCK is disabled\n");
	return 0;
}

static inline void idpf_ptp_release(struct idpf_adapter *adapter) { }

static inline int idpf_ptp_get_dev_clk_time(struct idpf_adapter *adapter,
					    struct idpf_ptp_dev_timers *dev_clk_time)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_get_cross_time(struct idpf_adapter *adapter,
					  struct idpf_ptp_dev_timers *cross_time)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_set_dev_clk_time(struct idpf_adapter *adapter,
					    u64 time)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_adj_dev_clk_fine(struct idpf_adapter *adapter,
					    u64 incval)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_adj_dev_clk_time(struct idpf_adapter *adapter,
					    s64 delta)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_get_tx_tstamp(struct idpf_vport *vport)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_get_ts_config(struct idpf_vport *vport,
					 struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline int idpf_ptp_set_ts_config(struct idpf_vport *vport,
					 struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

static inline s8 idpf_ptp_request_ts(struct idpf_vport *vport,
				     struct sk_buff *skb)
{
	return -1;
}

static inline u64 idpf_ptp_extend_ts(struct idpf_adapter *adapter,
				     u32 in_tstamp)
{
	return 0;
}

static inline u64 idpf_ptp_tstamp_extend_32b_to_64b(u64 cached_phc_time,
						    u32 in_timestamp)
{
	return 0;
}
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
#endif /* _IDPF_PTP_H_ */
