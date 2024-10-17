/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019-2024 Intel Corporation */

#include "idpf.h"
#if IS_ENABLED(CONFIG_ARM_ARCH_TIMER)
#include <clocksource/arm_arch_timer.h>
#endif

/**
 * idpf_ptp_is_cap_ena - check if certain PTP caps are enabled
 * @adapter: Driver specific private structure
 * @cap: Capability to check
 */
bool idpf_ptp_is_cap_ena(struct idpf_adapter *adapter, u32 cap)
{
	dev_dbg(idpf_adapter_to_dev(adapter), "PTP caps %x\n", adapter->ptp.caps);

	return adapter->ptp.caps & cap;
}

/**
 * idpf_ptp_get_access - Determine the access type of the PTP features
 * @adapter: Driver specific private structure
 * @direct: Capability that indicates the direct access
 * @mailbox: Capability that indicates the mailbox access
 *
 * Returns the type of supported access
 */
static enum idpf_ptp_access idpf_ptp_get_access(struct idpf_adapter *adapter,
						u32 direct, u32 mailbox)
{
	if (idpf_ptp_is_cap_ena(adapter, direct))
		return IDPF_PTP_DIRECT;
	else if (idpf_ptp_is_cap_ena(adapter, mailbox))
		return IDPF_PTP_MAILBOX;
	else
		return IDPF_PTP_NONE;
}

/**
 * idpf_ptp_get_features_access - Determine the access type of PTP features
 * @adapter: Driver specific private structure
 *
 * Returns the type of the supported access
 */
void idpf_ptp_get_features_access(struct idpf_adapter *adapter)
{
	struct idpf_ptp *ptp = &adapter->ptp;

	/* Get the device clock time */
	ptp->get_dev_clk_time_access = idpf_ptp_get_access(adapter,
							   VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME,
							   VIRTCHNL2_CAP_PTP_GET_DEVICE_CLK_TIME_MB);

	/* Get the cross timestamp */
	ptp->get_cross_tstamp_access = idpf_ptp_get_access(adapter,
							   VIRTCHNL2_CAP_PTP_GET_CROSS_TIME,
							   VIRTCHNL2_CAP_PTP_GET_CROSS_TIME_MB);

	/* Set the device clock time */
	ptp->set_dev_clk_time_access = idpf_ptp_get_access(adapter,
							   VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME,
							   VIRTCHNL2_CAP_PTP_SET_DEVICE_CLK_TIME_MB);
	/* Adjust the device clock time */
	ptp->adj_dev_clk_time_access = idpf_ptp_get_access(adapter,
							   VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK,
							   VIRTCHNL2_CAP_PTP_ADJ_DEVICE_CLK_MB);
	/* Tx timestamping */
	ptp->tx_tstamp_access = idpf_ptp_get_access(adapter,
						    VIRTCHNL2_CAP_PTP_TX_TSTAMPS,
						    VIRTCHNL2_CAP_PTP_TX_TSTAMPS_MB);
}

/**
 * idpf_ptp_enable_shtime - Enable shadow time and execute a command
 * @adapter: Driver specific private structure
 */
static void idpf_ptp_enable_shtime(struct idpf_adapter *adapter)
{
	u32 syn_cmd, shtime_enable, exec_cmd;

	/* Get offsets */
	syn_cmd = adapter->ptp.dev_clk_regs.cmd_sync;
	shtime_enable = adapter->ptp.cmd.shtime_enable_mask;
	exec_cmd = adapter->ptp.cmd.exec_cmd_mask;

	/* Set the shtime en and the sync field */
	writel(shtime_enable, idpf_get_reg_addr(adapter, syn_cmd));
	writel(exec_cmd | shtime_enable, idpf_get_reg_addr(adapter, syn_cmd));
}

/**
 * idpf_ptp_read_src_clk_reg - Read the source clock register
 * @adapter: Driver specific private structure
 * @src_clk: Returned main timer value in nanoseconds unit
 * @sts: Optional parameter for holding a pair of system timestamps from
 *	 the system clock. Will be ignored if NULL is given.
 */
static int idpf_ptp_read_src_clk_reg(struct idpf_adapter *adapter,
				     u64 *src_clk,
				     struct ptp_system_timestamp *sts)
{
	struct idpf_ptp *ptp = &adapter->ptp;
	struct idpf_ptp_dev_timers clk_time;
	u32 hi, lo, offset_lo, offset_hi;
	enum idpf_ptp_access access;
	int err;

	access = adapter->ptp.get_dev_clk_time_access;
	if (access == IDPF_PTP_NONE) {
		return -EOPNOTSUPP;
	} else if (access == IDPF_PTP_MAILBOX) {
		/* Read the system timestamp pre PHC read */
		ptp_read_system_prets(sts);

		err = idpf_ptp_get_dev_clk_time(adapter, &clk_time);
		if (err)
			return err;

		/* Read the system timestamp post PHC read */
		ptp_read_system_postts(sts);

		*src_clk = clk_time.dev_clk_time_ns;
	} else {
		/* Get offsets */
		offset_lo = ptp->dev_clk_regs.dev_clk_ns_l;
		offset_hi = ptp->dev_clk_regs.dev_clk_ns_h;

		/* Read the system timestamp pre PHC read */
		ptp_read_system_prets(sts);

		idpf_ptp_enable_shtime(adapter);
		lo = readl(idpf_get_reg_addr(adapter, offset_lo));

		/* Read the system timestamp post PHC read */
		ptp_read_system_postts(sts);

		hi = readl(idpf_get_reg_addr(adapter, offset_hi));

		*src_clk = ((u64)hi << 32) | lo;
	}

	dev_dbg(idpf_adapter_to_dev(adapter), "Device clock time: %lld\n", *src_clk);

	return 0;
}

#ifdef HAVE_PTP_CROSSTIMESTAMP
/**
 * idpf_ptp_get_sync_device_time - Get the cross time stamp info
 * @device: Current device time
 * @system: System counter value read synchronously with device time
 * @ctx: Context provided by timekeeping code
 *
 * Read device and system (ART) clock simultaneously and return the corrected
 * clock values in ns.
 */
static int idpf_ptp_get_sync_device_time(ktime_t *device,
					 struct system_counterval_t *system,
					 void *ctx)
{
	struct idpf_adapter *adapter = ctx;
	u32 dev_time_lo, dev_time_hi, sys_time_lo, sys_time_hi;
	struct idpf_ptp_dev_timers cross_time;
	struct idpf_ptp *ptp = &adapter->ptp;
	u64 ns_time_dev, ns_time_sys = 0;
	enum idpf_ptp_access access;
	u32 offset_lo, offset_hi;
	int err = 0;

	access = adapter->ptp.get_cross_tstamp_access;
	if (access == IDPF_PTP_NONE) {
		return -EOPNOTSUPP;
	} else if (access == IDPF_PTP_MAILBOX) {
		err = idpf_ptp_get_cross_time(adapter, &cross_time);
		if (err)
			return err;

		ns_time_dev = cross_time.dev_clk_time_ns;
		ns_time_sys = cross_time.sys_time_ns;
	} else {
		idpf_ptp_enable_shtime(adapter);

		/* Get the device clock offsets */
		offset_lo = ptp->dev_clk_regs.dev_clk_ns_l;
		offset_hi = ptp->dev_clk_regs.dev_clk_ns_h;

		dev_time_lo = readl(idpf_get_reg_addr(adapter, offset_lo));
		dev_time_hi = readl(idpf_get_reg_addr(adapter, offset_hi));

		/* Get the system time offsets */
		offset_lo = ptp->dev_clk_regs.sys_time_ns_l;
		offset_hi = ptp->dev_clk_regs.sys_time_ns_h;

		sys_time_lo = readl(idpf_get_reg_addr(adapter, offset_lo));
		sys_time_hi = readl(idpf_get_reg_addr(adapter, offset_hi));

		ns_time_dev = (u64)dev_time_hi << 32;
		ns_time_dev |= dev_time_lo;

		ns_time_sys = (u64)sys_time_hi << 32;
		ns_time_sys |= sys_time_lo;
	}

	*device = ns_to_ktime(ns_time_dev);
#if IS_ENABLED(CONFIG_ARM_ARCH_TIMER)
	*system = arch_timer_wrap_counter(ns_time_sys);
#elif IS_ENABLED(CONFIG_PCIE_PTM)
	*system = convert_art_ns_to_tsc(ns_time_sys);
#endif /* CONFIG_ARM_ARCH_TIMER */

	return err;
}

/**
 * idpf_ptp_get_crosststamp - Capture a device cross timestamp
 * @info: the driver's PTP info structure
 * @cts: The memory to fill the cross timestamp info
 *
 * Capture a cross timestamp between the ART and the device PTP hardware
 * clock. Fill the cross timestamp information and report it back to the
 * caller.
 */
static int idpf_ptp_get_crosststamp(struct ptp_clock_info *info,
				    struct system_device_crosststamp *cts)
{
	struct idpf_adapter *adapter = idpf_ptp_info_to_adapter(info);

	return get_device_system_crosststamp(idpf_ptp_get_sync_device_time,
					     adapter, NULL, cts);
}

#endif /* HAVE_PTP_CROSSTIMESTAMP */
/**
 * idpf_ptp_update_cached_phctime - Update the cached PHC time values
 * @adapter: Driver specific private structure
 *
 * This function updates the system time values which are cached in the adapter
 * structure and the Rx rings.
 *
 * This function must be called periodically to ensure that the cached value
 * is never more than 2 seconds old.
 *
 * Note that the cached copy in the adapter PTP structure is always updated,
 * even if we can't update the copy in the Rx rings.
 *
 */
static int idpf_ptp_update_cached_phctime(struct idpf_adapter *adapter)
{
	struct idpf_q_grp q_grp;
	struct idpf_queue *rxq;
	int i, j, err;
	u64 systime;

	err = idpf_ptp_read_src_clk_reg(adapter, &systime, NULL);
	if (err)
		return -EACCES;

	/* Update the cached PHC time stored in the adapter structure */
	WRITE_ONCE(adapter->ptp.cached_phc_time, systime);
	WRITE_ONCE(adapter->ptp.cached_phc_jiffies, jiffies);

	idpf_for_each_vport(adapter, i) {
		struct idpf_vport *vport = adapter->vports[i];

		if (!vport || !vport->dflt_grp.q_grp.rxqs)
			continue;

		q_grp = vport->dflt_grp.q_grp;

		for (j = 0; j < q_grp.num_rxq; j++) {
			rxq = q_grp.rxqs[j];
			WRITE_ONCE(rxq->rx_cached_phctime, systime);
		}
	}

	return 0;
}

/**
 * idpf_ptp_gettimex64 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure to hold the current time value
 * @sts: Optional parameter for holding a pair of system timestamps from
 *       the system clock. Will be ignored if NULL is given.
 *
 * Read the device clock and return the correct value in ns, after converting it
 * into a timespec struct.
 */
static int idpf_ptp_gettimex64(struct ptp_clock_info *info,
			       struct timespec64 *ts,
			       struct ptp_system_timestamp *sts)
{
	struct idpf_adapter *adapter = idpf_ptp_info_to_adapter(info);
	u64 time_ns;
	int err;

	err = idpf_ptp_read_src_clk_reg(adapter, &time_ns, sts);
	if (err)
		return -EACCES;

	*ts = ns_to_timespec64(time_ns);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIMEX64
/**
 * idpf_ptp_gettime64 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int idpf_ptp_gettime64(struct ptp_clock_info *info,
			      struct timespec64 *ts)
{
	return idpf_ptp_gettimex64(info, ts, NULL);
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * idpf_ptp_gettime32 - Get the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the device clock and return the correct value on ns, after converting it
 * into a timespec struct.
 */
static int idpf_ptp_gettime32(struct ptp_clock_info *info, struct timespec *ts)
{
	struct timespec64 ts64;

	if (idpf_ptp_gettime64(info, &ts64))
		return -EFAULT;

	*ts = timespec64_to_timespec(ts64);

	return 0;
}

#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */
#endif /* !HAVE_PTP_CLOCK_INFO_GETTIMEX64 */
/**
 * idpf_ptp_settime64 - Set the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec64 structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int idpf_ptp_settime64(struct ptp_clock_info *info,
			      const struct timespec64 *ts)
{
	struct idpf_adapter *adapter = idpf_ptp_info_to_adapter(info);
	enum idpf_ptp_access access;
	int err;
	u64 ns;

	access = adapter->ptp.set_dev_clk_time_access;
	if (access != IDPF_PTP_MAILBOX)
		return -EOPNOTSUPP;

	ns = timespec64_to_ns(ts);

	err = idpf_ptp_set_dev_clk_time(adapter, ns);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to set the time\n");
		return err;
	}

	err = idpf_ptp_update_cached_phctime(adapter);
	if (err)
		dev_warn(idpf_adapter_to_dev(adapter),
			 "Unable to immediately update cached PHC time\n");

	return err;
}

#ifndef HAVE_PTP_CLOCK_INFO_GETTIME64
/**
 * idpf_ptp_settime32 - Set the time of the clock
 * @info: the driver's PTP info structure
 * @ts: timespec structure that holds the new time value
 *
 * Set the device clock to the user input value. The conversion from timespec
 * to ns happens in the write function.
 */
static int idpf_ptp_settime32(struct ptp_clock_info *info,
			      const struct timespec *ts)
{
	struct timespec64 ts64 = timespec_to_timespec64(*ts);

	return idpf_ptp_settime64(info, &ts64);
}

#endif /* !HAVE_PTP_CLOCK_INFO_GETTIME64 */
/**
 * idpf_ptp_adjtime_nonatomic - Do a non-atomic clock adjustment
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int idpf_ptp_adjtime_nonatomic(struct ptp_clock_info *info, s64 delta)
{
	struct timespec64 now, then;
	int ret;

	then = ns_to_timespec64(delta);
	ret = idpf_ptp_gettimex64(info, &now, NULL);
	if (ret)
		return ret;

	now = timespec64_add(now, then);

	return idpf_ptp_settime64(info, (const struct timespec64 *)&now);
}

/**
 * idpf_ptp_adjtime - Adjust the time of the clock by the indicated delta
 * @info: the driver's PTP info structure
 * @delta: Offset in nanoseconds to adjust the time by
 */
static int idpf_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct idpf_adapter *adapter = idpf_ptp_info_to_adapter(info);
	enum idpf_ptp_access access;
	int err;

	access = adapter->ptp.adj_dev_clk_time_access;
	if (access != IDPF_PTP_MAILBOX)
		return -EOPNOTSUPP;

	/* Hardware only supports atomic adjustments using signed 32-bit
	 * integers. For any adjustment outside this range, perform
	 * a non-atomic get->adjust->set flow.
	 */
	if (delta > S32_MAX || delta < S32_MIN) {
		dev_dbg(idpf_adapter_to_dev(adapter), "delta = %lld, adjtime non-atomic\n", delta);
		return idpf_ptp_adjtime_nonatomic(info, delta);
	}

	err = idpf_ptp_adj_dev_clk_time(adapter, delta);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to adjust the clock\n");
		return err;
	}

	err = idpf_ptp_update_cached_phctime(adapter);
	if (err)
		dev_warn(idpf_adapter_to_dev(adapter),
			 "Unable to immediately update cached PHC time\n");

	return err;
}

/**
 * idpf_ptp_adjfine - Adjust clock increment rate
 * @info: the driver's PTP info structure
 * @scaled_ppm: Parts per million with 16-bit fractional field
 *
 * Adjust the frequency of the clock by the indicated scaled ppm from the
 * base frequency.
 */
static int idpf_ptp_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	struct idpf_adapter *adapter = idpf_ptp_info_to_adapter(info);
	enum idpf_ptp_access access;
	u64 incval, diff;
	int err;

	access = adapter->ptp.adj_dev_clk_time_access;
	if (access != IDPF_PTP_MAILBOX)
		return -EOPNOTSUPP;

	incval = adapter->ptp.base_incval;

	diff = adjust_by_scaled_ppm(incval, scaled_ppm);

	err = idpf_ptp_adj_dev_clk_fine(adapter, diff);
	if (err)
		dev_err(idpf_adapter_to_dev(adapter),
			"Failed to adjust clock increment rate\n");

	return err;
}

#ifndef HAVE_PTP_CLOCK_INFO_ADJFINE
/**
 * idpf_ptp_adjfreq - Adjust the frequency of the clock
 * @info: the driver's PTP info structure
 * @ppb: Parts per billion adjustment from the base
 *
 * Adjust the frequency of the clock by the indicated parts per billion from the
 * base frequency.
 */
static int idpf_ptp_adjfreq(struct ptp_clock_info *info, s32 ppb)
{
	long scaled_ppm;

	/*
	 * We want to calculate
	 *    scaled_ppm = ppb * 2^16 / 1000
	 * which simplifies to
	 *    scaled_ppm = ppb * 2^13 / 125
	 */
	scaled_ppm = ((long)ppb << 13 / 125);

	return idpf_ptp_adjfine(info, scaled_ppm);
}

#endif /* HAVE_PTP_CLOCK_INFO_ADJFINE */
/**
 * idpf_ptp_verify_pin - Verify if pin supports requested pin function
 * @info: the driver's PTP info structure
 * @pin: Pin index
 * @func: Assigned function
 * @chan: Assigned channel
 */
static int idpf_ptp_verify_pin(struct ptp_clock_info *info, unsigned int pin,
			       enum ptp_pin_function func, unsigned int chan)
{
	return -EOPNOTSUPP;
}

/**
 * idpf_ptp_gpio_enable - Enable/disable ancillary features of PHC
 * @info: the driver's PTP info structure
 * @rq: The requested feature to change
 * @on: Enable/disable flag
 */
static int idpf_ptp_gpio_enable(struct ptp_clock_info *info,
				struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

/**
 * idpf_ptp_periodic_work - Scheduling PTP periodic work
 * @work: PTP work
 */
static void idpf_periodic_work(struct kthread_work *work)
{
	struct idpf_ptp *ptp = container_of(work, struct idpf_ptp, work.work);
	struct idpf_adapter *adapter;
	u32 err;

	adapter = container_of(ptp, struct idpf_adapter, ptp);

	err = idpf_ptp_update_cached_phctime(adapter);
	if (err)
		dev_warn(idpf_adapter_to_dev(adapter),
			 "Unable to immediately update cached PHC time\n");

	kthread_queue_delayed_work(ptp->kworker, &ptp->work,
				   msecs_to_jiffies(err ? 10 : 500));
}

/**
 * idpf_ptp_init_work - Initialize PTP work threads
 * @adapter: Driver specific private structure
 */
static int idpf_ptp_init_work(struct idpf_adapter *adapter)
{
	struct idpf_ptp *ptp = &adapter->ptp;
	struct kthread_worker *kworker;

	/* Do not initialize the PTP work if the device clock time cannot be
	 * read.
	 */
	if (adapter->ptp.get_dev_clk_time_access == IDPF_PTP_NONE)
		return 0;

	kthread_init_delayed_work(&ptp->work, idpf_periodic_work);

	kworker = kthread_create_worker(0, "idpf-ptp-%s",
					dev_name(idpf_adapter_to_dev(adapter)));

	if (IS_ERR(kworker))
		return PTR_ERR(kworker);

	ptp->kworker = kworker;
	kthread_queue_delayed_work(ptp->kworker, &ptp->work, 0);

	return 0;
}

/**
 * idpf_ptp_tstamp_extend_32b_to_64b - Convert a 32b nanoseconds Tx timestamp
 *				       to 64b
 * @cached_phc_time: recently cached copy of PHC time
 * @in_timestamp: Ingress/egress 32b nanoseconds timestamp value
 *
 * Hardware captures timestamps which contain only 32 bits of nominal
 * nanoseconds, as opposed to the 64bit timestamps that the stack expects.
 */
u64 idpf_ptp_tstamp_extend_32b_to_64b(u64 cached_phc_time, u32 in_timestamp)
{
	u32 delta, phc_lo;
	u64 ns;

	phc_lo = (u32)cached_phc_time;
	delta = (in_timestamp - phc_lo);

	if (delta > U32_MAX / 2) {
		delta = phc_lo - in_timestamp;
		ns = cached_phc_time - delta;
	} else {
		ns = cached_phc_time + delta;
	}

	return ns;
}

/**
 * idpf_ptp_extend_40b_ts - Convert a 40b timestamp to 64b nanoseconds
 * @adapter: Driver specific private structure
 * @in_tstamp: Ingress/egress timestamp value
 *
 * It is assumed that the caller verifies the timestamp is valid prior to
 * calling this function.
 *
 * Extract the 32bit nominal nanoseconds and extend them. Use the cached PHC
 * time stored in the device private PTP structure as the basis for timestamp
 * extension.
 */
u64 idpf_ptp_extend_ts(struct idpf_adapter *adapter, u32 in_tstamp)
{
	unsigned long discard_time;
	u64 ticks;

	discard_time = adapter->ptp.cached_phc_jiffies + msecs_to_jiffies(2000);

	if (time_is_before_jiffies(discard_time))
		return 0;

	ticks =  idpf_ptp_tstamp_extend_32b_to_64b(adapter->ptp.cached_phc_time,
						   in_tstamp);
	return ticks;
}

/**
 * idpf_ptp_request_ts - Request an available Tx timestamp index
 * @vport: Virtual port structure
 * @skb: The SKB to associate with this timestamp request
 *
 * Request tx timestamp index negotiated during PTP init that will be set into
 * Tx descriptor.
 *
 * Return -1 in case of no available indexes, otherwise return the index
 * that can be provided to Tx descriptor
 */
s8 idpf_ptp_request_ts(struct idpf_vport *vport, struct sk_buff *skb)
{
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp;
	struct list_head *head;
	u8 idx = -1;

	if (!vport->tx_tstamp_caps)
		return idx;

	head = &vport->tx_tstamp_caps->latches_free;

	if (list_empty(head))
		return idx;

	/* Get the index from the free latches list */
	mutex_lock(&vport->tx_tstamp_caps->lock_free);
	ptp_tx_tstamp = list_first_entry(head, struct idpf_ptp_tx_tstamp,
					 list_member);
	list_del(&ptp_tx_tstamp->list_member);
	mutex_unlock(&vport->tx_tstamp_caps->lock_free);

	ptp_tx_tstamp->skb = skb_get(skb);
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	/* Move the element to the used latches list */
	mutex_lock(&vport->tx_tstamp_caps->lock_in_use);
	list_add(&ptp_tx_tstamp->list_member,
		 &vport->tx_tstamp_caps->latches_in_use);
	mutex_unlock(&vport->tx_tstamp_caps->lock_in_use);

	return ptp_tx_tstamp->idx;
}

/**
 * idpf_set_rx_tstamp - Enable or disable Rx timestamping
 * @vport: Virtual port structure
 * @on: bool value for whether timestamps are enabled or disabled
 */
static void idpf_ptp_set_rx_tstamp(struct idpf_vport *vport, bool on)
{
	enum idpf_ptp_access access;
	u16 i;

	access = vport->adapter->ptp.tx_tstamp_access;
	if (access != IDPF_PTP_MAILBOX)
		return;

	for (i = 0; i < vport->dflt_grp.q_grp.num_rxq; i++)
		vport->dflt_grp.q_grp.rxqs[i]->ptp_rx = on;

	vport->tstamp_config.rx_filter = on ? HWTSTAMP_FILTER_ALL :
					      HWTSTAMP_FILTER_NONE;
}

/**
 * idpf_ptp_set_timestamp_mode - Setup driver for requested timestamp mode
 * @vport: Virtual port structure
 * @config: Hwtstamp settings requested or saved
 */
static int idpf_ptp_set_timestamp_mode(struct idpf_vport *vport,
				       struct hwtstamp_config *config)
{
	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		vport->tstamp_config.tx_type = HWTSTAMP_TX_OFF;
		break;
	case HWTSTAMP_TX_ON:
		vport->tstamp_config.tx_type = HWTSTAMP_TX_ON;
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		idpf_ptp_set_rx_tstamp(vport, false);
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
#ifdef HAVE_HWTSTAMP_FILTER_NTP_ALL
	case HWTSTAMP_FILTER_NTP_ALL:
#endif /* HAVE_HWTSTAMP_FILTER_NTP_ALL */
	case HWTSTAMP_FILTER_ALL:
		idpf_ptp_set_rx_tstamp(vport, true);
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

/**
 * idpf_ptp_set_ts_config - ioctl interface to control the timestamping
 * @vport: Virtual port structure
 * @ifr: ioctl data
 *
 * Get the user config and store it
 */
int idpf_ptp_set_ts_config(struct idpf_vport *vport, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = idpf_ptp_set_timestamp_mode(vport, &config);
	if (err)
		return err;

	config = vport->tstamp_config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ?
			    -EFAULT : 0;
}

/**
 * idpf_ptp_get_ts_config - ioctl interface to read the timestamping config
 * @vport: Virtual port structure
 * @ifr: ioctl data
 *
 * Copy the timestamping config to user buffer
 */
int idpf_ptp_get_ts_config(struct idpf_vport *vport, struct ifreq *ifr)
{
	struct hwtstamp_config *config;

	config = &vport->tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ?
			    -EFAULT : 0;
}

/**
 * idpf_ptp_set_caps - Set PTP capabilities
 * @adapter: Driver specific private structure
 *
 * This function sets the PTP functions
 */
static void idpf_ptp_set_caps(struct idpf_adapter *adapter)
{
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct ptp_clock_info *info = &adapter->ptp.info;

	snprintf(info->name, sizeof(info->name) - 1, "%s-%s-clk",
		 dev_driver_string(dev), dev_name(dev));

	info->max_adj = adapter->ptp.max_adj;
	info->owner = THIS_MODULE;
	info->adjtime = idpf_ptp_adjtime;
#ifdef HAVE_PTP_CLOCK_INFO_ADJFINE
	info->adjfine = idpf_ptp_adjfine;
#else
	info->adjfreq = idpf_ptp_adjfreq;
#endif /* HAVE_PTP_CLOCK_INFO_ADJFINE */
#ifdef HAVE_PTP_CLOCK_INFO_GETTIME64
	info->settime64 = idpf_ptp_settime64;
#else
	info->settime = idpf_ptp_settime32;
#endif /* HAVE_PTP_CLOCK_INFO_GETTIME64 */
	info->verify = idpf_ptp_verify_pin;
	info->enable = idpf_ptp_gpio_enable;

#if defined(HAVE_PTP_CLOCK_INFO_GETTIMEX64)
	info->gettimex64 = idpf_ptp_gettimex64;
#elif defined(HAVE_PTP_CLOCK_INFO_GETTIME64)
	info->gettime64 = idpf_ptp_gettime64;
#else
	info->gettime = idpf_ptp_gettime32;
#endif
#ifdef HAVE_PTP_CROSSTIMESTAMP
#if IS_ENABLED(CONFIG_ARM_ARCH_TIMER)
	info->getcrosststamp = idpf_ptp_get_crosststamp;
#elif IS_ENABLED(CONFIG_PCIE_PTM)
	if (pcie_ptm_enabled(adapter->pdev) &&
	    boot_cpu_has(X86_FEATURE_ART) &&
	    boot_cpu_has(X86_FEATURE_TSC_KNOWN_FREQ)) {
		info->getcrosststamp = idpf_ptp_get_crosststamp;
	} else {
		dev_dbg(idpf_adapter_to_dev(adapter), "PTM not enabled\n");
	}

#endif /* CONFIG_ARM_ARCH_TIMER */
#endif /* HAVE_PTP_CROSSTIMESTAMP */
}

/**
 * idpf_ptp_create_clock - Create PTP clock device for userspace
 * @adapter: Driver specific private structure
 *
 * This function creates a new PTP clock device.
 */
static int idpf_ptp_create_clock(struct idpf_adapter *adapter)
{
	struct ptp_clock *clock;

	/* No need to create a clock device if we already have one */
	if (adapter->ptp.clock)
		return 0;

	idpf_ptp_set_caps(adapter);

	/* Attempt to register the clock before enabling the hardware. */
	clock = ptp_clock_register(&adapter->ptp.info,
				   idpf_adapter_to_dev(adapter));
	if (IS_ERR_OR_NULL(clock)) {
		dev_err(idpf_adapter_to_dev(adapter), "PTP clock creation failed\n");
		return -EPERM;
	}

	adapter->ptp.clock = clock;

	return 0;
}

/**
 * idpf_ptp_release_tstamp - Release the Tx timestamps trackers
 * @adapter: Driver specific private structure
 *
 * Remove the queues and delete lists that tracks Tx timestamp entries for the
 * specific vport.
 */
static void idpf_ptp_release_tstamp(struct idpf_adapter *adapter)
{
	struct idpf_ptp_tx_tstamp *ptp_tx_tstamp, *tmp;
	struct list_head *head;
	int i;

	idpf_for_each_vport(adapter, i) {
		struct idpf_vport *vport = adapter->vports[i];

		if (!vport || !vport->tx_tstamp_caps)
			continue;

		cancel_work_sync(&vport->tstamp_task);

		/* Remove list with free latches */
		mutex_lock(&vport->tx_tstamp_caps->lock_free);

		head = &vport->tx_tstamp_caps->latches_free;
		list_for_each_entry_safe(ptp_tx_tstamp, tmp, head, list_member) {
			list_del(&ptp_tx_tstamp->list_member);
			kfree(ptp_tx_tstamp);
		}

		mutex_unlock(&vport->tx_tstamp_caps->lock_free);
		mutex_destroy(&vport->tx_tstamp_caps->lock_free);

		/* Remove list with latches in use */
		mutex_lock(&vport->tx_tstamp_caps->lock_in_use);

		head = &vport->tx_tstamp_caps->latches_in_use;
		list_for_each_entry_safe(ptp_tx_tstamp, tmp, head, list_member) {
			list_del(&ptp_tx_tstamp->list_member);
			kfree(ptp_tx_tstamp);
		}

		mutex_unlock(&vport->tx_tstamp_caps->lock_in_use);
		mutex_destroy(&vport->tx_tstamp_caps->lock_in_use);

		kfree(vport->tx_tstamp_caps->tx_tstamp_status);
		kfree(vport->tx_tstamp_caps);
	}
}

/**
 * idpf_ptp_init - Initialize PTP hardware clock support
 * @adapter: Driver specific private structure
 *
 * Set up the device for interacting with the PTP hardware clock for all
 * functions. Function will allocate and register a ptp_clock with the
 * PTP_1588_CLOCK infrastructure.
 */
int idpf_ptp_init(struct idpf_adapter *adapter)
{
	struct timespec64 ts;
	int err = 0;

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_PTP)) {
		dev_dbg(idpf_adapter_to_dev(adapter), "PTP capability not detected\n");
		return err;
	}

	err = idpf_ptp_get_caps(adapter);
	if (err) {
		dev_err(idpf_adapter_to_dev(adapter), "Failed to get PTP caps\n");
		return err;
	}

	if (adapter->dev_ops.reg_ops.ptp_reg_init)
		adapter->dev_ops.reg_ops.ptp_reg_init(adapter);

	err = idpf_ptp_create_clock(adapter);
	if (err) {
		dev_info(idpf_adapter_to_dev(adapter), "Failed to create the PTP clock\n");
		return err;
	}

	err = idpf_ptp_init_work(adapter);
	if (err) {
		dev_info(idpf_adapter_to_dev(adapter), "Cannot init PTP work\n");
		goto remove_clock;
	}

	/* Write the default increment time value if the clock adjustments
	 * are enabled
	 */
	if (adapter->ptp.adj_dev_clk_time_access != IDPF_PTP_NONE) {
		err = idpf_ptp_adj_dev_clk_fine(adapter, adapter->ptp.base_incval);
		if (err)
			goto release;
	}

	/* Write the initial time value if the set time operation is enabled */
	if (adapter->ptp.set_dev_clk_time_access != IDPF_PTP_NONE) {
		ts = ktime_to_timespec64(ktime_get_real());
		err = idpf_ptp_settime64(&adapter->ptp.info, &ts);
		if (err)
			goto release;
	}

	if (!err)
		dev_info(idpf_adapter_to_dev(adapter), "PTP init successful\n");
	else
		dev_err(idpf_adapter_to_dev(adapter), "PTP init failed, err=%d\n", err);

	return err;

release:
	kthread_cancel_delayed_work_sync(&adapter->ptp.work);
remove_clock:
	if (adapter->ptp.clock) {
		ptp_clock_unregister(adapter->ptp.clock);
		adapter->ptp.clock = NULL;
		memset(&adapter->ptp.info, 0, sizeof(adapter->ptp.info));
	}

	return err;
}

/**
 * idpf_ptp_release - Clear PTP hardware clock support
 * @adapter: Driver specific private structure
 */
void idpf_ptp_release(struct idpf_adapter *adapter)
{
	if (adapter->ptp.get_dev_clk_time_access != IDPF_PTP_NONE)
		kthread_cancel_delayed_work_sync(&adapter->ptp.work);

	if (adapter->ptp.tx_tstamp_access != IDPF_PTP_NONE)
		idpf_ptp_release_tstamp(adapter);

	if (adapter->ptp.clock) {
		ptp_clock_unregister(adapter->ptp.clock);
		adapter->ptp.clock = NULL;
		memset(&adapter->ptp.info, 0, sizeof(adapter->ptp.info));
	}
}
