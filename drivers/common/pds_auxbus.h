/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Pensando Systems, Inc */


#ifndef _PDSC_AUXBUS_H_
#define _PDSC_AUXBUS_H_

#include <linux/auxiliary_bus.h>

struct pds_auxiliary_dev;

struct pds_auxiliary_drv {

	/* .event_handler() - callback for receiving events
	 * padev:  ptr to the client device info
	 * event:  ptr to event data
	 * The client can provide an event handler callback that can
	 * receive DSC events.  The Core driver may generate its
	 * own events which can notify the client of changes in the
	 * DSC status, such as a RESET event generated when the Core
	 * as lost contact with the FW - in this case the event.eid
	 * field will be 0.
	 */
	void (*event_handler)(struct pds_auxiliary_dev *padev,
			      union pds_core_notifyq_comp *event);
};

struct pds_auxiliary_dev {
	struct auxiliary_device aux_dev;
	struct pds_core_ops *ops;
	struct pci_dev *pcidev;
	u32 id;
	u16 client_id;
	void (*event_handler)(struct pds_auxiliary_dev *padev,
			      union pds_core_notifyq_comp *event);
	void *priv;
};

struct pds_fw_state {
	unsigned long last_fw_time;
	u32 fw_heartbeat;
	u8  fw_status;
};

/*
 *   ptrs to functions to be used by the client for core services
 */
struct pds_core_ops {

	/* .register() - register the client with the device
	 * padev:  ptr to the client device info
	 * padrv:  ptr to the client driver info
	 * Register the client with the core and with the DSC.  The core
	 * will fill in the client padrv->client_id for use in calls
	 * to the DSC AdminQ
	 */
	int (*register_client)(struct pds_auxiliary_dev *padev,
			       struct pds_auxiliary_drv *padrv);

	/* .unregister() - disconnect the client from the device
	 * padev:  ptr to the client device info
	 * Disconnect the client from the core and with the DSC.
	 */
	int (*unregister_client)(struct pds_auxiliary_dev *padev);

	/* .adminq_cmd() - process an adminq request for the client
	 * padev:  ptr to the client device
	 * adminq_id: use 0 for default adminq, or use an adminq_id
	 *            returned by new_adminq()
	 * req:     ptr to buffer with request
	 * req_len: length of actual struct used for request
	 * resp:    ptr to buffer where answer is to be copied
	 * comp_cb: ptr to callback for signaling async request is
	 *          completed.  If NULL, the request is synchronous,
	 *          else it will be an asynchronous call.
	 * data:    opaque cookie to be passed to comp_cb
	 * flags:   optional flags defined by enum pds_core_adminq_flags
	 *	    and used for more flexible adminq behvior
	 *
	 * returns 0 on success of a synchronous call (NULL comp_cb),
	 *         positive comp_id value for asynchronous call, or
	 *         negative for error
	 * Client sends pointers to request and response buffers
	 * Core copies request data into pds_core_client_request_cmd
	 * Core sets other fields as needed
	 * Core posts to AdminQ
	 * Core copies completion data into response buffer
	 * Core either returns (synchronous) or calls comp_cb to
	 *   signal asynchronous completion
	 */
	int (*adminq_cmd)(struct pds_auxiliary_dev *padev,
			  u8 adminq_id,
			  union pds_core_adminq_cmd *req,
			  size_t req_len,
			  union pds_core_adminq_comp *resp,
			  pds_core_cb comp_cb, void *data,
			  u64 flags);

	/* .request_irq() - request an interrupt vector on the core device
	 * padev:     ptr to the client device
	 * name:      ptr to interrupt name string
	 * handler:   ptr to the client handler for interrupt processing
	 * data:      a cookie passed to the handler function
	 * intr_ctrl: ptr to store the DMA of the interrupt control block
	 * return a positive interrupt index or negative error code
	 */
	int (*request_irq)(struct pds_auxiliary_dev *padev,
			   char *name,
			   irq_handler_t handler,
			   void *data,
			   struct pds_core_intr __iomem **intr_ctrl);

	/* .free_irq() - client frees the interrupt resource
	 * padev:   ptr to the client device
	 * irq:     interrupt index
	 */
	int (*free_irq)(struct pds_auxiliary_dev *padev,
			unsigned int irq);


	/* .new_adminq() - request a new separate adminq
	 * padev:   ptr to the client device
	 * length: adminq descriptor length
	 * adminq_option_flags: selects RDMA or other AdminQ specific needs
	 * name: name for the AdminQ
	 * returns an adminq_id to be used in adminq_cmd() requests
	 * or negative error code
	 */
	int (*new_adminq)(struct pds_auxiliary_dev *padev,
			  unsigned int length,
			  u32 adminq_option_flags,
			  const char *name);

	/* .free_adminq() - free the indicated adminq
	 * padev:  ptr to the client device
	 * adminq_id: use 0 for default adminq, or use an adminq_id
	 *            returned by new_adminq()
	 */
	int (*free_adminq)(struct pds_auxiliary_dev *padev,
			   uint adminq_id);

	/* .fw_state() - get current firmware running/stopped state
	 * padev:   ptr to the client device
	 * fws:     ptr to state structure
	 * returns FW state
	 */
	int (*fw_state)(struct pds_auxiliary_dev *padev,
			struct pds_fw_state *fws);

};

#endif /* _PDSC_AUXBUS_H_ */
