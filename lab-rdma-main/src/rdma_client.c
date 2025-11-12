#include "rdma_common.h"


/* This section declared some variables that might be helpful for RDMA
 * You do not need to use all of them, and feel free to add/remove anything you want
 */

/* These are basic RDMA resources */
/* These are RDMA connection related resources */
static struct rdma_event_channel *cm_event_channel = NULL;
static struct rdma_cm_id *cm_client_id = NULL;
static struct ibv_pd *pd = NULL;
static struct ibv_comp_channel *io_completion_channel = NULL;
static struct ibv_cq *client_cq = NULL;
static struct ibv_qp_init_attr qp_init_attr;
static struct ibv_qp *client_qp;
/* These are memory buffers related resources */
static struct ibv_mr *client_metadata_mr = NULL, 
		     *client_src_mr = NULL, 
		     *client_dst_mr = NULL, 
		     *server_metadata_mr = NULL,
			 *ctrl_recv_mr = NULL;
static struct rdma_buffer_attr client_metadata_attr, server_metadata_attr;
static void* ctrl_recv_buf;
static struct ibv_send_wr client_send_wr, *bad_client_send_wr = NULL;
static struct ibv_recv_wr server_recv_wr, *bad_server_recv_wr = NULL, ctrl_recv_wr, *ctrl_bad_recv = NULL;
static struct ibv_sge client_send_sge, server_recv_sge, ctrl_recv_sge;
/* Source file management */
static char *src = NULL, *dst = NULL; 
static uint64_t file_len = 0;
static uint8_t *src_file = NULL;
static int src_fd = -1; 
static const char *student_id = NULL;


enum { WRITE_CHUNK = 256 * 1024 };
enum { WRITE_WINDOW = 32 };

#define WRID_WRITE_TAG  100

/* This function prepares client side connection resources for an RDMA connection */
static int client_prepare_connection(struct sockaddr_in *s_addr)
{
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	/*  Open a channel used to report asynchronous communication event */
	cm_event_channel = rdma_create_event_channel();
	if (!cm_event_channel) {
		rdma_error("Creating cm event channel failed, errno: %d \n", -errno);
		return -errno;
	}
	debug("RDMA CM event channel is created at : %p \n", cm_event_channel);
	/* Create rdma_cm_id, the connection identifier (like socket) which is used 
	 * to define an RDMA connection. 
	 */
	ret = rdma_create_id(cm_event_channel, &cm_client_id, NULL, RDMA_PS_TCP);
	if (ret) {
		rdma_error("Creating cm id failed with errno: %d \n", -errno); 
		return -errno;
	}
	/* Resolve destination and optional source addresses from IP addresses  to
	 * an RDMA address.  If successful, the specified rdma_cm_id will be bound
	 * to a local device. */
	ret = rdma_resolve_addr(cm_client_id, NULL, (struct sockaddr *)s_addr, 2000);
	if (ret) {
		rdma_error("Failed to resolve address, errno: %d \n", -errno);
		return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ADDR_RESOLVED\n");
	ret  = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ADDR_RESOLVED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to receive a valid event, ret = %d \n", ret);
		return ret;
	}
	/* we ack the event */
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge the CM event, errno: %d\n", -errno);
		return -errno;
	}
	debug("RDMA address is resolved \n");

	 /* Resolves an RDMA route to the destination address in order to 
	  * establish a connection */
	ret = rdma_resolve_route(cm_client_id, 2000);
	if (ret) {
		rdma_error("Failed to resolve route, erno: %d \n", -errno);
	       return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ROUTE_RESOLVED\n");
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ROUTE_RESOLVED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to receive a valid event, ret = %d \n", ret);
		return ret;
	}
	/* we ack the event */
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge the CM event, errno: %d \n", -errno);
		return -errno;
	}
	printf("Trying to connect to server at : %s port: %d \n", 
			inet_ntoa(s_addr->sin_addr),
			ntohs(s_addr->sin_port));
	/* Protection Domain (PD) is similar to a "process abstraction" 
	 * in the operating system. All resources are tied to a particular PD. 
	 * And accessing recourses across PD will result in a protection fault.
	 */
	pd = ibv_alloc_pd(cm_client_id->verbs);
	if (!pd) {
		rdma_error("Failed to alloc pd, errno: %d \n", -errno);
		return -errno;
	}
	debug("pd allocated at %p \n", pd);
	/* Now we need a completion channel, were the I/O completion 
	 * notifications are sent. This is different from connection 
	 * management (CM) event notifications. 
	 * A completion channel is also tied to an RDMA device, hence we will 
	 * use cm_client_id->verbs. 
	 */
	io_completion_channel = ibv_create_comp_channel(cm_client_id->verbs);
	if (!io_completion_channel) {
		rdma_error("Failed to create IO completion event channel, errno: %d\n",
			       -errno);
	return -errno;
	}
	debug("completion event channel created at : %p \n", io_completion_channel);
	/* Now we create a completion queue (CQ) where actual I/O 
	 * completion metadata is placed. The metadata is packed into a structure 
	 * called struct ibv_wc (wc = work completion).
	 */
	client_cq = ibv_create_cq(cm_client_id->verbs, CQ_CAPACITY, NULL, io_completion_channel, 0);
	if (!client_cq) {
		rdma_error("Failed to create CQ, errno: %d \n", -errno);
		return -errno;
	}
	debug("CQ created at %p with %d elements \n", client_cq, client_cq->cqe);
	/*tell CQ that we want notification*/
	ret = ibv_req_notify_cq(client_cq, 0);
	if (ret) {
		rdma_error("Failed to request notifications, errno: %d\n", -errno);
		return -errno;
	}
       /* Set up the queue pair (send, recv) queues and their capacity.
         * The capacity here is define statically but this can be probed from the 
	 * device. We just use a small number as defined in rdma_common.h */
       bzero(&qp_init_attr, sizeof qp_init_attr);
       qp_init_attr.cap.max_recv_sge = MAX_SGE; /* Maximum SGE per receive posting */
       qp_init_attr.cap.max_recv_wr = MAX_WR; /* Maximum receive posting capacity */
       qp_init_attr.cap.max_send_sge = MAX_SGE; /* Maximum SGE per send posting */
       qp_init_attr.cap.max_send_wr = MAX_WR; /* Maximum send posting capacity */
       qp_init_attr.qp_type = IBV_QPT_RC; /* QP type, RC = Reliable connection */
       /* We use same completion queue, but one can use different queues */
       qp_init_attr.recv_cq = client_cq; /* Where should I notify for receive completion operations */
       qp_init_attr.send_cq = client_cq; /* Where should I notify for send completion operations */
       /*Lets create a QP */
       ret = rdma_create_qp(cm_client_id, pd, &qp_init_attr);
	if (ret) {
		rdma_error("Failed to create QP, errno: %d \n", -errno);
	       return -errno;
	}
	/*assign it to a variable*/
	client_qp = cm_client_id->qp;
	debug("QP created at %p \n", client_qp);
	return 0;
}

/* Pre-posts receive buffers before calling rdma_connect () */
static int client_pre_post_recv_buffer()
{
	/* We first pre-post receive buffer for server file MR attributes*/
	int ret = -1;
	server_metadata_mr = rdma_buffer_alloc(pd, sizeof(struct rdma_buffer_attr), IBV_ACCESS_LOCAL_WRITE);
	if(!server_metadata_mr){
		rdma_error("Failed to setup the server metadata mr , -ENOMEM\n");
		return -ENOMEM;
	}
	server_recv_sge.addr = (uint64_t) server_metadata_mr->addr;
	server_recv_sge.length = (uint32_t) server_metadata_mr->length;
	server_recv_sge.lkey = (uint32_t) server_metadata_mr->lkey;
	/* now we link it to the request */
	bzero(&server_recv_wr, sizeof(server_recv_wr));
	server_recv_wr.wr_id = 0; // For this lab, wr_id is not important for client since we know which WC we are expecting logically
	server_recv_wr.sg_list = &server_recv_sge;
	server_recv_wr.num_sge = 1;
	ret = ibv_post_recv(client_qp, &server_recv_wr, &bad_server_recv_wr);
	if (ret) {
		rdma_error("Failed to pre-post the receive buffer, errno: %d \n", ret);
		return ret;
	}


	/* Create CTRL MR similarly */
	ctrl_recv_buf = calloc(1, CTRL_MAX);
	ctrl_recv_mr = rdma_buffer_register(pd, ctrl_recv_buf, CTRL_MAX, IBV_ACCESS_LOCAL_WRITE);
	if (!ctrl_recv_mr) {
		rdma_error("Failed to setup the ctrl recv mr , -ENOMEM\n");
		return -ENOMEM;
	}
	ctrl_recv_sge.addr   = (uintptr_t) ctrl_recv_mr->addr;
    ctrl_recv_sge.length = CTRL_MAX;
    ctrl_recv_sge.lkey   = ctrl_recv_mr->lkey;
	bzero(&ctrl_recv_wr, sizeof(ctrl_recv_wr));
	ctrl_recv_wr.wr_id = 0xABC00001;
	ctrl_recv_wr.sg_list = &ctrl_recv_sge;
	ctrl_recv_wr.num_sge = 1;
	ret = ibv_post_recv(client_qp, &ctrl_recv_wr, &ctrl_bad_recv);
	if (ret) { fprintf(stderr, "client post ctrl recv failed: %d\n", ret); return ret; }
	
	return 0;
}

/* Connects to the RDMA server */
static int client_connect_to_server() 
{
	struct rdma_conn_param conn_param;
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	bzero(&conn_param, sizeof(conn_param));
	conn_param.initiator_depth = 3;
	conn_param.responder_resources = 3;
	conn_param.retry_count = 3; // if fail, then how many times to retry
	ret = rdma_connect(cm_client_id, &conn_param);
	if (ret) {
		rdma_error("Failed to connect to remote host , errno: %d\n", -errno);
		return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ESTABLISHED\n");
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ESTABLISHED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to get cm event, ret = %d \n", ret);
	       return ret;
	}
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge cm event, errno: %d\n", 
			       -errno);
		return -errno;
	}
	printf("The client is connected successfully \n");
	return 0;
}

static int client_send_msg_req()
{
	uint8_t digest[32];
	int ret = -1;

	/* We read file using mmap, works nicely with RDMA syntax */
	src_fd = open(src, O_RDONLY);
	if (src_fd < 0) {
        perror("open");
        return -1;
    }

	struct stat st;
    if (fstat(src_fd, &st) != 0) {
        perror("fstat");
        close(src_fd); src_fd = -1;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        rdma_error("Not a regular file\n");
        close(src_fd); src_fd = -1;
        return -1;
    }
    if (st.st_size <= 0) {
        rdma_error("Empty file\n");
        close(src_fd); src_fd = -1;
        return -1;
    }

	file_len = st.st_size;
	src_file = (uint8_t*)mmap(NULL, file_len, PROT_READ, MAP_PRIVATE, src_fd, 0);
    if (src_file == MAP_FAILED) {
        perror("mmap");
        close(src_fd); src_fd = -1;
        src_file = NULL; file_len = 0;
        return -1;
    }

	(void)madvise(src_file, file_len, MADV_SEQUENTIAL);

	// Compute the sha256 of the provided file
	if (sha256_buf(src_file, file_len, digest) != 0) {
        rdma_error("sha256_buf failed\n");
        munmap(src_file, file_len); src_file = NULL; file_len = 0;
        close(src_fd); src_fd = -1;
        return -1;
    }

	/* Create MSG_REQ and send it */
	uint8_t req_blob[sizeof(struct ctrl_hdr) + sizeof(struct msg_req)];
	struct ctrl_hdr *h = (struct ctrl_hdr *)req_blob;
	struct msg_req  *p = (struct msg_req *)(req_blob + sizeof(*h));
	h->type = MSG_REQ;
	h->len  = sizeof(struct msg_req);
	p->file_len = file_len;
	memcpy(p->sha256, digest, 32);

	// Post the send wr
	struct ibv_mr *req_mr = rdma_buffer_register(pd, req_blob, sizeof(req_blob), IBV_ACCESS_LOCAL_WRITE);
	if (!req_mr) {
		rdma_error("Failed to register req_blob MR\n");
		return -ENOMEM;
	}
	struct ibv_sge send_sge = {
    	.addr   = (uintptr_t)req_mr->addr,
    	.length = sizeof(req_blob),
    	.lkey   = req_mr->lkey
		};
	struct ibv_send_wr swr = {0}, *bad_swr = NULL;
	swr.wr_id      = 0xABC10001;
	swr.sg_list    = &send_sge;
	swr.num_sge    = 1;
	swr.opcode     = IBV_WR_SEND;
	swr.send_flags = IBV_SEND_SIGNALED;
	ret = ibv_post_send(client_qp, &swr, &bad_swr);
	if (ret) { 
		fprintf(stderr, "client send REQ failed: %d\n", ret); 
		ibv_dereg_mr(req_mr);
		return ret; 
	}

	/* Here we process two completion event together: send completion and server metadata recv*/
	struct ibv_wc wc[2];
	ret = process_work_completion_events(io_completion_channel, 
			wc, 2);
	if(ret != 2) {
		rdma_error("We failed to get 2 work completions , ret = %d \n",
				ret);
		ibv_dereg_mr(req_mr);
		return ret;
	}
	
	/* Copy server metadata from receive buffer */
	memcpy(&server_metadata_attr, server_metadata_mr->addr, sizeof(struct rdma_buffer_attr));
	
	ibv_dereg_mr(req_mr);
	
	printf("Client: sent MSG_REQ (file_len=%lu, sha256=\n", (unsigned long)file_len);
	for (int k = 0; k < 32; k++) fprintf(stdout, "%02x", p->sha256[k]);
                        fprintf(stdout, "\n");
	
	debug("Server sent us its buffer location and credentials, showing \n");
	show_rdma_buffer_attr(&server_metadata_attr);
	
	return 0;
}

/* Only polling 1 cqe, useful for bulk write*/
static int poll_one_cqe(struct ibv_cq *cq, struct ibv_wc *wc) {
    for (;;) {
        int n = ibv_poll_cq(cq, 1, wc);
        if (n < 0) return n;
        if (n == 1) return 1;
    }
}

/* This function does :
 * 1) Prepare memory buffers for RDMA operations 
 * 1) RDMA write from src -> remote buffer 
 */ 
static int client_write_file() 
{
	struct ibv_wc wc;
	int ret = -1;
	client_src_mr = rdma_buffer_register(pd,
			src_file,
			file_len,
			0);
	if (!client_src_mr) {
    	rdma_error("client: reg src MR failed\n");
		munmap(src_file, file_len); src_file = NULL; file_len = 0;
        close(src_fd); src_fd = -1;
    	return -1;
	}
	const uint64_t remote_base = server_metadata_attr.address;
    const uint32_t remote_len  = server_metadata_attr.length;
    const uint32_t remote_rkey = server_metadata_attr.stag.remote_stag;

	if (file_len > remote_len) {
        rdma_error("server MR too small");
        return -1;
    }

	size_t off = 0;
	int inflight = 0;
	int wr_index = 0;

	 while (off < file_len) {
		/* Write window */
		if (inflight >= WRITE_WINDOW) {
			struct ibv_wc wc;
			int ret = process_work_completion_events(io_completion_channel, &wc, 1);
			if (ret != 1) { rdma_error("client: poll send cqe err %d\n", ret); return ret; }
			if (wc.opcode == IBV_WC_RDMA_WRITE) {
                inflight--;
            }
            continue;
		}
		
		size_t remain = file_len - off;
		
		uint32_t chunk = (remain > WRITE_CHUNK) ? WRITE_CHUNK : (uint32_t)remain;

		struct ibv_sge sge = {
            .addr   = (uintptr_t)((uint8_t*)client_src_mr->addr + off),
            .length = chunk,
            .lkey   = client_src_mr->lkey
        };

		/* Create and post direct write WR*/
		struct ibv_send_wr wr = {0}, *bad = NULL;
        wr.wr_id                 = WRID_WRITE_TAG;
        wr.sg_list               = &sge;
        wr.num_sge               = 1;
        wr.opcode                = IBV_WR_RDMA_WRITE; //Directly write to remote memory
        wr.send_flags            = IBV_SEND_SIGNALED; //signal every write
        wr.wr.rdma.remote_addr   = remote_base + off;
        wr.wr.rdma.rkey          = remote_rkey;
		ret = ibv_post_send(client_qp, &wr, &bad);
		if (ret) {
            rdma_error("ibv_post_send RDMA_WRITE failed: %d\n", ret);
            return ret;
        }
		printf("Remain: %zu\n", remain);
		inflight++;
		off += chunk;
	 }

	 /* handle remaining inflight write */
	 while (inflight > 0) {
        struct ibv_wc wc;
    	int ret = poll_one_cqe(client_cq, &wc);
    	if (ret != 1) { rdma_error("poll err %d\n", ret); return ret; }
    	if (wc.status != IBV_WC_SUCCESS)
    	    return -(wc.status);
    	if (wc.opcode == IBV_WC_RDMA_WRITE || wc.opcode == IBV_WC_SEND)
    	    inflight--;
    }

	printf("Client: RDMA WRITE completed (%zu bytes)\n", (size_t)file_len);

	/* Send MSG_DONE to server */
	struct {
        struct ctrl_hdr h;
        // no payload
    } __attribute__((packed)) msg;

	msg.h.type = MSG_DONE;
    msg.h.len  = 0;

	/* Create and post MSG_DONE */
	struct ibv_mr *mr = rdma_buffer_register(pd, &msg, sizeof(msg), IBV_ACCESS_LOCAL_WRITE);
	if (!mr) { rdma_error("client: reg DONE mr failed\n"); return -1; }
	struct ibv_sge sge = {
        .addr   = (uintptr_t)mr->addr,
        .length = sizeof(msg),
        .lkey   = mr->lkey
    };

	struct ibv_send_wr swr = {0}, *bad = NULL;
    swr.wr_id      = 0xD0D0D0D0ull;
    swr.sg_list    = &sge;
    swr.num_sge    = 1;
    swr.opcode     = IBV_WR_SEND;
    swr.send_flags = IBV_SEND_SIGNALED;

    ret = ibv_post_send(client_qp, &swr, &bad);
    if (ret) { rdma_error("client: post SEND DONE failed %d\n", ret); return ret; }

    ret = process_work_completion_events(io_completion_channel, &wc, 1);
    if (ret != 1 || wc.opcode != IBV_WC_SEND) {
        rdma_error("client: DONE send completion err (ret=%d, opcode=%d)\n", ret, (int)wc.opcode);
        return -1;
    }

	ibv_dereg_mr(mr);

    printf("Client: sent MSG_DONE\n");
    return 0;
}

/* Wait for server MSG_VERDICT*/
static int client_wait_verdict() {
    struct ibv_wc wc;
    int ret = process_work_completion_events(io_completion_channel, &wc, 1);
    if (ret != 1) return ret;
    if (wc.opcode != IBV_WC_RECV) return -1;
    uint8_t *buf = (uint8_t*)ctrl_recv_buf; 
    uint32_t blen = wc.byte_len;
    if (blen >= sizeof(struct ctrl_hdr)) {
        struct ctrl_hdr *h = (struct ctrl_hdr*)buf;
        if (h->type == MSG_VERDICT && h->len == sizeof(struct msg_verdict) &&
            blen >= sizeof(*h) + sizeof(struct msg_verdict)) {
            struct msg_verdict *v = (struct msg_verdict*)(buf + sizeof(*h));
            printf("Client: verdict code=%u (%s)\n", v->code, v->code == 0 ? "OK" : "FAIL");
            
			// Repost CTRL RECV WR. We need to reuse CTRL MR for future CTRL messages
			int r = ibv_post_recv(client_qp, &ctrl_recv_wr, &ctrl_bad_recv);
    		if (r) fprintf(stderr, "client: repost ctrl recv failed: %d\n", r);
            return (v->code == 0) ? 0 : 1;
        }
    }

	return 0;
	
}

/* Send ID */
static int client_send_id()
{
	if (!student_id) { rdma_error("no -i <id>\n"); return -EINVAL; }
    const uint16_t id_len = (uint16_t)strlen(student_id);
	printf("Client sends ID: %s\n", (const char*)student_id);

	uint8_t blob[sizeof(struct ctrl_hdr) + MAX_ID_LEN];
	struct ctrl_hdr *h = (struct ctrl_hdr*)blob;
    h->type = MSG_ID;
    h->len  = id_len;
    memcpy(blob + sizeof(*h), student_id, id_len);

	/* Create and post MSG_ID */
	struct ibv_mr *mr = rdma_buffer_register(pd, blob, sizeof(*h) + id_len, IBV_ACCESS_LOCAL_WRITE);
	if (!mr) { rdma_error("client: reg ID mr failed\n"); return -1; }

	struct ibv_sge sge = { .addr=(uintptr_t)mr->addr, .length=(uint32_t)(sizeof(*h)+id_len), .lkey=mr->lkey };
    struct ibv_send_wr swr = {0}, *bad=NULL;
	swr.wr_id = 200;
	swr.sg_list = &sge; 
	swr.num_sge = 1;
	swr.opcode = IBV_WR_SEND;
	swr.send_flags = IBV_SEND_SIGNALED;

	int ret = ibv_post_send(client_qp, &swr, &bad);
    if (ret) { rdma_error("client: post MSG_ID failed %d\n", ret); ibv_dereg_mr(mr); return ret; }

	struct ibv_wc wc;
    ret = process_work_completion_events(io_completion_channel, &wc, 1);
    ibv_dereg_mr(mr);
    if (ret != 1 || wc.status != IBV_WC_SUCCESS || wc.opcode != IBV_WC_SEND) {
        rdma_error("client: MSG_ID send completion err\n"); return -1;
    }
    return 0;
}

/* Wait for server to send MSG_HASH*/
static int client_wait_hash(){
	struct ibv_wc wc;
	int ret = process_work_completion_events(io_completion_channel, &wc, 1);
	if (ret != 1) return ret;
	if (wc.opcode != IBV_WC_RECV) return -1;
	uint8_t *buf = (uint8_t*)ctrl_recv_buf;
    uint32_t blen = wc.byte_len;
    if (blen >= sizeof(struct ctrl_hdr)) {
        struct ctrl_hdr *h = (struct ctrl_hdr*)buf;
        if (h->type == MSG_HASH && h->len == 32 && blen >= sizeof(*h) + 32) {
            uint8_t *digest = buf + sizeof(*h);
            printf("Client: hash = ");
            for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
            printf("\n");
        }
    }
	return 0;
}

/* This function disconnects the RDMA connection from the server and cleans up 
 * all the resources.
 */
static int client_disconnect_and_clean()
{
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	/* active disconnect from the client side */
	ret = rdma_disconnect(cm_client_id);
	if (ret) {
		rdma_error("Failed to disconnect, errno: %d \n", -errno);
		//continuing anyways
	}
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_DISCONNECTED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to get RDMA_CM_EVENT_DISCONNECTED event, ret = %d\n",
				ret);
		//continuing anyways 
	}
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge cm event, errno: %d\n", 
			       -errno);
		//continuing anyways
	}
	/* Destroy QP */
	rdma_destroy_qp(cm_client_id);
	/* Destroy client cm id */
	ret = rdma_destroy_id(cm_client_id);
	if (ret) {
		rdma_error("Failed to destroy client id cleanly, %d \n", -errno);
		// we continue anyways;
	}
	/* Destroy CQ */
	ret = ibv_destroy_cq(client_cq);
	if (ret) {
		rdma_error("Failed to destroy completion queue cleanly, %d \n", -errno);
		// we continue anyways;
	}
	/* Destroy completion channel */
	ret = ibv_destroy_comp_channel(io_completion_channel);
	if (ret) {
		rdma_error("Failed to destroy completion channel cleanly, %d \n", -errno);
		// we continue anyways;
	}	
	
	rdma_destroy_event_channel(cm_event_channel);
	printf("Client resource clean up is complete \n");
	return 0;
}

void usage() {
	printf("Usage:\n");
	printf("rdma_client: [-a <server_addr>] [-p <server_port>] -f filename (required) -i ID (required)\n");
	printf("(default IP is 127.0.0.1 and port is %d)\n", DEFAULT_RDMA_PORT);
	exit(1);
}

int main(int argc, char **argv) {
	struct sockaddr_in server_sockaddr;
	int ret, option;
	bzero(&server_sockaddr, sizeof server_sockaddr);
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* buffers are NULL */
	src = dst = NULL; 
	/* Parse Command Line Arguments */
	while ((option = getopt(argc, argv, "f:a:p:i:")) != -1) {
		switch (option) {
			case 'f':
				printf("Passed string is : %s , with count %u \n", 
						optarg, 
						(unsigned int) strlen(optarg));
				src = calloc(strlen(optarg) , 1);
				if (!src) {
					rdma_error("Failed to allocate memory : -ENOMEM\n");
					return -ENOMEM;
				}
				/* Copy the passes arguments */
				strncpy(src, optarg, strlen(optarg));
				dst = calloc(strlen(optarg), 1);
				if (!dst) {
					rdma_error("Failed to allocate destination memory, -ENOMEM\n");
					free(src);
					return -ENOMEM;
				}
				break;
			case 'i':
				student_id = strdup(optarg);
				if (!student_id) { rdma_error("alloc id failed\n"); return -ENOMEM; }
				if (strlen(student_id) > MAX_ID_LEN) {
            		rdma_error("id too long (>%d)\n", MAX_ID_LEN); return -EINVAL;
        		}
				break;
			case 'a':
				/* remember, this overwrites the port info */
				ret = get_addr(optarg, (struct sockaddr*) &server_sockaddr);
				if (ret) {
					rdma_error("Invalid IP \n");
					return ret;
				}
				break;
			case 'p':
				/* passed port to listen on */
				server_sockaddr.sin_port = htons(strtol(optarg, NULL, 0)); 
				break;
			default:
				usage();
				break;
			}
		}
	if (!server_sockaddr.sin_port) {
	  /* no port provided, use the default port */
	  server_sockaddr.sin_port = htons(DEFAULT_RDMA_PORT);
	  }
	if (src == NULL) {
		printf("Please provide a filename \n");
		usage();
       	}
	ret = client_prepare_connection(&server_sockaddr);
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	 }
	ret = client_pre_post_recv_buffer(); 
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	ret = client_connect_to_server();
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	ret = client_send_msg_req();
	if (ret) {
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	
	ret = client_write_file();
	if (ret) {
		rdma_error("Failed to finish remote memory ops, ret = %d \n", ret);
		return ret;
	}
	
	if (client_wait_verdict()) {
		rdma_error("verdict incorrect \n");
		return -1;
	} else {
		printf("Verdict SUCCESS.\n");
	}

	struct ibv_recv_wr *bad = NULL;
    int r = ibv_post_recv(client_qp, &ctrl_recv_wr, &ctrl_bad_recv);
    if (r) fprintf(stderr, "client: (re)post ctrl recv failed: %d\n", r);

	ret = client_send_id();
	if (ret) {
		rdma_error("Failed to send id \n");
		return ret;
	}
	
	ret = client_wait_hash();
	if (ret) {
		rdma_error("Failed to get hash \n");
	}

	ret = client_disconnect_and_clean();
	if (ret) {
		rdma_error("Failed to cleanup \n");
	}
	
	return ret;
}

