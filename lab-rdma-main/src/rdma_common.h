#ifndef RDMA_COMMON_H
#define RDMA_COMMON_H


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <netdb.h>
#include <netinet/in.h>	
#include <arpa/inet.h>
#include <sys/socket.h>

#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>

#include <openssl/sha.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Error Macro*/
#define rdma_error(msg, args...) do {\
	fprintf(stderr, "%s : %d : ERROR : "msg, __FILE__, __LINE__, ## args);\
}while(0);

#ifdef ACN_RDMA_DEBUG 
/* Debug Macro */
#define debug(msg, args...) do {\
    printf("DEBUG: "msg, ## args);\
}while(0);

#else 

#define debug(msg, args...) 

#endif /* ACN_RDMA_DEBUG */

/* Capacity of the completion queue (CQ) */
#define CQ_CAPACITY (128)
/* MAX SGE capacity */
#define MAX_SGE (2)
/* MAX work requests */
#define MAX_WR (64)
/* Default port where the RDMA server is listening */
#define DEFAULT_RDMA_PORT (20886)

/* Server CTRL RECV slot number */
#define CTRL_RECV_SLOTS 8

/* MAX size of control message */
#define CTRL_MAX 4096

#define WRID_ATTR_RECV  50

/* MAX ID length */
#define MAX_ID_LEN 128        
  

/* 
 * We use attribute so that compiler does not step in and try to pad the structure.
 * We use this structure to exchange information between the server and the client. 
 *
 * For details see: http://gcc.gnu.org/onlinedocs/gcc/Type-Attributes.html
 */
/* Control message types for Send/Recv control plane */
enum msg_type {
    MSG_REQ     = 1,   /* client -> server: file_len + sha256(file) */
    MSG_DONE    = 2,   /* client -> server: data finished */
    MSG_VERDICT = 3,   /* server -> client: ok/bad */
    MSG_ID      = 4,   /* client -> server: ID bytes */
    MSG_HASH    = 5    /* server -> client: H(ID||salt) */
};

/* Fixed header for all control messages sent over SEND/RECV */
struct __attribute__((packed)) ctrl_hdr {
    uint32_t type;   /* enum msg_type */
    uint32_t len;    /* length in bytes of the payload immediately following */
};

/* Payload for MSG_REQ */
struct __attribute__((packed)) msg_req {
    uint64_t file_len;     /* number of bytes the client intends to write later */
    uint8_t  sha256[32];   /* SHA-256 of the whole file */
};

/* Payload for MGS_VERDICT */
struct __attribute__((packed)) msg_verdict {
    uint32_t code;   /* 0 = match, else mismatch/error */
};

/* Payload for MSG_HASH */
struct __attribute__((packed)) msg_hash    { uint8_t digest[32]; };


/* RDMA metadata buffer */
struct __attribute((packed)) rdma_buffer_attr {
  uint64_t address;
  uint32_t length;
  union stag {
	  /* if we send, we call it local stags */
	  uint32_t local_stag;
	  /* if we receive, we call it remote stag */
	  uint32_t remote_stag;
  }stag;
};

/* Managing CTRL RECV */
struct ctrl_ring {
    int slots;
    void **bufs;
    struct ibv_mr **mrs;
    struct ibv_sge *sges;
    struct ibv_qp *qp;
};


/* resolves a given destination name to sin_addr */
int get_addr(char *dst, struct sockaddr *addr);

/* prints RDMA buffer info structure */
void show_rdma_buffer_attr(struct rdma_buffer_attr *attr);

/* 
 * Processes an RDMA connection management (CM) event. 
 * @echannel: CM event channel where the event is expected. 
 * @expected_event: Expected event type 
 * @cm_event: where the event will be stored 
 */
int process_rdma_cm_event(struct rdma_event_channel *echannel, 
		enum rdma_cm_event_type expected_event,
		struct rdma_cm_event **cm_event);

/* Allocates an RDMA buffer of size 'length' with permission permission. This 
 * function will also register the memory and returns a memory region (MR) 
 * identifier or NULL on error. 
 * @pd: Protection domain where the buffer should be allocated 
 * @length: Length of the buffer 
 * @permission: OR of IBV_ACCESS_* permissions as defined for the enum ibv_access_flags
 */
struct ibv_mr* rdma_buffer_alloc(struct ibv_pd *pd, 
		uint32_t length, 
		enum ibv_access_flags permission);

/* Frees a previously allocated RDMA buffer. The buffer must be allocated by 
 * calling rdma_buffer_alloc();
 * @mr: RDMA memory region to free 
 */
void rdma_buffer_free(struct ibv_mr *mr);

/* This function registers a previously allocated memory. Returns a memory region 
 * Basically an error handling wrapper around ibv_reg_mr
 * (MR) identifier or NULL on error.
 * @pd: protection domain where to register memory 
 * @addr: Buffer address 
 * @length: Length of the buffer 
 * @permission: OR of IBV_ACCESS_* permissions as defined for the enum ibv_access_flags
 */
struct ibv_mr *rdma_buffer_register(struct ibv_pd *pd, 
		void *addr, 
		uint32_t length, 
		enum ibv_access_flags permission);
/* Deregisters a previously register memory 
 * @mr: Memory region to deregister 
 */
void rdma_buffer_deregister(struct ibv_mr *mr);

/* Processes a work completion (WC) notification. 
 * @comp_channel: Completion channel where the notifications are expected to arrive 
 * @wc: Array where to hold the work completion elements 
 * @max_wc: Maximum number of expected work completion (WC) elements. wc must be 
 *          atleast this size.
 */
int process_work_completion_events(struct ibv_comp_channel *comp_channel, 
		struct ibv_wc *wc, 
		int max_wc);

/* prints some details from the cm id */
void show_rdma_cmid(struct rdma_cm_id *id);

/* Compute sha256 of a file
 * @src_file: file
 * @path: path of the file
 * @out: buffer where the results will be
 * @out_len: the length of the file
 */
int sha256_file(FILE **src_file, const char *path, uint8_t out[32], uint64_t *out_len);

/*
 * Similar to above but operate over a buffer
 * @buf: buffer storing the content
 * @len: length of the content
 * @out: buffer where the results will be
 */
int sha256_buf(const void *buf, size_t len, uint8_t out[32]);

#endif /* RDMA_COMMON_H */
