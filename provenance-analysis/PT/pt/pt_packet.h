#ifndef _PT_PT_PACKET_H
#define _PT_PT_PACKET_H

enum pt_packet_kind {
	PT_PACKET_ERROR = -1,
	PT_PACKET_NONE,
	PT_PACKET_TNTSHORT,
	PT_PACKET_TNTLONG,
	PT_PACKET_TIP,
	PT_PACKET_TIPPGE,
	PT_PACKET_TIPPGD,
	PT_PACKET_FUP,
	PT_PACKET_PIP,
	PT_PACKET_MODE,
	PT_PACKET_TRACESTOP,
	PT_PACKET_CBR,
	PT_PACKET_TSC,
	PT_PACKET_MTC,
	PT_PACKET_TMA,
	PT_PACKET_CYC,
	PT_PACKET_VMCS,
	PT_PACKET_OVF,
	PT_PACKET_PSB,
	PT_PACKET_PSBEND,
	PT_PACKET_MNT,
	PT_PACKET_PAD,
};

enum pt_event_kind {
	PT_EVENT_NONE,
	PT_EVENT_CALL,
	PT_EVENT_RET,
	PT_EVENT_XBEGIN,
	PT_EVENT_XCOMMIT,
	PT_EVENT_XABORT,
};

struct pt_event {
	unsigned long addr:48;
	unsigned long kind:16;
};

struct pt_logfile_header {
	unsigned int magic;
	unsigned int version;
};

enum pt_logitem_kind {
	PT_LOGITEM_BUFFER,
	PT_LOGITEM_PROCESS,
	PT_LOGITEM_THREAD,
	PT_LOGITEM_IMAGE,
	PT_LOGITEM_XPAGE,
	PT_LOGITEM_UNMAP,
	PT_LOGITEM_FORK,
	PT_LOGITEM_SECTION,
	PT_LOGITEM_THREAD_END,
	PT_LOGITEM_AUDIT
};

struct pt_logitem_header {
	enum pt_logitem_kind kind;
	unsigned int size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
	unsigned long sequence;
	unsigned long size;
};

struct pt_logitem_process {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
	char name[16]; // TASK_COMM_LEN = 16
};

struct pt_logitem_image {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned int size;
	unsigned int timestamp;
	unsigned long image_name_length;
};

struct pt_logitem_xpage {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned long size;
};

struct pt_logitem_unmap {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
};

struct pt_logitem_fork {
	struct pt_logitem_header header;
	unsigned long parent_tgid;
	unsigned long parent_pid;
	unsigned long child_tgid;
	unsigned long child_pid;
};

struct pt_logitem_audit {
	struct pt_logitem_header header;
	unsigned long sid;
	unsigned int timestamp;
	int pid;
};

enum pt_packet_kind
pt_get_packet(unsigned char *buffer, unsigned long size, unsigned long *len);

unsigned long
pt_get_and_update_ip(unsigned char *packet, unsigned int len, unsigned long *last_ip);

#endif