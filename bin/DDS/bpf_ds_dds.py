#!/usr/bin/python3
from bcc import BPF

intrucode="""
BPF_PERF_OUTPUT(events);

//#undef DEBUG 
//#define DEBUG 

#define    DDS_RECORD     1
#define   SOCK_RECORD     2


#define FID_CREATE_TOPIC      40
#define FID_CREATE_DDSWRITER  41
#define FID_CREATE_DDSREADER  42
#define FID_VWRITER_NEW       43

#define FID_DDSWRITER_WRITE    1
#define FID_WRITER_WRITE       2
#define FID_RTPS_WRITE         3

#define FID_DDSREADER_READ     6
#define FID_DDSREADER_TAKE     7
#define FID_DO_PACKET          8
#define FID_GROUPWRITE         9
#define FID_DDSREADER_FLUSH_COPY 10

#define FID_SOCK_SEND         20
#define FID_IP_SEND           21

#define FID_SOCK_RECV         30
#define FID_RECV_UDP          31


#ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
#endif

#include <linux/sched.h>
#include <linux/stddef.h>

#include <net/inet_sock.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ip.h>

typedef struct topic_info_t { 
    char name[64];
} topic_info;
BPF_HASH(tName_map, u64, topic_info);

typedef struct v_gid_t {
    u32 systemId;
    u32 localId;
    u32 serial;
} v_gid;

typedef struct v_message_t {
    u32    v_node;
    u64    allocTime;
    u32    sequenceNumber;
    u32    transactionId;
    u64    writeTime;
    v_gid  writerGID;
    v_gid  writerInstanceGID;
    u64    qos;
} v_message;

typedef struct trace_id_t {
    v_gid  gid;
    u32    seqNum;
} traceId;
BPF_HASH(traceId_map, u64, traceId);

typedef struct bpf_data_t {
    u64  ts;
    u64  sts;
    u64  ets;
    u64  pid;
//  char comm[TASK_COMM_LEN];
    char comm[32];
    char tName[20];

    u8   recordType;
    u8    fun_ID;
    u8   fun_ret; 

    u64  arg1;
    u64  arg2;
    u64  arg3;
    u64  arg4;
    u64  arg5;
    u64  arg6;
    u64  ret;
    u64  link;

    u64  seqNum;
    u32  gid_sys;
    u32  gid_local;
    u32  gid_seria;
} bpf_data;
BPF_HASH(data_map, u64, bpf_data);

BPF_HASH(ts_map, u64, u64);

static void Start_TS (u64 id) {
    u64  ts = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
    id += pid;
    ts_map.update(&id, &ts);
}

static u64 End_TS (u64 id, u64 * e_ts) {
    *e_ts = bpf_ktime_get_ns();

    u64 pid = bpf_get_current_pid_tgid();
    id += pid;
    u64* s_ts_p = ts_map.lookup(&id);
    if (s_ts_p) {
        u64 s_ts;

        s_ts = *s_ts_p;
        ts_map.delete(&id);
        return s_ts;
    }
    return 0;
}



static void get_topic_info (u64 id, bpf_data* data) {

    topic_info* t_info_p = tName_map.lookup(&id);
    if (t_info_p) {
        bpf_probe_read_str(data->tName, 64, t_info_p->name);
     }

    traceId * trace_id_p = traceId_map.lookup(&id);
    if (trace_id_p) {
        traceId trace_id = *trace_id_p;
        data->gid_sys = trace_id.gid.systemId;
        data->gid_local = trace_id.gid.localId;
        data->gid_seria = trace_id.gid.serial;
        data->seqNum = trace_id.seqNum;
    }
}

static void drop_topic_info (u64 id) {

    topic_info* t_info_p = tName_map.lookup(&id);
    if (t_info_p) {
        tName_map.delete(&id);
     }

    traceId * trace_id_p = traceId_map.lookup(&id);
    if (trace_id_p) {
        traceId_map.delete(&id);
    }
}

static void insert_bpf_data(u64 id, bpf_data* data) {
    u64 pid = bpf_get_current_pid_tgid();
    id += pid;
    data_map.update(&id, data);
}

static bpf_data* get_bpf_data(u64 id) {
    u64 pid = bpf_get_current_pid_tgid();
    id += pid;

    bpf_data* data_p = data_map.lookup(&id);
    if (data_p) {
        data_map.delete(&id);
        return data_p;
    }
    return 0;
}
/*************************************************************************************************/
/**                                                                                             **/
/**                     This part record OpenSplice DDS topic information.                      **/
/**                                                                                             **/
/*************************************************************************************************/

/* =======================================================================
    Instrumented function:         DDS_DomainParticipant_create_topic
   ======================================================================= */ 
int T_GetTopicName(struct pt_regs *ctx) { // 2:topic name; 3: type_name; ret: topic pointer
 
    topic_info topic   = {};
    u64        tName_p = PT_REGS_PARM2(ctx);
    u64        pid     = bpf_get_current_pid_tgid();

    bpf_probe_read_str(topic.name, 20, (const char *)tName_p);
    tName_map.update(&pid, &topic);

    return 0;
}

int T_MapTopic2TopicName(struct pt_regs *ctx){ // ret: topic

    u64               pid = bpf_get_current_pid_tgid();
    topic_info*  t_info_p = tName_map.lookup(&pid);


    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 topic_p = PT_REGS_RC(ctx);

        tName_map.update(&topic_p, &topic);
        tName_map.delete(&pid);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ret = topic_p;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID = FID_CREATE_TOPIC;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 20, (const char *)t_info_p->name);

        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
     Instrumented function:         DDS_Publisher_create_datawriter
   ======================================================================= */ 
int W_MapPID2Topic(struct pt_regs *ctx) { // 2:topic; ret: writer
    u64          topic_p = PT_REGS_PARM2(ctx);
    topic_info* t_info_p = tName_map.lookup(&topic_p);

    if (t_info_p) {
        topic_info   topic = *t_info_p;


        u64 pid = bpf_get_current_pid_tgid();
        tName_map.update(&pid, &topic);
    }

    return 0;
}

int W_MapWriter2TopicName(struct pt_regs *ctx) { // 2:topic; ret: writer
    u64 pid = bpf_get_current_pid_tgid();

    topic_info* t_info_p;
    t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;


        u64 writer = PT_REGS_RC(ctx);
        tName_map.update(&writer, &topic);
        tName_map.delete(&pid);
    #ifdef DEBUG
        //topic_info  topic = *t_info_p;

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_CREATE_DDSWRITER;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);
        data.ret = writer;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
     Instrumented function:         v_writerNew
   ======================================================================= */ 
int W_MapVWriter2TopicName (struct pt_regs *ctx) { //ret: v_writer
    u64 pid = bpf_get_current_pid_tgid();

    topic_info* t_info_p;
    t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 v_writer = PT_REGS_RC(ctx);
        tName_map.update(&v_writer, &topic);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_VWRITER_NEW;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);
        data.ret = v_writer;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}

/* =======================================================================
    Instrumented function:         DDS_Subscriber_create_datareader
   ======================================================================= */ 
int R_MapPID2Topic(struct pt_regs *ctx) { // 2:topic; ret: reader
    u64          topic_p = PT_REGS_PARM2(ctx);
    topic_info* t_info_p = tName_map.lookup(&topic_p);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 pid = bpf_get_current_pid_tgid();
        tName_map.update(&pid, &topic);
    }

    return 0;
}

int R_MapReader2TopicName(struct pt_regs *ctx) { // 2:topic; ret: reader_p
    u64              pid = bpf_get_current_pid_tgid();
    topic_info* t_info_p = tName_map.lookup(&pid);

    if (t_info_p) {
        topic_info   topic = *t_info_p;

        u64 reader = PT_REGS_RC(ctx);
        tName_map.update(&reader, &topic);
        tName_map.delete(&pid);
    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_CREATE_DDSREADER;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);
        data.ret = reader;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}
int uretprobe_v_dataReaderNewBySQL (struct pt_regs *ctx) {

    u64 pid = bpf_get_current_pid_tgid();

    topic_info* t_info_p = tName_map.lookup(&pid);
    if (t_info_p) {

        u64 v_reader = PT_REGS_RC(ctx);
        tName_map.update(&v_reader, t_info_p);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_VWRITER_NEW;
        data.fun_ret = 1;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);

        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }

    return 0;
}


/*************************************************************************************************/
/**                                                                                             **/
/**                This part record write/read and its corresponding v_message.                 **/
/**                                                                                             **/
/*************************************************************************************************/

/* =======================================================================
    Instrumented function:         DDS_DataWriter_write
   ======================================================================= */ 
int uprobe_DDS_DataWriter_write(struct pt_regs *ctx) {
    u64           writer = PT_REGS_PARM1(ctx); // DDS_DataWriter
    Start_TS(FID_DDSWRITER_WRITE);


    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_DDSWRITER_WRITE;
        data.fun_ret = 0;

        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    
    return 0;
}

int uretprobe_DDS_DataWriter_write(struct pt_regs *ctx) {

    u64 sts, ets;
    sts = End_TS(FID_DDSWRITER_WRITE, &ets);
   

    bpf_data data = {};
    data.recordType = DDS_RECORD;
    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    data.fun_ID  = FID_DDSWRITER_WRITE;
    data.fun_ret = 1;

    data.sts = sts;
    data.ets = ets;
    get_topic_info (data.pid, &data);
    drop_topic_info (data.pid);
    events.perf_submit(ctx, &data, sizeof(data));

    
    return 0;
}

/* =======================================================================
    Instrumented function:         writerWrite
   ======================================================================= */ 
int writerWrite (struct pt_regs *ctx) {

    u64         v_writer = PT_REGS_PARM1(ctx);
    topic_info* t_info_p = tName_map.lookup(&v_writer);

    if (t_info_p) {
        u64 pid = bpf_get_current_pid_tgid();
        topic_info   topic = *t_info_p;

        u64        v_mess_p = PT_REGS_PARM3(ctx);
        v_message  v_mess;
        bpf_probe_read(&v_mess, sizeof(v_message), (const void *) v_mess_p);
        tName_map.update(&v_mess_p, &topic);
        tName_map.update(&pid, &topic);

        traceId trace_id;
        bpf_probe_read(&trace_id.gid, sizeof(v_gid), (const void *) v_mess_p + offsetof(v_message, writerGID));
        bpf_probe_read(&trace_id.seqNum, sizeof(u32), (const void *) v_mess_p + offsetof(v_message, sequenceNumber));
        traceId_map.update(&v_mess_p, &trace_id);
        traceId_map.update(&pid, &trace_id);

    #ifdef DEBUG

        bpf_data data = {};
        data.recordType = DDS_RECORD;

        data.ts  = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID  = FID_WRITER_WRITE;
        data.fun_ret = 0;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);

        data.gid_sys   = v_mess.writerGID.systemId;
        data.gid_local = v_mess.writerGID.localId;
        data.gid_seria = v_mess.writerGID.serial;
        data.seqNum = v_mess.sequenceNumber;

        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    }
    return 0;
}

/* =======================================================================
    Instrumented function:         rtps_Write
   ======================================================================= */ 
int uprobe_rtps_Write(struct pt_regs *ctx){ // (xp, &sender, message)
    Start_TS(FID_RTPS_WRITE);

    bpf_data data = {};
    u64       pid = bpf_get_current_pid_tgid();

    v_gid* gid_p = (v_gid*)PT_REGS_PARM2(ctx);
    v_gid   gid = *gid_p; 
    u64     v_mess_p = PT_REGS_PARM3(ctx); //v_message

    topic_info* t_info_p = tName_map.lookup(&v_mess_p);
    if (t_info_p) {
        topic_info   topic = *t_info_p;

        bpf_probe_read_str(data.tName, 20, t_info_p->name);

        tName_map.update(&pid, &topic);
        tName_map.delete(&v_mess_p);
     }

    traceId * trace_id_p = traceId_map.lookup(&v_mess_p);
    if (trace_id_p) {
        traceId trace_id = *trace_id_p;
        data.gid_sys = trace_id.gid.systemId;
        data.gid_local = trace_id.gid.localId;
        data.gid_seria = trace_id.gid.serial;
        data.seqNum = trace_id.seqNum;
        traceId_map.update(&pid, &trace_id);
        traceId_map.delete(&v_mess_p);
    }
 
    data.ret = v_mess_p;
    data.recordType = DDS_RECORD;

    data.ts  = bpf_ktime_get_ns();
    data.pid = pid;
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));
    data.fun_ID = FID_RTPS_WRITE;

    insert_bpf_data(FID_RTPS_WRITE,&data);
    //events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int uretprobe_rtps_Write(struct pt_regs *ctx){ // (xp, &sender, message)
    u64 sts, ets;
    sts = End_TS(FID_RTPS_WRITE, &ets); 

    bpf_data* data_p = get_bpf_data(FID_RTPS_WRITE);
    if (data_p == 0) return 0;

    data_p->ets = ets;
    data_p->sts = sts;
    
    if (data_p->gid_sys)
    events.perf_submit(ctx, data_p, sizeof(*data_p));
    return 0;
}


/* =======================================================================
     This one process DDS DataReader Vmessage information
   ======================================================================= */ 

//DDS_DataReader_read 

int uprobe_DDS_DataReader_take(struct pt_regs *ctx) {
    u64           reader = PT_REGS_PARM1(ctx); 
    Start_TS(FID_DDSREADER_TAKE);
    bpf_data data = {};

    topic_info* t_info_p = tName_map.lookup(&reader);
    if (t_info_p) {
        topic_info   topic = *t_info_p;
        bpf_probe_read_str(data.tName, 20, t_info_p->name);
        insert_bpf_data(FID_DDSREADER_TAKE, &data);

     }
    #ifdef DEBUG

        bpf_data dg_data = {};
        dg_data = data;
        dg_data.recordType = DDS_RECORD;

        dg_data.ts  = bpf_ktime_get_ns();
        dg_data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(dg_data.comm), sizeof(dg_data.comm));

        dg_data.fun_ID  = FID_DDSREADER_TAKE;
        dg_data.fun_ret = 0;

        events.perf_submit(ctx, &dg_data, sizeof(dg_data));
    #endif
    
    return 0;
}

int uretprobe_DDS_DataReader_take(struct pt_regs *ctx) {

    u64 sts, ets;
    sts = End_TS(FID_DDSREADER_TAKE, &ets);
    u64 pid = bpf_get_current_pid_tgid();
    u64 id = pid + FID_DDSREADER_TAKE;
    bpf_data * data_p = get_bpf_data(FID_DDSREADER_TAKE);
    if (data_p == 0) return 0;

    data_p->recordType = DDS_RECORD;
    data_p->ts  = bpf_ktime_get_ns();
    data_p->pid = pid;
    bpf_get_current_comm(&(data_p->comm), sizeof(data_p->comm));

    data_p->fun_ID  = FID_DDSREADER_TAKE;
    data_p->fun_ret = 1;

    data_p->sts = sts;
    data_p->ets = ets;
    get_topic_info (id, data_p);
    drop_topic_info (id);
//traceId_map.delete(&pid);
//tName_map.delete(&pid);
    events.perf_submit(ctx, data_p, sizeof(bpf_data));

    return 0;
}


void uprobe_DataReader_samples_flush_copy(struct pt_regs *ctx) {

    u64 id = bpf_get_current_pid_tgid() + FID_DDSREADER_FLUSH_COPY;
    u64 reader = PT_REGS_PARM1(ctx);

    ts_map.update(&id, &reader);
}

void uretprobe_DataReader_samples_flush_copy(struct pt_regs *ctx) {

    u64 id = bpf_get_current_pid_tgid() + FID_DDSREADER_FLUSH_COPY;
    ts_map.delete(&id);
}

int uprobe_DDS_ReaderCommon_samples_flush_copy(struct pt_regs *ctx) { // 1:data (v_message = data - 64)

    u64 pdata = PT_REGS_PARM1(ctx);
    u64 pv_mess = pdata - 64;

    v_message v_mess;
    bpf_probe_read(&v_mess.writerGID, sizeof(v_gid), (const void *)pv_mess + offsetof(v_message, writerGID));
    bpf_probe_read(&v_mess.sequenceNumber, sizeof(u32), (const void *)pv_mess + offsetof(v_message, sequenceNumber));

    u64 reader_p;
    u64 id = bpf_get_current_pid_tgid() + FID_DDSREADER_FLUSH_COPY;

    reader_p = (u64)ts_map.lookup(&id);
    if (reader_p) {
        topic_info  t_info = {};
        topic_info* t_info_p =  tName_map.lookup((u64 *)reader_p);

        if (t_info_p) {
            id = id + FID_DDSREADER_TAKE - FID_DDSREADER_FLUSH_COPY;
            tName_map.update(&id, t_info_p); // !!!!!!!!!!!!!!!!!!!!!
            traceId  trace_id = {};
            trace_id.gid.systemId = v_mess.writerGID.systemId;
            trace_id.gid.localId = v_mess.writerGID.localId;
            trace_id.gid.serial = v_mess.writerGID.serial;
            trace_id.seqNum = v_mess.sequenceNumber;
            traceId_map.update(&id, &trace_id);// !!!!!!!!!!!!!!!!!!!!!
        }
    }
    #ifdef DEBUG

        bpf_data data = {};
        data.ts  = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));

        data.fun_ID = FID_DDSREADER_FLUSH_COPY;

        data.gid_sys = v_mess.writerGID.systemId;
        data.gid_local = v_mess.writerGID.localId;
        data.gid_seria = v_mess.writerGID.serial;
        data.seqNum = v_mess.sequenceNumber;
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    return 0;

}

int uprobe_do_packet(struct pt_regs *ctx) {
    Start_TS(FID_DO_PACKET);
    return 0;
}

int uretprobe_do_packet(struct pt_regs *ctx) {

    u64 sts, ets;
    sts = End_TS(FID_DO_PACKET, &ets);
   

    bpf_data data = {};

    data.recordType = DDS_RECORD;
    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));
    
    data.fun_ID  = FID_DO_PACKET;
    data.fun_ret = 1;

    data.sts = sts;
    data.ets = ets;

    u64 id = data.pid + FID_DO_PACKET;
    get_topic_info (id, &data);
    drop_topic_info (id);
    events.perf_submit(ctx, &data, sizeof(bpf_data));

    return 0;
}


int do_groupwrite  (struct pt_regs *ctx) { 

    u64 arg = PT_REGS_PARM2(ctx);
    u64 msg;
    bpf_probe_read(&msg, sizeof(u64), (u64 *) arg);
    u64 pid = bpf_get_current_pid_tgid();
    u64 id = pid + FID_DO_PACKET;
    v_message v_mess;

    bpf_probe_read(&v_mess.writerGID, sizeof(v_gid), (const void *)msg + offsetof(v_message, writerGID));
    bpf_probe_read(&v_mess.sequenceNumber, sizeof(u32), (const void *)msg + offsetof(v_message, sequenceNumber));

    traceId  trace_id = {};
    trace_id.gid.systemId = v_mess.writerGID.systemId;
    trace_id.gid.localId = v_mess.writerGID.localId;
    trace_id.gid.serial = v_mess.writerGID.serial;
    trace_id.seqNum = v_mess.sequenceNumber;
    traceId_map.update(&id, &trace_id);

    bpf_data* data_p = get_bpf_data(FID_SOCK_RECV);
    if (data_p) {
       
        data_p->gid_sys   = v_mess.writerGID.systemId;
        data_p->gid_local = v_mess.writerGID.localId;
        data_p->gid_seria = v_mess.writerGID.serial;
        data_p->seqNum    = v_mess.sequenceNumber;

        events.perf_submit(ctx, data_p, sizeof(bpf_data));
    }

    #ifdef DEBUG
        bpf_data data = {};
        data.recordType = DDS_RECORD;
        bpf_get_current_comm(&(data.comm), sizeof(data.comm));
        data.ts  = bpf_ktime_get_ns();
        data.pid = pid;

        data.gid_sys = v_mess.writerGID.systemId;
        data.gid_local = v_mess.writerGID.localId;
        data.gid_seria = v_mess.writerGID.serial;
        data.seqNum = v_mess.sequenceNumber;

        data.fun_ID = FID_GROUPWRITE;
        data.fun_ret = 0;

        events.perf_submit(ctx, &data, sizeof(data));
    #endif

    return 0;
}


/*************************************************************************************************/
/**                                                                                             **/
/**                kprobe for recording packets Tx/Rx messages                                  **/
/**                                                                                             **/
/*************************************************************************************************/




/* =======================================================================
    Instrumented function:         sock_sendmsg
   ======================================================================= */
BPF_HASH(start, struct sock *, u64);
BPF_HASH(end, u64, bpf_data);

int kprobe_sock_sendmsg(struct pt_regs *ctx)
{
    Start_TS(FID_SOCK_SEND);

    struct socket *sock;
    u64 ts;
    sock = (struct socket *)PT_REGS_PARM1(ctx); 
    struct sock *sk = sock->sk;

    ts = bpf_ktime_get_ns();
    start.update(&sk, &ts);


    return 0;
}

int kretprobe_sock_sendmsg(struct pt_regs *ctx)
{
    u64 sts, ets;
    sts = End_TS(FID_SOCK_SEND, &ets);

    bpf_data * bpf_data_p = get_bpf_data(FID_SOCK_SEND);
    if (bpf_data_p == 0) return 0;

    bpf_data_p->fun_ID  = FID_SOCK_SEND;
    bpf_data_p->sts = sts;
    bpf_data_p->ets = ets;
    bpf_data_p->recordType = SOCK_RECORD;
    events.perf_submit(ctx, bpf_data_p, sizeof(bpf_data));

/*
    u64 id = FID_SOCK_SEND;
    u64 pid = bpf_get_current_pid_tgid();
    id += pid; 

    bpf_data * bpf_data_p = data_map.lookup(&id);
    if (bpf_data_p) {
        bpf_data data = {};
        data = *bpf_data_p;
        data.sts = sts;
        data.ets = bpf_ktime_get_ns();;
        events.perf_submit(ctx, &data, sizeof(data));
        data_map.delete(&id);
    }
*/
    return 0;
}

/* =======================================================================
    Instrumented function:         ip_send_skb
   ======================================================================= */
int ip_send_skb (struct pt_regs *ctx)
{

    bpf_data data = {};

    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    data.fun_ID  = FID_IP_SEND;

    struct sk_buff*  skb = (struct sk_buff *) PT_REGS_PARM2(ctx);
    struct  udphdr*   uh = (struct udphdr *) (skb->head + skb->transport_header);
    struct   iphdr*  iph = (struct iphdr *) (skb->head + skb->network_header);
    struct    sock*   sk = skb->sk;

    u64 *l4_ts = start.lookup(&sk);
    if (l4_ts) {
        data.link = bpf_ktime_get_ns();
        data.ret   = *l4_ts;
        start.delete(&sk);
    }

    data.arg6 = 0x000000000000ffff & uh->check;
    data.arg5 = 0x000000000000ffff & skb->len;
    data.arg4 = 0x000000000000ffff & uh->dest;
    data.arg3 = 0x000000000000ffff & uh->source;
    data.arg2 = 0x00000000ffffffff & iph->daddr;
    data.arg1 = 0x00000000ffffffff & iph->saddr;

    get_topic_info(data.pid, &data);
    drop_topic_info(data.pid);

    insert_bpf_data(FID_SOCK_SEND, &data);

/*
    topic_info* t_info_p = tName_map.lookup(&data.pid);
    if (t_info_p) {
        bpf_probe_read_str(data.tName, 20, t_info_p->name);
        tName_map.delete(&data.pid);
     }

    traceId * trace_id_p = traceId_map.lookup(&data.pid);
    if (trace_id_p) {
        traceId trace_id = *trace_id_p;
        data.gid_sys = trace_id.gid.systemId;
        data.gid_local = trace_id.gid.localId;
        data.gid_seria = trace_id.gid.serial;
        data.seqNum = trace_id.seqNum;

        traceId_map.delete(&data.pid);
    }

    u64 id =   FID_SOCK_SEND;
    id += data.pid;
    data_map.update(&id, &data);

    events.perf_submit(ctx, &data, sizeof(data));
*/


    return 0;
}


/* =======================================================================
    Instrumented function:         __skb_recv_udp
   ======================================================================= */
int kretprobe_skb_recv_udp(struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct udphdr * uh;
    struct iphdr * iph;

    skb = (struct sk_buff *)PT_REGS_RC(ctx);

    uh = (struct udphdr *) (skb->head + skb->transport_header);
    iph = (struct iphdr *) (skb->head + skb->network_header);


    u64 pid = bpf_get_current_pid_tgid();

    bpf_data data = {};
    data.recordType = SOCK_RECORD;

    data.ts  = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(data.comm), sizeof(data.comm));

    data.fun_ID  = FID_RECV_UDP;
    data.fun_ret = 1;


    data.arg6 = 0x000000000000ffff & uh->check;
    data.arg5 = 0x000000000000ffff & skb->len;
    data.arg4 = 0x000000000000ffff & uh->dest;
    data.arg3 = 0x000000000000ffff & uh->source;
    data.arg2 = 0x00000000ffffffff & iph->daddr;
    data.arg1 = 0x00000000ffffffff & iph->saddr;
    insert_bpf_data(FID_RECV_UDP, &data);
    // end.update(&pid, &data);

 
    #ifdef DEBUG
        events.perf_submit(ctx, &data, sizeof(data));
    #endif
    return 0;

}

/* =======================================================================
    Instrumented function:         sock_recvmsg
   ====================================================get_topic_info=================== */

int kprobe_sock_recvmsg(struct pt_regs *ctx)
{
    Start_TS(FID_SOCK_RECV);
    return 0;
}

int kretprobe_sock_recvmsg(struct pt_regs *ctx)
{
    u64 sts, ets;
    sts = End_TS(FID_SOCK_RECV, &ets);

    int len = PT_REGS_RC(ctx);
    if (len < 0) {
        return 0;
    }

    //bpf_data* data_p = end.lookup(&pid);
    bpf_data* data_p = get_bpf_data(FID_RECV_UDP);
    if (data_p) {
        data_p->ets = ets;
        data_p->sts = sts;

        data_p->fun_ID  = FID_SOCK_RECV;
        data_p->fun_ret = 1;
        data_p->ts = bpf_ktime_get_ns();

        if (data_p->arg1 || data_p->arg2 || data_p->arg3 || data_p->arg4) {
            insert_bpf_data(FID_SOCK_RECV, data_p);

            //data_map.update(&pid, &data);
            //events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    return 0;
}


"""

bpf = BPF(text=intrucode)

f = open("dds_cfg_4_sofa.txt")
LIBPATH = f.read().rstrip('\n')
f.close()
if LIBPATH[-1] != '/':
    LIBPATH = LIBPATH + '/'

# Topic information recording
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="T_GetTopicName")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DomainParticipant_create_topic", fn_name="T_MapTopic2TopicName")

bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="W_MapPID2Topic")
bpf.attach_uretprobe(name="%slibddskernel.so"%LIBPATH, sym="v_writerNew", fn_name="W_MapVWriter2TopicName")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Publisher_create_datawriter", fn_name="W_MapWriter2TopicName")

bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="R_MapPID2Topic")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_Subscriber_create_datareader", fn_name="R_MapReader2TopicName")
bpf.attach_uretprobe(name="%slibddskernel.so"%LIBPATH, sym="v_dataReaderNewBySQL", fn_name="uretprobe_v_dataReaderNewBySQL")



# Write/Read Records
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym= "DDS_DataWriter_write", fn_name="uprobe_DDS_DataWriter_write")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym= "DDS_DataWriter_write", fn_name="uretprobe_DDS_DataWriter_write")

bpf.attach_uprobe(name="%slibddskernel.so"%LIBPATH, sym="writerWrite", fn_name="writerWrite")
bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="rtps_write", fn_name="uprobe_rtps_Write")
bpf.attach_uretprobe(name="%slibddsi2.so"%LIBPATH, sym="rtps_write", fn_name="uretprobe_rtps_Write")

bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DataReader_take", fn_name="uprobe_DDS_DataReader_take")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_DataReader_take", fn_name="uretprobe_DDS_DataReader_take")

bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="do_packet", fn_name="uprobe_do_packet")
bpf.attach_uretprobe(name="%slibddsi2.so"%LIBPATH, sym="do_packet", fn_name="uretprobe_do_packet")

bpf.attach_uprobe(name="%slibddsi2.so"%LIBPATH, sym="do_groupwrite", fn_name="do_groupwrite")


bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="DDS_ReaderCommon_samples_flush_copy", fn_name="uprobe_DDS_ReaderCommon_samples_flush_copy")
bpf.attach_uprobe(name="%slibdcpssac.so"%LIBPATH, sym="_DataReader_samples_flush_copy", fn_name="uprobe_DataReader_samples_flush_copy")
bpf.attach_uretprobe(name="%slibdcpssac.so"%LIBPATH, sym="_DataReader_samples_flush_copy", fn_name="uretprobe_DataReader_samples_flush_copy")

#sys_enter_recvmsg



bpf.attach_kprobe( event="sock_sendmsg", fn_name="kprobe_sock_sendmsg")
bpf.attach_kprobe( event="ip_send_skb", fn_name="ip_send_skb")
bpf.attach_kretprobe(event="sock_sendmsg", fn_name="kretprobe_sock_sendmsg")

bpf.attach_kprobe( event="sock_recvmsg", fn_name="kprobe_sock_recvmsg")
bpf.attach_kretprobe( event="__skb_recv_udp", fn_name="kretprobe_skb_recv_udp") 
bpf.attach_kretprobe(event="sock_recvmsg", fn_name="kretprobe_sock_recvmsg")


def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    if 1:
        print("%14d,%14d,%14d,%2d,%14d,%4d,%20s,%14s,%6d,%12d,%8d,%8d,%14d,%14d,%14d,%14d,%14d,%14d,%14d,%14d" % 
             (event.ts, event.sts, event.ets,
              event.recordType, event.pid, event.fun_ID, str(event.tName, "utf-8"), str(event.comm, "utf-8"),
              event.seqNum, event.gid_sys, event.gid_local, event.gid_seria,
              event.arg1, event.arg2, event.arg3,
              event.arg4, event.arg5, event.arg6,
              event.link, event.fun_ret))
    else:
        pass

bpf["events"].open_perf_buffer(print_event, page_cnt = 64*64)
while 1:
    bpf.perf_buffer_poll()

