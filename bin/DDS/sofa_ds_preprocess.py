import csv
import glob
import os
import re
import datetime
import itertools
import json
import numpy as np
import pandas as pd
import subprocess
import random 
from sofa_config import *

class highchart_annotation_label:
    def __init__(self):
        self.point = {'xAxis' : 0,'yAxis' : 0,'x' :0,'y':0}
        self.text = ''
   

def ds_cnct_trace_init():	
### field = name, x, y
    name, x, y  =  '', None, None
    trace = [name, x, y]
    return trace

def cor_tab_init():
    cor_tab = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]
    return cor_tab

def ds_trace_preprocess_functions_init():
    null_functions = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    return null_functions

def create_DDS_info(ds_trace):
    return '[' + ds_trace[7] + "]" + str(ds_trace[10])+'.'+str(ds_trace[11])+'.'+str(ds_trace[12]) + ':' + str(ds_trace[9])

def get_socket_src_addr(ds_trace):
    return ds_trace[13] + ':' + str(ds_trace[15])

def get_socket_des_addr(ds_trace):
    return ds_trace[14] + ':' + str(ds_trace[16])

def create_socket_info(ds_trace):
    socket_info = '<br>'
    socket_info += '[' + get_socket_src_addr(ds_trace) + " --> " +  get_socket_des_addr(ds_trace) + ']'
    socket_info += '<br>' + create_DDS_info(ds_trace)
    return socket_info

def ds_traces2sofa_traces(ds_traces, index_table, functions = ds_trace_preprocess_functions_init()):
    from sofa_preprocess import trace_init
    sofa_traces = []

    for ds_trace in ds_traces:
        sofa_trace = trace_init()

        for i in range(len(sofa_trace)):
            if index_table[i] != -1:
                sofa_trace[i] = ds_trace[index_table[i]]
            elif functions[i] != 0:
                sofa_trace[i] = functions[i](ds_trace)

        sofa_traces.append(sofa_trace)

    return sofa_traces

def calculate_bandwidth_with_socket_payload(data_in):
    from sofa_preprocess import trace_init
    result = list()
    total_payload = 0
    first_ts = 0
    curr_ts = 0
    i = 1 
    
    for line in data_in:
        trace = trace_init()

        curr_ts = line[1]
        if not first_ts:
            first_ts = line[1]
            curr_ts = line[1] * 2
        
        total_payload += line[17]
        trace[6] = total_payload / (curr_ts - first_ts)        
        trace[0] = line[1]
        result.append(trace)

    return result

def funID2funName(id):
    if id == 1:
        return 'DDS_DataWriter_write'
    if id == 3:
        return 'rtps_write'
    if id == 20:
        return 'sock_sendmsg'
    if id == 30:
        return 'sock_recvmsg'
    if id == 8:
        return 'do_packet'
    if id == 7:
        return "DDS_DataReader_take"

def ds_dds_preprocess(cfg, logdir, pid):	
    from sofa_preprocess import sofa_fieldnames
    from sofa_preprocess import list_to_csv_and_traces

    trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']
    ds_df = pd.DataFrame(columns=trace_field)

    tmp_df = pd.read_csv('%s/ds_dds_trace'%logdir, sep=',\s+', delimiter=',', encoding="utf-8", skipinitialspace=False, header=0)
    tmp_df = tmp_df.dropna()

    for i in range(len(tmp_df.columns)):
        if i < 5:
            series = tmp_df.iloc[:,i]

            ds_df.iloc[:,i] = series
            ds_df.iloc[:,i] = ds_df.iloc[:,i].astype('int64')
        else:
            series = tmp_df.iloc[:,i]
            ds_df.iloc[:,i+1] = series
            if i != 6 and i != 7:
                ds_df.iloc[:,i+1] = ds_df.iloc[:,i+1].astype('int64')

    ds_df['tid']  = ds_df['tgid'].astype('int64').apply( lambda x: x & 0xFFFFFFFF )
    ds_df['tgid'] = ds_df['tgid'].apply( lambda x: (int(x) >> 32) & 0xFFFFFFFF )

    filter = ds_df['tgid'] == int(pid)
    ds_df  = ds_df[filter]
    ds_df.sort_values('start_ts')



### Normalize SOFA traces timeline
    ds_df.sort_values('start_ts')
    bpf_timebase_uptime = 0 
    bpf_timebase_unix = 0 
    
    with open(logdir + 'bpf_timebase.txt') as f:
        lines = f.readlines()
        bpf_timebase_unix = float(lines[-1].split(',')[0])
        bpf_timebase_uptime = float(lines[-1].split(',')[1].rstrip())
    offset = bpf_timebase_unix - bpf_timebase_uptime
    ds_df['start_ts'] = ds_df['start_ts'].apply(lambda x: (x / 10**9) + offset - cfg.time_base )
    ds_df[  'end_ts'] = ds_df[  'end_ts'].apply(lambda x: (x / 10**9) + offset - cfg.time_base )

    ds_df.to_csv(logdir + 'ds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
### Preprocess socket trace data
  # socket trace field name meaning
  # arg1: source IP               # arg2: destination IP
  # arg3: source port             # arg4: destination port
  # arg5: payload size            # arg6: checksum

    socket_df  = pd.DataFrame(columns=trace_field)
    filter     = ds_df['record_type'] == 2 # 2 for socket traces
    socket_df  = ds_df[filter]
    
    socket_df['arg1'] = socket_df['arg1'].apply(lambda x: str( x        & 0x000000FF) + "."
                                                        + str((x >>  8) & 0x000000FF) + "."
                                                        + str((x >> 16) & 0x000000FF) + "."
                                                        + str((x >> 24) & 0x000000FF) 
                                               )
    socket_df['arg2'] = socket_df['arg2'].apply(lambda x: str( x        & 0x000000FF) + "."
                                                        + str((x >>  8) & 0x000000FF) + "."
                                                        + str((x >> 16) & 0x000000FF) + "."
                                                        + str((x >> 24) & 0x000000FF) 
                                               )
#   socket_df['arg3'] = socket_df.apply(lambda x: (socket_df['arg3'].values >> 8) & 0x00FF | (socket_df['arg3'].values << 8) & 0xFF00)
    socket_df['arg3'] = socket_df['arg3'].apply(lambda x: (x >> 8) & 0x00FF | (x << 8) & 0xFF00)
    socket_df['arg4'] = socket_df['arg4'].apply(lambda x: (x >> 8) & 0x00FF | (x << 8) & 0xFF00)

### Classify socket traces by function ID 
  # 20: socket_sendmsg
  # 30: socket_recvmsg
    filter       = socket_df['fun_ID'] == 20
    socket_tx_df = socket_df[filter]

    filter       = socket_df['fun_ID'] == 30
    socket_rx_df = socket_df[filter]

    socket_df.to_csv(logdir + 'socket_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
    socket_tx_df.to_csv(logdir + 'socket_trace_tx_%s'%pid, mode='w', index=False, float_format='%.9f')
    socket_rx_df.to_csv(logdir + 'socket_trace_rx_%s'%pid, mode='w', index=False, float_format='%.9f')

    socket_norm_time_lists = [socket_tx_df.values.tolist(), socket_rx_df.values.tolist()]

### pid to IP/Port mapping
    pid2ip = socket_tx_df[0:1].values.tolist()
    pid2ip = pid2ip[0]
    pid2ip = str(pid2ip[4]) + ' ' + str(pid2ip[13]) + ":" + str(pid2ip[15])
    f = open ('%spid2ip.txt'%logdir, 'w')
    f.write(pid2ip)
    f.close()

# DS/DDS trace field index/name
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link       
  
# SOFA trace field index/name
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name
        
### Convert DS teace to SOFA trace format
    SOFA_trace_lists = []
    sock_trace4sofa_trace_index = [1, -1, -1, 18, -1, 17, -1, 
                                  -1, -1, -1,  4, -1, -1]

    sock_preprocess_functions = ds_trace_preprocess_functions_init()
    sock_preprocess_functions[7] = get_socket_src_addr
    sock_preprocess_functions[8] = get_socket_des_addr
    sock_preprocess_functions[11] = create_socket_info

    SOFA_trace_lists.append(ds_traces2sofa_traces(socket_norm_time_lists[0], sock_trace4sofa_trace_index, sock_preprocess_functions))
    SOFA_trace_lists.append(ds_traces2sofa_traces(socket_norm_time_lists[1], sock_trace4sofa_trace_index, sock_preprocess_functions))
    SOFA_trace_lists.append(calculate_bandwidth_with_socket_payload(socket_norm_time_lists[0]))
    SOFA_trace_lists.append(calculate_bandwidth_with_socket_payload(socket_norm_time_lists[1]))

### Preprocess DDS trace
    dds_df = pd.DataFrame(columns=trace_field)
    filter = ds_df['record_type'] == 1 # 1 for DDS traces
    dds_df = ds_df[filter]

    filter = dds_df['fun_ID'] == 1
    dds_pub_df = dds_df[filter]

    filter = dds_df['fun_ID'] == 7
    dds_sub_df = dds_df[filter]

    dds_df.to_csv(logdir + 'dds_trace_%s'%pid, mode='w', index=False, float_format='%.9f')
    dds_pub_df.to_csv(logdir + 'dds_trace_pub_%s'%pid, mode='w', index=False, float_format='%.9f')
    dds_sub_df.to_csv(logdir + 'dds_trace_sub_%s'%pid, mode='w', index=False, float_format='%.9f')

    dds_norm_time_lists = [dds_pub_df.values.tolist(), dds_sub_df.values.tolist()]


# DS/DDS trace 
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link    

# SOFA trace
# 0: timestamp   # 3: deviceId   # 6: bandwidth   # 9:  pid       # 12: category
# 1: event       # 4: copyKind   # 7: pkt_src     # 10: tid
# 2: duration    # 5: payload    # 8: pkt_dst     # 11: name

    dds_trace4sofa_trace_index = [1,  6, -1, -1, -1, -1, -1,  
                                 -1, -1,  4,  5,  8, -1]
    dds_preprocess_functions = ds_trace_preprocess_functions_init()
    dds_preprocess_functions[11] = create_DDS_info
    SOFA_trace_lists.append(ds_traces2sofa_traces(dds_norm_time_lists[0], dds_trace4sofa_trace_index, dds_preprocess_functions))
    SOFA_trace_lists.append(ds_traces2sofa_traces(dds_norm_time_lists[1], dds_trace4sofa_trace_index, dds_preprocess_functions))


### Convert to csv format which SOFA used to be stored as SOFA trace class  
    return [
            list_to_csv_and_traces(logdir, SOFA_trace_lists[0], 'ds_trace_tx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[1], 'ds_trace_rx%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[2], 'ds_trace_tx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[3], 'ds_trace_rx_bandwidth%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[4], 'dds_trace_pub%s.csv'%pid, 'w'),
            list_to_csv_and_traces(logdir, SOFA_trace_lists[5], 'dds_trace_sub%s.csv'%pid, 'w')
           ]


def create_span_in_hightchart (x, y, name):
    trace = ds_cnct_trace_init()
    trace = [name, x, y]
    return trace

# DS/DDS trace 
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link  
def ds_dds_create_span(cfg):
    from sofa_preprocess import traces_to_json
    from sofa_models import SOFATrace
    trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']
    all_ds_df = pd.DataFrame([], columns=trace_field)

    nodes_dir = glob.glob('[0-9]*')
    for nd_dir_iter in nodes_dir:
        ds_df = pd.read_csv('%s/ds_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')
        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)

    all_ds_df['timestamp'] = all_ds_df['start_ts']


    vid_seq_map = {}
    vidToIp_map = {}
    all_ds_list = all_ds_df.values.tolist()
    for ds_trace in all_ds_list:

        vid_seq = str(ds_trace[10]) + str(ds_trace[11]) + str(ds_trace[12]) + str(ds_trace[9])
        if vid_seq not in vid_seq_map:
            vid_seq_map[str(vid_seq)] = []
            vid_seq_map[str(vid_seq)].append(ds_trace)
        else:
            vid_seq_map[str(vid_seq)].append(ds_trace)

        if (ds_trace[6] == 20):
            vidToIP = str(ds_trace[10]) + str(ds_trace[11]) + str(ds_trace[12]) 
            if vidToIP not in vidToIp_map:
                vidToIp_map[str(vidToIP)] = str(  ds_trace[13]        & 0x000000FF) + "." \
                                          + str(( ds_trace[13] >>  8) & 0x000000FF) + "." \
                                          + str(( ds_trace[13] >> 16) & 0x000000FF) + "." \
                                          + str(( ds_trace[13] >> 24) & 0x000000FF) + ":" \
                                          + str(( ds_trace[15] >>  8) &     0x00FF| (ds_trace[15] <<  8) &     0xFF00)
                print(vidToIP)
                print(vidToIp_map[str(vidToIP)])



    fix_df_dic = {}
    pd.set_option("display.precision", 8)
    fix_df = pd.DataFrame([], columns=trace_field)
    seq_map_cnt = 0
    for vid_seq in vid_seq_map:
        if len(vid_seq_map[vid_seq]) == 6:
            _df = pd.DataFrame(vid_seq_map[vid_seq],columns=trace_field)

            fix_topic = 0
            rebase_span_timeline = 0
            SIP2DIP = 0
            for ds_trace in vid_seq_map[vid_seq]:
                if str(ds_trace[7]) !='nan' and not fix_topic:
                    topic_name = str(ds_trace[7]) 
                    _df['topic_name'] = topic_name

                    fix_topic = 1
                
                if not rebase_span_timeline and ds_trace[6] == 1 :
                    baseStime4eachtrace = ds_trace[1]
                    _df['start_ts'] = _df['start_ts'].apply(lambda x: x - baseStime4eachtrace)
                    _df[  'end_ts'] = _df[  'end_ts'].apply(lambda x: x - baseStime4eachtrace)
                    rebase_span_timeline = 1

                if not SIP2DIP and ds_trace[6] == 20 :
                    SIP = str(  ds_trace[13]        & 0x000000FF) + "." \
                        + str(( ds_trace[13] >>  8) & 0x000000FF) + "." \
                        + str(( ds_trace[13] >> 16) & 0x000000FF) + "." \
                        + str(( ds_trace[13] >> 24) & 0x000000FF) + ":" \
                        + str(( ds_trace[15] >>  8) &     0x00FF| (ds_trace[15] <<  8) &     0xFF00)
                    DIP = str(  ds_trace[14]        & 0x000000FF) + "." \
                        + str(( ds_trace[14] >>  8) & 0x000000FF) + "." \
                        + str(( ds_trace[14] >> 16) & 0x000000FF) + "." \
                        + str(( ds_trace[14] >> 24) & 0x000000FF) + ":" \
                        + str(( ds_trace[16] >>  8) &     0x00FF| (ds_trace[16] <<  8) &     0xFF00)
                    SIP2DIP = SIP + " to " + DIP

                here_not_classify = """
                if rebase_span_timeline and fix_topic and SIP2DIP:
                    fix_df = pd.concat([fix_df, _df], ignore_index=True, sort=False)
                    break
                """
                if rebase_span_timeline and fix_topic and SIP2DIP:
                    if SIP2DIP not in fix_df_dic:
                        fix_df_dic[SIP2DIP] = pd.DataFrame([], columns=trace_field)
                        fix_df_dic[SIP2DIP] = pd.concat([fix_df_dic[SIP2DIP], _df], ignore_index=True, sort=False)
                    else:
                        fix_df_dic[SIP2DIP] = pd.concat([fix_df_dic[SIP2DIP], _df], ignore_index=True, sort=False)
                    break

            vid_seq_map[vid_seq] = _df.values.tolist() # Write back fix trace in map

    traces = []
    span_cnt = 0
    for fix_df in fix_df_dic:
        span_cnt += 1
        span_list = fix_df_dic[fix_df].values.tolist()
        span4SOFA = []

        for ds_trace in span_list:
            x  = ds_trace[0]
            y1 = ds_trace[1]
            y2 = ds_trace[2]
            execution_time = y2 - y1

            funName = funID2funName(ds_trace[6])
            topicInfo = ' &lt;' + str(ds_trace[7]) + ':' + str(ds_trace[9]) + '&gt;'
            y1_info = funName + topicInfo + '<br> Start time: ' + str(format(ds_trace[0] + ds_trace[1], '.6f')) + 's' + "<br> Execution time: " + str(format(execution_time*1000, '.3f')) + "ms"
            y2_info = funName + topicInfo + '<br> End time: ' +   str(format(ds_trace[0] + ds_trace[2], '.6f')) + 's' + "<br> Execution time: " + str(format(execution_time*1000, '.3f')) + "ms"
            span4SOFA.append([x,y1,y1_info])
            span4SOFA.append([x,y2,y2_info])
            span4SOFA.append([None,None,''])

        span_trace = pd.DataFrame(span4SOFA, columns = ['x','y','name'])
        sofatrace = SOFATrace()
        sofatrace.name = 'DDS_span_view' + str(span_cnt)
        sofatrace.title = fix_df
        sofatrace.color = 'rgba(%s,%s,%s,0.8)' %(random.randint(0,255),random.randint(0,255),random.randint(0,255))
        sofatrace.x_field = 'x'
        sofatrace.y_field = 'y'
        sofatrace.data = span_trace
        traces.append(sofatrace)

    traces_to_json(traces, 'span_view.js', cfg, '_span')

# Not used
def ds_find_sender(recv_iter, all_send_index_list, send_find, send_canidate, latency, negative,total_latency):

    recv_tmp = recv_iter[0]
    recv_feature_pattern = str(recv_tmp[7]) + str(recv_tmp[8]) + str(recv_tmp[9]) + str(recv_tmp[10]) + str(recv_tmp[11])
    #print(recv_feature_pattern)

    for send_cnt in range(len(all_send_index_list)):
        send_tmp = list(all_send_index_list[send_cnt][0])
        send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + str(send_tmp[10]) + str(send_tmp[11])
        #print(send_feature_pattern)
        if (recv_feature_pattern == send_feature_pattern) and send_canidate[send_cnt]:
            send_select = all_send_index_list[send_cnt][1]

            if not negative:
                if (0 < recv_tmp[0] - send_tmp[0] < latency):              
                    if not send_find[send_select]:
                        total_latency += recv_tmp[0] - send_tmp[0] 
                        return total_latency, send_cnt
            else:
                latency = 0 - latency
                if (latency < recv_tmp[0] - send_tmp[0] < 0):
                    if not send_find[send_select]:
                        total_latency += recv_tmp[0] - send_tmp[0]
                        return total_latency, send_cnt

    return total_latency, False

### Add single point information in Highchart's line chart data format 
def create_cnct_trace(cnct_list, is_sender, pid_yPos_dic):
    cnct_trace_tmp = list(cnct_list)
    
    name = ''
    x = cnct_trace_tmp[1]
    y = pid_yPos_dic[str(cnct_trace_tmp[4])]

    if is_sender:
        name = str(cnct_trace_tmp[13]) + ':' + str(cnct_trace_tmp[15]) + ' | checksum = ' + str(cnct_trace_tmp[18])
    else:
        name = str(cnct_trace_tmp[14]) + ':' + str(cnct_trace_tmp[16]) + ' | checksum = ' + str(cnct_trace_tmp[18])

    trace = ds_cnct_trace_init()
    trace = [name, x, y]

    return trace
    
def ds_connect_preprocess(cfg):
# DS/DDS trace field name
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link   
    logdir = cfg.logdir
    ds_trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']

    all_ds_df = pd.DataFrame([], columns=ds_trace_field)
   
    pid_yPos_dic = {} 
    yPos_cnt = 0
    pid_ip_dic = {}
    
    adjust_list = []
    en_adjust = 1
    second_1 = 1
    adjust_file_exist = 0
    if (os.path.exists('adjust_offset.txt')):
        adjust_file_exist = 1
        f = open('adjust_offset.txt')
        adjust_list = f.readline().split(',')
        second_1 = float(adjust_list[2])

### Read in all nodes network activities information
    nodes_dir = glob.glob('[0-9]*')
    command_dic = {}
    for nd_dir_iter in nodes_dir:

        f = open ('%s/pid2ip.txt'%nd_dir_iter)
        pid2ip = f.readline().split()
        f.close()
        f = open ('%s/command.txt'%nd_dir_iter)
        command = f.readline().split()
        f.close()
        command_dic[command[0]] = 1
        pid_ip_dic[pid2ip[0]] = pid2ip[1]
        pid_yPos_dic[nd_dir_iter] = yPos_cnt

        ds_df = pd.read_csv('%s/socket_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')

            
        if en_adjust and adjust_file_exist and (nd_dir_iter == adjust_list[0]):
            ds_df['start_ts'] = ds_df['start_ts'].apply( lambda x: x - float(adjust_list[1]) )


        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)

        yPos_cnt += 1

    all_ds_df.sort_values(by='start_ts', inplace=True)
    all_ds_df.to_csv('processed_ds_record', mode='w', index=False, float_format='%.9f')
    print('\nIn kernel ds data preprocess done')



    y = [0,0,0,0,0,0,0,0,0,0,0,0,0]

    ds_df_no_multicast = pd.DataFrame([], columns=ds_trace_field)
    ds_df_no_multicast = all_ds_df.apply( lambda x: x if (int(x['arg2'].split('.')[0]) & 0xf0 != 0xe0) else 0
                                         , result_type='broadcast', axis=1)
    #print(ds_df_no_multicast)
    #ds_df_no_multicast = ds_df_no_multicast.dropna()
    #ds_df_no_multicast = all_ds_df

### Not really important, just nickname for sender and receiver records.
    filter = ds_df_no_multicast['fun_ID'] == 20 
    all_send_df = ds_df_no_multicast[filter]
    all_send_df = all_send_df.dropna()	
    all_send_list = all_send_df.values.tolist()

    filter = ds_df_no_multicast['fun_ID'] == 30
    all_recv_df = ds_df_no_multicast[filter]
    all_recv_list = all_recv_df.values.tolist()

    #print(all_recv_df)
### Create list to accelerate preprocess when finding network connection which is accomplished by remove redundant calculation.
    all_send_index_list = []
    all_recv_index_list = []

    for index in range(len(all_send_list)):
        all_send_index_list.append([all_send_list[index], index])

    for index in range(len(all_recv_list)):
        all_recv_index_list.append([all_recv_list[index], index])

### Choose those data whose feature pattern is unique in the whole 
    send_canidate = [False] * len(all_send_list)
    feature_send_dic = {}
    for send_cnt in range(len(all_send_index_list)):
        send_tmp = all_send_index_list[send_cnt][0]
        send_feature_pattern = \
                               str(send_tmp[13]) + str(send_tmp[15]) + str(send_tmp[14]) + \
                               str(send_tmp[16]) + str(send_tmp[18])
        send_feature_pattern = str(send_tmp[10]) + str(send_tmp[11]) + str(send_tmp[12]) + str(send_tmp[9])

        if send_feature_pattern not in feature_send_dic:
            feature_send_dic[send_feature_pattern] = [1, send_cnt]
            send_canidate[send_cnt] = True
        else:
            feature_send_dic[send_feature_pattern][0] += 1
   #         send_canidate[feature_send_dic[send_feature_pattern][1]] = False
            send_canidate[send_cnt] = True
                             
    recv_canidate = [False] * len(all_recv_list)
    feature_recv_dic = {}
    for recv_cnt in range(len(all_recv_index_list)):
        recv_tmp = all_recv_index_list[recv_cnt][0]
        recv_feature_pattern =  \
                               str(recv_tmp[13]) + str(recv_tmp[15]) + str(recv_tmp[14]) + \
                               str(recv_tmp[16]) + str(recv_tmp[18])
        recv_feature_pattern = str(recv_tmp[10]) + str(recv_tmp[11]) + str(recv_tmp[12]) + str(recv_tmp[9])

        if recv_feature_pattern not in feature_recv_dic:
            feature_recv_dic[recv_feature_pattern] = [1, recv_cnt]
            recv_canidate[recv_cnt] = True
        else:
            feature_recv_dic[recv_feature_pattern][0] += 1
#            recv_canidate[feature_recv_dic[recv_feature_pattern][1]] = False
            recv_canidate[recv_cnt] = True

### Create connection view by add highchart line data
    # Used to avoid miss selection of same data if there exist multiple same feature pattern in the data.
    send_find = [False] * len(all_send_list)
    recv_find = [False] * len(all_recv_list)

    # Create node to node connection view traces
    cnct_trace = []
    cnct_traces =[]
    trace_index = 0
    node2node_traceIndex_dic = {}

    # Because searching list is ordered and none matched received data should not 
    # search again (not found in previous searing), skip previous searched data.
    recv_cnt_skip = 0 

    # Accounting
    pre_sent_count, pre_recv_count, positive_min, negative_max, total_latency = 0, 0, 16, 0, 0
    who = 0
    match_cnt, neg_count, pos_count, total_neg, total_pos= 0, 0, 0, 0, 0

    # Loop control paremeters
    latency, retry, negative = 1, True, False 
    neg_who_dic = {} # []
    accounting = {}
    while retry:
        retry = False

        for recv_cnt in range(len(all_recv_index_list)):
            if not recv_canidate[all_recv_index_list[recv_cnt][1]]:
            #if  recv_find[all_recv_index_list[recv_cnt][1]]:
                continue

            recv_tmp = all_recv_index_list[recv_cnt][0]
            recv_feature_pattern = str(recv_tmp[13]) + str(recv_tmp[15]) + str(recv_tmp[14]) + \
                                   str(recv_tmp[16]) + str(recv_tmp[18])
            recv_feature_pattern = str(recv_tmp[10]) + str(recv_tmp[11]) + str(recv_tmp[12]) + str(recv_tmp[9])
            #print(recv_feature_pattern)
            sfind = False
            for send_cnt in range(len(all_send_index_list)):
                if not send_canidate[all_send_index_list[send_cnt][1]]:
                #if  send_find[all_send_index_list[send_cnt][1]]:
                    continue

                send_tmp = list(all_send_index_list[send_cnt][0])
                if  recv_tmp[0] - send_tmp[0] < 0:
                    pass #break
                send_feature_pattern = str(send_tmp[13]) + str(send_tmp[15]) + str(send_tmp[14]) + \
                                       str(send_tmp[16]) + str(send_tmp[18])
                send_feature_pattern = str(send_tmp[10]) + str(send_tmp[11]) + str(send_tmp[12]) + str(send_tmp[9])
                if (recv_feature_pattern == send_feature_pattern):
                    sfind = send_cnt
                    match_cnt += 1

                    acc_id = str(send_tmp[13]) + ':' + str(send_tmp[15]) + " to " + str(send_tmp[14]) + ':' + str(send_tmp[16])
                    if acc_id not in accounting:
                        accounting[acc_id] = {}
                        accounting[acc_id]['latency'] = []
                        accounting[acc_id]['bandwidth'] = []

                    accounting[acc_id]['latency'].append(recv_tmp[1] - send_tmp[1])
                    accounting[acc_id]['bandwidth'].append([send_tmp[1], recv_tmp[1], recv_tmp[17] ])

                    if  recv_tmp[1] - send_tmp[1] < 0:
                        continue
                        neg_count += 1
                        total_neg += recv_tmp[1] - send_tmp[1]
                        if send_tmp[4] in neg_who_dic:
                            neg_who_dic[send_tmp[4]]['neg_count'] += 1
                        else:
                            neg_who_dic[send_tmp[4]] = {}
                            neg_who_dic[send_tmp[4]]['neg_count'] = 1
                            neg_who_dic[send_tmp[4]]['neg_max'] = 0
                            neg_who_dic[send_tmp[4]]['pos_count'] = 0
                            neg_who_dic[send_tmp[4]]['pos_min'] = 16

                        #print(abs(recv_tmp[1] - send_tmp[1]))
                        if 6 > abs(recv_tmp[1] - send_tmp[1]) > neg_who_dic[send_tmp[4]]['neg_max']: 
                            negative_max = abs(recv_tmp[1] - send_tmp[1])
                            neg_who_dic[send_tmp[4]]['neg_max'] = negative_max
                            
                    else:
                        pos_count += 1
                        total_pos += recv_tmp[1] - send_tmp[1]

                        if send_tmp[4] in neg_who_dic:
                            neg_who_dic[send_tmp[4]]['pos_count'] += 1
                        else:
                            neg_who_dic[send_tmp[4]] = {}
                            neg_who_dic[send_tmp[4]]['neg_count'] = 0
                            neg_who_dic[send_tmp[4]]['neg_max'] = 0
                            neg_who_dic[send_tmp[4]]['pos_count'] = 1
                            neg_who_dic[send_tmp[4]]['pos_min'] = 16

                        #if positive_min > abs(recv_tmp[0] - send_tmp[0]) and who !=send_tmp[3]:
                        if abs(recv_tmp[1] - send_tmp[1]) < neg_who_dic[send_tmp[4]]['pos_min']: 
                            positive_min = abs(recv_tmp[1] - send_tmp[1])
                            neg_who_dic[send_tmp[4]]['pos_min'] = positive_min
                    break;
           # total_latency, send_cnt = \
           # ds_find_sender(all_recv_index_list[recv_cnt], all_send_index_list, send_find, send_canidate, latency, negative,total_latency)


### ------- Account ambibuous record (need to be filter out before making connection trace)
            if sfind:

                send_select = all_send_index_list[sfind][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                node2node = \
                    'Node ' + str(all_send_index_list[sfind][0][13]) + ':' + str(all_send_index_list[sfind][0][15]) + \
                ' to Node ' + str(all_recv_index_list[recv_cnt][0][14]) + ':' + str(all_send_index_list[sfind][0][16])
                #print(node2node)
### -----------    If we want to create point to point connect effect in highchart's line chart, 
### ----------- we need to add null data in series for differentiating different connection.
                if node2node in node2node_traceIndex_dic:
                    cnct_trace = cnct_traces[node2node_traceIndex_dic[node2node]]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[sfind][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[node2node_traceIndex_dic[node2node]] = cnct_trace
                else:
                    node2node_traceIndex_dic[node2node] = trace_index
                    cnct_traces.append([])
                    cnct_trace = cnct_traces[trace_index]
                    cnct_trace.append(create_cnct_trace(all_send_index_list[sfind][0], 1, pid_yPos_dic))
                    cnct_trace.append(create_cnct_trace(all_recv_index_list[recv_cnt][0], 0, pid_yPos_dic))
                    cnct_trace.append(ds_cnct_trace_init())
                    cnct_traces[trace_index] = cnct_trace
                    trace_index += 1

                del all_send_index_list[sfind]
                send_find[send_select] = True
                recv_find[recv_select] = True
                #retry = True

# --------- END if sfind:
# ----- END for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
# - END while retry:

### ---    Expand the searching range with larger latency if connection can not be figured out in previous given range. 
### --- Though in practice it should not exceed 1 second.

        if ( retry) and True:

            if not negative:
                #print("positive latency %d %d"%(latency, len(all_send_index_list)))
                if (latency < 1):
                    retry = True
                    latency += 1
                    recv_cnt_skip = 0
                else:
                    pre_sent_count = len(all_send_index_list)
                    pre_recv_count = len(all_recv_index_list)
                    negative = True
                    retry = True
                    latency = 1
                    recv_cnt_skip = 0
            else:

                pre_sent_count = len(all_send_index_list)
                pre_recv_count = len(all_recv_index_list)
                if (latency < 2):
                    retry = True
                    latency += 1
                    recv_cnt_skip = 0

    result_send_list = []
    result_recv_list = []
    for i in range(len(all_send_index_list)):
        result_send_list.append(all_send_index_list[i][0])

    for i in range(len(all_recv_index_list)):
        result_recv_list.append(all_recv_index_list[i][0])



    neg_count_max = 0
    for neg_who in neg_who_dic:
        print(('%s count: %s')%(neg_who, neg_who_dic[neg_who]['neg_count']))
        if (neg_who_dic[neg_who]['neg_count'] > neg_count_max):
            who = neg_who
            neg_count_max = neg_who_dic[who]['neg_count']
    if who in neg_who_dic:
        negative_max = neg_who_dic[who]['neg_max']

    for neg_who in neg_who_dic:
        if (neg_who != who):
            positive_min = neg_who_dic[neg_who]['pos_min']

    recv_nfind = [not i for i in recv_find]
    send_nfind = [not i for i in send_find]
    #print(send_nfind)
    recv_not_find = all_recv_df[recv_nfind]
    send_not_find = all_send_df[send_nfind]
    all_not_df = pd.concat([send_not_find, recv_not_find], ignore_index=True, sort=False)
    os.system('pwd')
    all_not_df.sort_values(by='timestamp', inplace=True)
    all_not_df.to_csv('nfound', mode='w', index=False, float_format='%.9f')

#    print(recv_not_find)
    print('match count: %s'%match_cnt)
    print('min positive latency: %s'%positive_min)
    print('max negative latency: %s'%negative_max)
    print('neg count %s'% neg_count)
    print('neg total %s'%total_neg)

    print('pos count %s'% pos_count)
    print('pos total %s'%total_pos)
    total_latency = float(total_neg)+float(total_pos)

    if neg_count > 5:
        neg_ratio = 0
        if positive_min > negative_max:
            neg_ratio_latancy = (positive_min - negative_max) * (1 - (total_pos/pos_count)/(total_pos/pos_count - total_neg/neg_count))
        print('max negative latency: %s'%negative_max)
        print('who: %s'%who)
        f = open('adjust_offset.txt','w')
        #if positive_min < negative_max:
         #   negative_max = positive_min
        if adjust_file_exist:
            if (who == int(adjust_list[0])):

                negative_max = float(adjust_list[1]) - total_neg 

       #     else:
      #          second_1 = negative_max - 0.0005
       #         who = int(adjust_list[0])
       #         negative_max = float(adjust_list[1]) - negative_max
        f.write(str(who))
        f.write(',')
        #f.write(str(total_neg/neg_count))
        #if (positive_min - negative_max) > 0:
          #  negative_max += (positive_min - negative_max)/2
        f.write(str(negative_max+neg_ratio_latancy))
        print('neg_ratio_latancy: %s'%neg_ratio_latancy)
        f.write(',')
        f.write(str(second_1))
        f.write('\n')
        f.close()
          
    print('total latency:%s'%float(total_latency))

    #print(cnct_trace)
    from sofa_preprocess import traces_to_json
    from sofa_models import SOFATrace
    # traces_to_json(traces, path, cfg, pid)
    traces = []
    #ambiguous = 0
    #for i in feature_cnt_dic:
    #    if feature_cnt_dic[i] > 1 :
    #        ambiguous += feature_cnt_dic[i] 

    y_categories = []
    for i in range(len(pid_yPos_dic)):
        y_categories.append([])
    for i in pid_yPos_dic:
        y_categories[pid_yPos_dic[i]] = pid_ip_dic[i]
    f = open('y_categories', 'w')
    json.dump(y_categories, f)
    f.close()
    #print(accounting)
    #f = open('ds_report.txt', 'w')

    for acc_id in accounting:
        print('\n')
        print(acc_id)
        df = pd.DataFrame(accounting[acc_id]['latency'])
        print('latency')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
        print('%%.75: %f'%(df.quantile(0.75)))
        print('%%.95: %f'%(df.quantile(0.95)))
        print('mean: %f'%(df.mean()))

        band = accounting[acc_id]['bandwidth']
        df = pd.DataFrame(accounting[acc_id]['bandwidth'],columns=['send','recv','payload'])
        df.sort_values('send')
        band = df.values.tolist()
        band_result = []
        payload = 0
        for i in range(len(band)):
            payload += band[i][2]
            band_result.append(payload/(band[i][1] - band[0][0]))
        d = """
        interval = 1000
        if int(len(band) / interval):
            for i in range(int(len(band)/interval)):
                stime = band[i*interval][0]
            #print(stime)
                payload = 0
                for j in range(interval):
                    payload += band[i*interval+j][2]
                etime = band[i*interval + interval-1][1]
            #print(etime) 
                band_result.append(payload/(etime-stime))
        else:
            payload = 0
            for i in range(len(band)):
                payload += band[i][2]
            band_result.append(payload/(band[-1][1]-band[1][0]))"""
        df = pd.DataFrame(band_result)
        print('\nbandwidth')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
        print('%%.75: %f'%(df.quantile(0.75)))
        print('%%.95: %f'%(df.quantile(0.95)))
        print('mean: %f\n'%(df.mean()))
    print('recv not find %d'%recv_find.count(False))
    print('send not find %d'%send_find.count(False))

    print('recv not canidate %d'%recv_canidate.count(False))
    print('send not canidate %d'%send_canidate.count(False))
    #for i in range(len(all_recv_list)):
     #   if not recv_find[i] and not recv_canidate[i]:
      #      print(all_recv_list[i])

    print('\n\n')
    for node2node in node2node_traceIndex_dic:

        cnct_trace = cnct_traces[node2node_traceIndex_dic[node2node]]
        cnct_trace = pd.DataFrame(cnct_trace, columns = ['name','x','y'])

        sofatrace = SOFATrace()
        sofatrace.name = 'ds_connection_trace%d' % node2node_traceIndex_dic[node2node]
        sofatrace.title = '%s' % node2node
        sofatrace.color = 'rgba(%s,%s,%s,0.8)' %(random.randint(0,255),random.randint(0,255),random.randint(0,255))
        sofatrace.x_field = 'x'
        sofatrace.y_field = 'y'
        sofatrace.data = cnct_trace
        traces.append(sofatrace)

    traces_to_json(traces, 'connect_view_data.js', cfg, '_connect')      
    return pid_yPos_dic

