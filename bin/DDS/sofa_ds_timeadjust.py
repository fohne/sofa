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

def ds_time_adjustment(cfg):
    default_logdir = cfg.logdir
    ds_logdir = cfg.logdir + "ds_finish/"
    os.chdir(ds_logdir)
    ds_trace_raw_field = ['timestamp', 'comm', 'pkt_type', 'tgid_tid', 'net_layer', 
                      'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time'] 
    ds_trace_field = ['timestamp', 'comm', 'pkt_type', 'tgid', 'tid', 'net_layer', 
                      'payload', 's_ip', 's_port', 'd_ip', 'd_port', 'checksum', 'start_time'] 

    node_dirs = glob.glob('[0-9]*')

    # find the smallest SOFA time as globally aligned timebase
    sofa_timebase_min = sys.maxint
    for nd_dir_iter in node_dirs:
        os.system('cp %s/sofa_time.txt %s/sofa_time.txt.ori' % (nd_dir_iter, nd_dir_iter))
        time_fd = open('%s/sofa_time.txt' % nd_dir_iter)
        unix_time = time_fd.readline()
        unix_time.rstrip()
        if unix_time < sofa_timebase_min:
            sofa_timebase_min = unix_time
    # update global timebase
    for nd_dir_iter in node_dirs:
        time_fd = open('%s/sofa_time.txt' % nd_dir_iter, 'w')
        time_fd.write(sofa_timebase_min)
        time_fd.close()

    # read in all ds record to adjust time offset due to ntp time update overhead and network latency
    all_ds_df = pd.DataFrame([], columns=ds_trace_raw_field)
    for nd_dir_iter in node_dirs:
        ds_df = pd.read_csv('%s/ds_trace'%(nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                                skipinitialspace=False, header=0, float_precision='round_trip')
        ds_df = tmp_ds_df.dropna()
        all_ds_df = pd.concat([ds_df, all_ds_df], ignore_index=True, sort=False)
    all_ds_df.sort_values(by='timestamp', inplace=True)

    adjust_list = []
    #en_adjust = 1
    second_1 = 1
    adjust_file_exist = 0

    if (os.path.exists('adjust_offset.txt')):
        adjust_file_exist = 1
        f = open('adjust_offset.txt')
        adjust_list = f.readline().split(',')
        second_1 = float(adjust_list[2])


### Not really important, just nickname for sender and receiver records.
    filter = all_ds_df['net_layer'] == 300 
    all_send_df = all_ds_df[filter]
    #all_send_df = all_send_df.apply(lambda x: x if (x['comm'].find('xmit.user')>-1) else None, result_type='broadcast', axis=1)
    all_send_df = all_send_df.dropna()	
    all_send_list = all_send_df.values.tolist()

    filter = all_ds_df['net_layer'] == 1410
    all_recv_df = all_ds_df[filter]
    all_recv_list = all_recv_df.values.tolist()

### Create list to accelerate preprocess when finding network connection which is accomplished by remove redundant calculation.
    all_send_index_list = []
    all_recv_index_list = []

    for index in range(len(all_send_list)):
        all_send_index_list.append([all_send_list[index], index])

    for index in range(len(all_recv_list)):
        all_recv_index_list.append([all_recv_list[index], index])

### Choose those data whose feature pattern is unique in the whole 
    feature_send_dic = {}
    send_candidate = [False] * len(all_send_list)
    for send_cnt in range(len(all_send_index_list)):
        send_tmp = all_send_index_list[send_cnt][0]
        send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + \
                               str(send_tmp[10]) + str(send_tmp[11])
        if send_feature_pattern not in feature_send_dic:
            # if multi-records exist, send_cnt is the first record of multi-records which should be fixed and not select as candidate
            feature_send_dic[send_feature_pattern] = [1, send_cnt]
            send_candidate[send_cnt] = True
        else:
            feature_send_dic[send_feature_pattern][0] += 1
            send_candidate[feature_send_dic[send_feature_pattern][1]] = False
            send_candidate[send_cnt] = False

    feature_recv_dic = {}
    recv_candidate = [False] * len(all_recv_list)
    for recv_cnt in range(len(all_recv_index_list)):
        recv_tmp = all_recv_index_list[recv_cnt][0]
        recv_feature_pattern = str(recv_tmp[7]) + str(recv_tmp[8]) + str(recv_tmp[9]) + \
                               str(recv_tmp[10]) + str(recv_tmp[11])
        if recv_feature_pattern not in feature_recv_dic:
            feature_recv_dic[recv_feature_pattern] = [1, recv_cnt]
            recv_candidate[recv_cnt] = True
        else:
            feature_recv_dic[recv_feature_pattern][0] += 1
            recv_candidate[feature_recv_dic[recv_feature_pattern][1]] = False
            recv_candidate[recv_cnt] = False

    send_find = [False] * len(all_send_list)
    recv_find = [False] * len(all_recv_list)

    # Because searching list is ordered and none matched received data should not 
    # search again (not found in previous searing), skip previous searched data.
    recv_cnt_skip = 0 

    # Accounting
    pre_sent_count, pre_recv_count, positive_min, negative_min, total_latency = 0, 0, 16, 0, 0
    who = []
    match_cnt, neg_count, pos_count, total_neg, total_pos= 0, 0, 0, 0, 0

    # Loop control paremeters
    latency, retry, negative = 1, True, False 
    neg_who_dic = {}
    accounting = {}

    nodes_timeoffset_dic = {}
    pid_ip_dic = {}
    while retry:
        retry = False

        for recv_cnt in range(len(all_recv_index_list)):
            if not recv_candidate[all_recv_index_list[recv_cnt][1]]:
                continue

            recv_tmp = all_recv_index_list[recv_cnt][0]
            recv_feature_pattern = str(recv_tmp[7]) + str(recv_tmp[8]) + str(recv_tmp[9]) + \
                                   str(recv_tmp[10]) + str(recv_tmp[11])

            sfind = False
            for send_cnt in range(len(all_send_index_list)):
                if not send_candidate[all_send_index_list[send_cnt][1]]:
                    continue

                send_tmp = list(all_send_index_list[send_cnt][0])
                send_feature_pattern = str(send_tmp[7]) + str(send_tmp[8]) + str(send_tmp[9]) + \
                                       str(send_tmp[10]) + str(send_tmp[11])

                if (recv_feature_pattern == send_feature_pattern):
                    sfind = send_cnt
                    send_pid = str(send_tmp[3])
                    recv_pid = str(recv_tmp[3])
                    if send_pid not in nodes_timeoffset_dic:
                        pid_ip_dic[send_pid] = send_tmp[7]
                        nodes_timeoffset_dic[send_pid] = {}

                    if recv_pid not in nodes_timeoffset_dic[send_pid]:
                        nodes_timeoffset_dic[send_pid][recv_pid] = {}


                    acc_id = str(send_tmp[7]) + " to " + str(send_tmp[9])
                    if acc_id not in accounting:
                        accounting[acc_id] = {}
                        accounting[acc_id]['latency'] = []
                        accounting[acc_id]['bandwidth'] = []

                    accounting[acc_id]['latency'].append(recv_tmp[0] - send_tmp[0])
                    accounting[acc_id]['bandwidth'].append([send_tmp[0], recv_tmp[0], send_tmp[6] ])

                    if  recv_tmp[0] - send_tmp[0] < 0:
                        neg_count += 1
                        total_neg += recv_tmp[0] - send_tmp[0]
                        if send_tmp[3] in neg_who_dic:
                            neg_who_dic[send_tmp[3]]['neg_count'] += 1
                        else:
                            neg_who_dic[send_tmp[3]] = {}
                            neg_who_dic[send_tmp[3]]['neg_count'] = 1
                            neg_who_dic[send_tmp[3]]['neg_max'] = 0
                        if second_1 > abs(recv_tmp[0] - send_tmp[0]) > neg_who_dic[send_tmp[3]]['neg_max']: 
                            negative_min = abs(recv_tmp[0] - send_tmp[0])
                            neg_who_dic[send_tmp[3]]['neg_max'] = negative_min
                            
                    else:
                        pos_count += 1
                        total_pos += recv_tmp[0] - send_tmp[0]
                        if positive_min > abs(recv_tmp[0] - send_tmp[0]) and who !=send_tmp[3]:
                            positive_min = abs(recv_tmp[0] - send_tmp[0])
                    break;
           # total_latency, send_cnt = \
           # ds_find_sender(all_recv_index_list[recv_cnt], all_send_index_list, send_find, send_candidate, latency, negative,total_latency)


### ------- Account ambibuous record (need to be filter out before making connection trace)
            if sfind:

                send_select = all_send_index_list[sfind][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                node2node = 'Node ' + str(all_send_index_list[sfind][0][7]) + \
                            ' to Node ' + str(all_recv_index_list[recv_cnt][0][9])

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
            #print(len(all_send_index_list))
            #print(len(all_recv_index_list))
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
                #print("negative latency %d %d"%(latency,pre_sent_count - len(all_send_index_list)))
                #print(pre_recv_count - len(all_recv_index_list))
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

    #print(len(result_send_list))
    #print(len(result_recv_list))
    #print('min positive latency: %s'%positive_max)

    max_who = 0
    for neg_who in neg_who_dic:
        print(('%s count: %s')%(neg_who, neg_who_dic[neg_who]['neg_count']))
        if (neg_who_dic[neg_who]['neg_count'] > max_who):
            who = neg_who
            max_who = neg_who_dic[who]['neg_count']
    #if who in neg_who_dic:
        #negative_min = neg_who_dic[who][1]
    print('match count: %s'%match_cnt)
    print('min positive latency: %s'%positive_min)
    print('max negative latency: %s'%negative_min)
    print('neg count %s'% neg_count)
    print('neg total %s'%total_neg)

    print('pos count %s'% pos_count)
    print('pos total %s'%total_pos)
    total_latency = float(total_neg)+float(total_pos)

    if neg_count > 5:
        print('max negative latency: %s'%negative_min)
        print('who: %s'%who)
        f = open('adjust_offset.txt','w')
        #if positive_min < negative_min:
         #   negative_min = positive_min
        if adjust_file_exist:
            if (who == int(adjust_list[0])):

                negative_min = float(adjust_list[1]) - total_neg 

       #     else:
      #          second_1 = negative_min - 0.0005
       #         who = int(adjust_list[0])
       #         negative_min = float(adjust_list[1]) - negative_min
        f.write(str(who))
        f.write(',')
        #f.write(str(total_neg/neg_count))
        #if (positive_min - negative_min) > 0:
          #  negative_min += (positive_min - negative_min)/2
        f.write(str(negative_min))
        f.write(',')
        f.write(str(second_1))
        f.write('\n')
        f.close()
          
    print('total latency:%s'%float(total_latency))

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
    f = open('y_categories', 'w' )
    json.dump(y_categories, f)
    f.close()
    print(accounting)
    for acc_id in accounting:
        print('\n')
        print(acc_id)
        df = pd.DataFrame(accounting[acc_id]['latency'])
        print('latency')
        print('%%.25: %f'%(df.quantile(0.25)))
        print('%%.50: %f'%(df.quantile(0.5)))
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


    return pid_yPos_dic

