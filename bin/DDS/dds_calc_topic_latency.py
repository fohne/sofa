import csv
import glob
import os
import re
import pandas as pd   
import json
from statistics import *

class Point:
    xAxis = []
    yAxis = []
    x = []
    y = []
class LabelAnnotation:

    text = []


def annotating_traces_to_json(traces, path):
    if len(traces) == 0:
        print_warning("Empty traces!")
        return
    with open(path, 'w') as f:
        for trace in traces:
            label = LabelAnnotation()
            label.point['x'] = trace[0]
            label.point['xAxis'] = 0
            label.point['y'] = trace[1]
            label.point['yAxis'] = 0
            label.text = "Trace ID :[" + str(trace[2]) + "]" + "Latency: [" + str(trace[3]) + "]"

            json.dump(label, f)
           


def dds_calc_topic_latency(cfg):
    logdir = cfg.logdir
    dds_trace_field = ['timestamp', 'start_ts', 'end_ts', 'record_type', 'tgid', 'tid', 'fun_ID', 'topic_name', 'comm', 'seq', 
                   'gid_sys', 'gid_local', 'gid_seria', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5', 'arg6', 'link', 'ret']

    all_dds_df = pd.DataFrame([], columns=dds_trace_field)

    pid_yPos_dic = {} 
    yPos_cnt = 0
    pid_ip_dic = {}
    
    adjust_list = []
    en_adjust = 0
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

        dds_df = pd.read_csv('%s/dds_trace_%s'%(nd_dir_iter, nd_dir_iter), sep=',\s+', delimiter=',', encoding="utf-8",
                            skipinitialspace=True, header=0, float_precision='round_trip')

        all_dds_df = pd.concat([dds_df, all_dds_df], ignore_index=True, sort=False)

        yPos_cnt += 1

    all_dds_df.sort_values(by='start_ts', inplace=True)
    all_dds_df.to_csv('processed_dds_record', mode='w', index=False, float_format='%.9f')
    print('DDS raw data preprocess done')
    de_noise = all_dds_df.values.tolist()
    max_cnt = 0
    for command in command_dic:

        cnt = False

        for i in range(len(de_noise)):
            if de_noise[i][8].find(command) !=-1:
                cnt = i

                break
        if cnt and cnt > max_cnt:
            max_cnt = cnt

    de_noise = de_noise[max_cnt:]
    all_dds_df = pd.DataFrame(de_noise, columns=dds_trace_field)


    y = [0,0,0,0,0,0,0,0,0,0,0,0,0]

  

### Not really important, just nickname for sender and receiver records.
    filter = all_dds_df['fun_ID'] == 1
    all_send_df = all_dds_df[filter]
    #all_send_df = all_send_df.apply(lambda x: x if (x['comm'].find('xmit.user')>-1) else None, result_type='broadcast', axis=1)
    all_send_df = all_send_df.dropna()	

    all_send_df.to_csv('all_dds_send', mode='w', index=False, float_format='%.9f')
    all_send_list = all_send_df.values.tolist()

    filter = all_dds_df['fun_ID'] == 7
    all_recv_df = all_dds_df[filter]
    all_recv_df.to_csv('all_dds_recv', mode='w', index=False, float_format='%.9f')
    all_recv_list = all_recv_df.values.tolist()


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


#['timestamp', 'comm', 'topic_name', 'tgid','tid','fid','topic_p','writer_p',
#    'data_p', 'winfo_p', 'v_msg', 'gid_sys', 'gid_local', 'gid_seria', 'seq']

# DS/DDS trace field name
# 0: Timestamp       # 3: record_type       # 6: fun_ID            # 9: seq          # 12: gid_seria         # 20: ret
# 1: start_TS        # 4: tgid              # 7: topic_name        # 10: gid_sys     # 13 ~ 18: arg1 ~ arg6 
# 2: end_TS          # 5: tid               # 8: comm              # 11: gid_local   # 19: link   

        send_identifier = str(send_tmp[7]) + str(send_tmp[10]) + str(send_tmp[11]) + \
                               str(send_tmp[12]) + str(send_tmp[9])
        if send_identifier not in feature_send_dic:
            feature_send_dic[send_identifier] = [1, send_cnt]
            send_canidate[send_cnt] = True
        else:
            feature_send_dic[send_identifier][0] += 1
            send_canidate[feature_send_dic[send_identifier][1]] = False
    #        send_canidate[send_cnt] = True
                             
    recv_canidate = [False] * len(all_recv_list)
    feature_recv_dic = {}
    for recv_cnt in range(len(all_recv_index_list)):
        recv_tmp = all_recv_index_list[recv_cnt][0]
        recv_identifier = str(recv_tmp[7]) + str(recv_tmp[10]) + str(recv_tmp[11]) + \
                               str(recv_tmp[12]) + str(recv_tmp[9])
        if recv_identifier not in feature_recv_dic:
            feature_recv_dic[recv_identifier] = [1, recv_cnt]
            recv_canidate[recv_cnt] = True
        else:
            feature_recv_dic[recv_identifier][0] += 1
            recv_canidate[feature_recv_dic[recv_identifier][1]] = False
#            recv_canidate[recv_cnt] = True

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

    who = 0
    match_cnt, latency_cnt = 0,0

    # Loop control paremeters
    latency, retry, negative = 1, True, False 
    neg_who_dic = {} # []
    accounting = {}
    latency_table = {}
    
    while retry:
        retry = False

        for recv_cnt in range(len(all_recv_index_list)):
            if not recv_canidate[all_recv_index_list[recv_cnt][1]]:
                continue

            recv_tmp = all_recv_index_list[recv_cnt][0]
            recv_identifier = str(recv_tmp[7]) + str(recv_tmp[10]) + str(recv_tmp[11]) +  \
                                   str(recv_tmp[12]) + str(recv_tmp[9])

            sfind = False
            for send_cnt in range(len(all_send_index_list)):
                if not send_canidate[all_send_index_list[send_cnt][1]]:
                #if  send_find[all_send_index_list[send_cnt][1]]:
                    continue

                send_tmp = list(all_send_index_list[send_cnt][0])
                if  recv_tmp[0] - send_tmp[0] < 0:
                    pass #break
                send_identifier = str(send_tmp[7]) + str(send_tmp[10]) + str(send_tmp[11]) + \
                                       str(send_tmp[12]) + str(send_tmp[9])

                if (recv_identifier == send_identifier):
                    #print(send_identifier)
                    sfind = send_cnt
                    match_cnt += 1
                    #print(recv_tmp[0] - send_tmp[0])
                    #print(match_cnt)
                    acc_id = "Topic:{"+str(send_tmp[7]) +"} from " + pid_ip_dic[str(send_tmp[4])] + " to " + pid_ip_dic[str(recv_tmp[4])]
                    if acc_id not in accounting:
                        accounting[acc_id] = {}
                        accounting[acc_id]['latency'] = []
                        accounting[acc_id]['from'] = send_tmp[4]
                        accounting[acc_id]['to'] = recv_tmp[4]
                        accounting[acc_id]['topic'] = str(send_tmp[7])
                        latency_table[acc_id] =[]
          
                    accounting[acc_id]['latency'].append(recv_tmp[1] - send_tmp[1])
                    latency_table[acc_id].append([recv_tmp[4],send_tmp[4],recv_tmp[1],recv_tmp[6],send_tmp[1],send_tmp[6],recv_tmp[1] - send_tmp[1],latency_cnt])
                    latency_cnt +=1
                  
                    break;


### ------- Account ambibuous record (need to be filter out before making connection trace)
            if sfind:

                send_select = all_send_index_list[sfind][1]
                recv_select = all_recv_index_list[recv_cnt][1]

                del all_send_index_list[sfind]
                send_find[send_select] = True
                recv_find[recv_select] = True


# --------- END if sfind:
# ----- END for recv_cnt in range(recv_cnt_skip, len(all_recv_index_list)):
# - END while retry:



    result_send_list = []
    result_recv_list = []
    for i in range(len(all_send_index_list)):
        result_send_list.append(all_send_index_list[i][0])

    for i in range(len(all_recv_index_list)):
        result_recv_list.append(all_recv_index_list[i][0])


    recv_nfind = [not i for i in recv_find]
    send_nfind = [not i for i in send_find]

    recv_not_find = all_recv_df[recv_nfind]
    send_not_find = all_send_df[send_nfind]
    all_not_df = pd.concat([send_not_find, recv_not_find], ignore_index=True, sort=False)

    all_not_df.sort_values(by='timestamp', inplace=True)
    all_not_df.to_csv('nfound', mode='w', index=False, float_format='%.9f')

    analysis_cnt_dic = {}
    outlier = []
    os.system('pwd')
    for acc_id in accounting:
        df = pd.DataFrame(accounting[acc_id]['latency'])

        from_pid = accounting[acc_id]['from']

        if from_pid not in analysis_cnt_dic:
            analysis_cnt_dic[from_pid] = 0
        analysis_cnt_dic[from_pid] += 1

        f = open('%s/topic_lat_report%s.txt' % (from_pid, analysis_cnt_dic[from_pid]),'w')

        f.write('Topic: %s\n' % accounting[acc_id]['topic'])
        f.write('From:  %s\n' % pid_ip_dic[str(accounting[acc_id]['from'])])
        f.write('To:    %s\n\n' % pid_ip_dic[str(accounting[acc_id]['to'])])

        f.write('Latency\n')

        f.write('%%.25: %f\n'%(df.quantile(0.25)))
        f.write('%%.50: %f\n'%(df.quantile(0.5)))
        f.write('%%.75: %f\n'%(df.quantile(0.75)))
        f.write('%%.95: %f\n'%(df.quantile(0.95)))
        f.write('%%1.0: %f\n\n'%(df.quantile(1)))

        mean_result = df.mean()
        f.write('mean:      %f\n'%mean_result)
        f.write('pstdev:    %f\n'%(pstdev(df[0][0:])))
        f.write('pvariance: %f\n'%(pvariance(df[0][0:2])))

        result_stdev = stdev(df[0][0:])
        f.write('stdev:     %f\n'%result_stdev)

        for i in range(df.size):
            if (float(df[0][i]) > (float(mean_result) +  float(result_stdev*3))):
                outlier.append(latency_table[acc_id][i])
        f.close()
#    rpid     spid      rx       ry        sx       sy        lag      id
#[recv_pid, send_pid, recv_ts, recv_fid, send_ts, send_fid, latancy, index]
    for i in analysis_cnt_dic:
        f = open('%s/topic_lat_report_cnt.txt'%i,'w')
        f.write('%s\n' % str(analysis_cnt_dic[i]))
        f.close()

    for i in outlier:
        pass
        #print(i)


    for nd_dir_iter in nodes_dir:
        out_trace = []
        f = open ('%s/outlier.js'%nd_dir_iter, 'w')
        for i in outlier:
            #print("%d,%d"%(i[0],int(nd_dir_iter)))
            if (i[0] == int(nd_dir_iter)):
                out_trace.append([i[2],i[3],i[6],i[7]])
            if (i[1] == int(nd_dir_iter)):
                out_trace.append([i[4],i[5],i[6],i[7]])
        f.write("outlier = [")
        for i in range(len(out_trace)):
            print(out_trace[i])
          #  f.write("{point: {x: %f,y: %f,xAxis:0,yAxis:0},text: \"(%f,%f)<br/>%s %fms\"}"%(out_trace[i][0],out_trace[i][1],out_trace[i][0],out_trace[i][1],"label:"+str(out_trace[i][3])+" <br/>latency:",out_trace[i][2]*1000))
            f.write("{visible: true,labels: [{shape: 'connector', point: {x: %f,y: %f,xAxis:0,yAxis:0},text: \"%s %f ms\"}]}"%(out_trace[i][0],out_trace[i][1],"label:"+str(out_trace[i][3])+" <br/>latency:",out_trace[i][2]*1000))
            if i != (len(out_trace) - 1):
                f.write(',\n')
        f.write("]\n\n")
        f.write("outlier%d = outlier" % int(nd_dir_iter))
        f.close()
        print('\n\n')
         



    color_table = ['255,173,173','255,214,165','253,255,182','202,255,191','155,246,255','160,196.255','189,178,255','255,198,255']

    for nd_dir_iter in nodes_dir:
        out_trace = []
        for i in outlier:
            #print("%d,%d"%(i[0],int(nd_dir_iter)))
            if (i[0] == int(nd_dir_iter)):
                out_trace.append([i[2],i[3],i[6],i[7]])
            if (i[1] == int(nd_dir_iter)):
                out_trace.append([i[4],i[5],i[6],i[7]])


        f = open ('%s/hl.js'%nd_dir_iter, 'w')

        f.write("hl%d  = {\
                       name: 'Highlight',\
                       marker:{radius: 3},\
                       tooltip: {\
                       headerFormat: '<b>{series.name}</b><br>',\
                       pointFormat: '{point.x} , {point.y},<br> {point.lan}'\
                       },\
                       data: [" % int(nd_dir_iter)) 
        for i in range(len(out_trace)):
            color_index = out_trace[i][3] % len(color_table)
            f.write("{x:%f, y:%f,lan:%f ,color:'rgba(%s,.8)'}" % (out_trace[i][0], out_trace[i][1], out_trace[i][2],color_table[color_index])) 

            if i != (len(out_trace) - 1):

                f.write(',\n')
        f.write("]  }\n\n")
        #f.write("hl%d = hl" % int(nd_dir_iter))
        f.close()
        print('\n\n')
    


    print('\nTotal match count: %s'%match_cnt)
    return (float(mean_result) +  float(result_stdev*3))
