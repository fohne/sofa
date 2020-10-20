#!/usr/bin/python3
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

from sofa_config import *
from sofa_preprocess import sofa_preprocess
from .sofa_ds_preprocess import ds_connect_preprocess
from .sofa_ds_preprocess import ds_dds_create_span
from .dds_calc_topic_latency import dds_calc_topic_latency

class DSTrace:
    data = []
    name = []
    title = []
    color = []
    x_field = []
    y_field = []

def ds_preprocess(cfg):
    save_logdir = cfg.logdir
    ds_logpath = cfg.logdir + "ds_finish/"
    os.chdir(ds_logpath)
    nodes_record_dir = glob.glob('[0-9]*')
    
    sofa_timebase_min = 0
    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        if (sofa_timebase_min == 0):
            sofa_timebase_min = unix_time

        if unix_time < sofa_timebase_min:
            sofa_timebase_min = unix_time

    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        cfg.cpu_time_offset = 0
        if (unix_time > sofa_timebase_min):
            basss = float(sofa_timebase_min) - float(unix_time)
            if basss < -28700:
                basss += 28800
            cfg.cpu_time_offset = basss
            #cfg.cpu_time_offset = float(sofa_timebase_min) - float(unix_time)
            print("%d, %f" %(int(nodes_record_dir[i]),cfg.cpu_time_offset))

        cfg.logdir = './' + str(nodes_record_dir[i]) + '/'
        sofa_preprocess(cfg)
        cfg.logdir = save_logdir

    pid2y_pos_dic = ds_connect_preprocess(cfg)
    dds_calc_topic_latency(cfg)
    ds_dds_create_span(cfg)

