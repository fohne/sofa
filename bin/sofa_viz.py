import os
import subprocess
import sys
import glob
from functools import partial

from sofa_config import *
from sofa_print import *
from DDS.ds_create_viz import ds_create_viz

def sofa_viz(cfg):
    sofa_home = os.path.dirname(os.path.realpath(__file__))
    if cfg.ds:
        ds_logpath = cfg.logdir + "ds_finish/"
        os.chdir(ds_logpath)
        nodes_record_dir = glob.glob('[0-9]*')
        ds_create_viz(ds_logpath, nodes_record_dir)
       
        for i in range(len(nodes_record_dir)):
            ds_logdir = './' + str(nodes_record_dir[i]) + '/'



    else:
        subprocess.Popen(
            ['bash', '-c', 'cp %s/../sofaboard/* %s;' % (sofa_home, cfg.logdir)])
    
    
     
    subprocess.Popen(['sleep', '2'])
    print_warning(
        'If your rendering timeline is slow, please try \033[4msofa report --plot_ratio=10\033[24m to downsample scatter points,')
    print_warning('and then \033[4msofa viz\033[24m to see the downsampled results.')
    print_hint('SOFA Vlization is listening on port \033[4m\033[97mhttp://localhost:%d\033[24m\033[0m\033[24m' % (cfg.viz_port) )
    print_hint('To change port, please run command: \033[4msofa viz --viz_port=PortNumber\033[24m')
    print_hint('Please open your browser to start profiling.')
    print_hint('After profiling, please enter Ctrl+C to exit.')

    if cfg.ds:
        print(ds_logpath)
        os.system('pwd')
        os.system(
        ' python3 -m http.server %d 2>&1 1> /dev/null;' %
        (cfg.viz_port))
    else:
        os.system(
        'cd %s && python3 -m http.server %d 2>&1 1> /dev/null; cd -' %
        (cfg.logdir,cfg.viz_port))
