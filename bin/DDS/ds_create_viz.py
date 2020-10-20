import os
def ds_create_viz(ds_logpath, nodes_record_dir):
    sofa_home = os.path.dirname(os.path.realpath(__file__))
    #os.system('cp %s/../sofaboard/ds_index_template ./' % sofa_home)
    #os.system('cp %s/../sofaboard/timeline.js ./' % sofa_home)
    
    f = open('%s/../../sofaboard/ds_index_template' % sofa_home ,'r')
    index = f.read()
    f.close()
    loc = index.find('<!--BODY-->')
    loc = loc + len('<!--BODY-->')
    top_index = index[:loc]
    bottom_index = index[loc:]
    

    f = open('%s/../../sofaboard/timeline.js' % sofa_home)
    timeline = f.read()
    f.close
    replace_string = ''
    for i in range(len(nodes_record_dir)):

        f = open ('%s/pid2ip.txt'%nodes_record_dir[i])
        node_ip = f.read()
        node_ip = node_ip.split()
        node_ip = node_ip[1]
        f.close()

        top_index = top_index + '\n        <div id="container%s" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>' % nodes_record_dir[i]
        #top_index = top_index + '\n        <script src="hl%s.js"></script>' % nodes_record_dir[i]
        top_index = top_index + '\n        <script src="report%s.js"></script>' % nodes_record_dir[i]
        top_index = top_index + '\n        <script src="outlier%s.js"></script>' % nodes_record_dir[i]
        top_index = top_index + '\n        <script src="timeline%s.js"></script>' % nodes_record_dir[i]

        f = open ('%s/topic_lat_report_cnt.txt'%nodes_record_dir[i])
        report_cnt = int(f.readline())
        f.close()
        top_index = top_index + '\n        <center>'
        for cnt in range(report_cnt):
            top_index = top_index + '\n        <embed style="width:19%%; height:250px;" src="%s/topic_lat_report%s.txt">' % (nodes_record_dir[i],str(cnt+1))
        top_index = top_index + '\n        </center>' 
        replace_string = timeline.replace('container', 'container%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('sofa_traces', 'sofa_traces%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('outlier', 'outlier%s' % nodes_record_dir[i])
        replace_string = replace_string.replace('Time Versus Functions and Events', 'Functions and Events Timeline on Node %s' % node_ip)

        f = open('timeline%s.js' % nodes_record_dir[i], 'w')
        f.write(replace_string)
        os.system('cp %s/outlier.js ./outlier%s.js' % (nodes_record_dir[i], nodes_record_dir[i]))
        os.system('cp %s/hl.js ./hl%s.js' % (nodes_record_dir[i], nodes_record_dir[i]))
        os.system('cp %s/report.js ./report%s.js' % (nodes_record_dir[i], nodes_record_dir[i]))
        f.close()
        pass
    
    f = open('%s/../../sofaboard/connect_timeline.js' % sofa_home)
    connection_view_timeline = f.read()
    f.close()
    connection_view_timeline = connection_view_timeline.replace('Node Connection View in Distributed System', 'OpenSplice Node Connection View')
    loc = connection_view_timeline.find("// categories: ['A', 'B'],")
    loc = loc + len("// categories: ['A', 'B'],")
    top_connection_view_timeline = connection_view_timeline[:loc]
    bottom_connection_view_timeline = connection_view_timeline[loc:]
    os.system('pwd')
    f = open('y_categories')
    y_categories = f.read()
    
    y_categories = 'categories: ' + y_categories + ','
    top_connection_view_timeline = top_connection_view_timeline + '\n    %s' % y_categories
    connection_view_timeline = top_connection_view_timeline + bottom_connection_view_timeline

    f = open('connect_timeline.js', 'w')
    f.write(connection_view_timeline)
    f.close()  
    top_index = top_index + \
              '\n        <div id="container" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>'
    top_index = top_index + '\n        <script src="connect_view_data.js"></script>'
    top_index = top_index + '\n        <script src="connect_timeline.js"></script>\n'

####  Span
    f = open('%s/../../sofaboard/connect_timeline.js' % sofa_home)
    span_view_timeline = f.read()
    f.close()
    span_view_timeline = span_view_timeline.replace('container', 'container_span')
    span_view_timeline = span_view_timeline.replace('sofa_traces_connect', 'sofa_traces_span')
    span_view_timeline = span_view_timeline.replace('Nodes', 'Spans')
    span_view_timeline = span_view_timeline.replace('Node Connection View in Distributed System', 'OpenSplice Data Trace Spans')

    f = open('span_timeline.js', 'w')
    f.write(span_view_timeline)
    f.close()  
    top_index = top_index + \
              '\n        <div id="container_span" style="min-width: 310px; height: 400px; max-width: 90%%; margin: 0 auto"></div>'
    top_index = top_index + '\n        <script src="span_view.js"></script>'
    top_index = top_index + '\n        <script src="span_timeline.js"></script>\n'


    index = top_index + bottom_index
    f = open('./index.html', 'w')
    f.write(index)
    f.close()

