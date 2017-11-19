import csv
import matplotlib
import numpy as np
import hashlib
import sys

from matplotlib import pyplot as plt

class Trace:
    name="";
    id=0;
    timestamp=0.0; 
    color=""; 
    radii=1;
traces=[];

def get_name_by_id(id):
    for trace in traces:
        if id == trace.id: 
            return trace.name  
    return ""



print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv) 

if len(sys.argv) < 2:
    print("Usage: potato report.csv")
    print("However, potato will read default.csv instead.")
    filein = 'report.csv' 
else:
    filein = sys.argv[1]

with open(filein) as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        trace = Trace() ;
        trace.timestamp = float(row['timestamp']) 
        trace.id  = int(row['func_id'])
        trace.name = row['func_name']
        trace.color = row['color']
        traces.append(trace)

fig = plt.figure()
ax = fig.add_subplot(111)
for trace in traces:
    line, = ax.plot( trace.timestamp, trace.id, 'o', color=trace.color, picker=5)  # 5 points tolerance
def onpick(event):
    thisline = event.artist
    xdata = thisline.get_xdata()
    ydata = thisline.get_ydata()
    ind = event.ind
    points = tuple(zip(xdata[ind], ydata[ind]))
    print('onpick points:', points, get_name_by_id(ydata[ind]))
fig.canvas.mpl_connect('pick_event', onpick)
plt.xlabel('Time (s)')
plt.ylabel('Kernel Event ID')
plt.show()
