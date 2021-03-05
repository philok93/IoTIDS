#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)


INDEX=13

for k in {1..3}
do
    for i in {1..3}
    do
        echo "Starting $i wf-configNG-v2BOF$(($INDEX)).cfg"
        bash ./invoke_whitefield.sh config/small/wf-configNG-v2BOF$(($INDEX)).cfg && sleep 3600
        #./scripts/wfshell plot_network_graph tree-r$i-BOF$(($INDEX)).png plot-r$i-BOF$(($INDEX)).png scale=20
        #mv *.png pics/small/
        ./scripts/mac_stats.sh > statsofnodes/statsv2BOF$(($INDEX))-v2-r$i.txt
        bash ./scripts/wfshell stop_whitefield
        mv log log-ids-v41nBOF$(($INDEX))-r$i
	mv pcap pcap16n-BOF$(($INDEX))-r$i
 	echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done
