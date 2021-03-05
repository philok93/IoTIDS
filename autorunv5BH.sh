#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)


INDEX=5


for k in {1..15}
do
    for i in {1..5}
    do
        echo "Starting $i wf-configNG-v2BH$(($INDEX)).cfg"
        bash ./invoke_whitefield.sh config/small/wf-configNG-v2BH$(($INDEX)).cfg && sleep 3600
        #BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph tree-r$i-BOF$(($INDEX)).png plot-r$i-BOF$(($INDEX)).png scale=20
        #mv *.png pics/small/
        ./scripts/mac_stats.sh > statsofnodes/statsv3BH$(($INDEX))-v2-r$i.txt
        bash ./scripts/wfshell stop_whitefield
        mv log t2log-ids-v5BH$(($INDEX))-r$i
	mv pcap pcap-v5BH$(($INDEX))-r$i
        echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done
