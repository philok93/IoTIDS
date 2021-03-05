#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)

INDEX=11
TOTAL=46

for k in {1..2}
do
    for i in {1..10}
    do
        echo "Starting $i wf-configNG-BH$(($INDEX)).cfg"
        bash ./invoke_whitefield.sh config/small/wf-configNG-BH$(($INDEX)).cfg && sleep 3600
        BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph tree-r$i-BH$(($INDEX)).png plot-r$i-BH$(($INDEX)).png scale=20
        mv *.png pics/small/
        for j in $(seq 0 $((TOTAL-1)));
        do
            ./scripts/wfshell cmd_mac_stats $j > statsofnodes/statsBH$(($INDEX))-node$j-r$i.txt
        done
        bash ./scripts/wfshell stop_whitefield
        mv log log-ids-BH$(($INDEX))-r$i
        echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
    TOTAL=$((TOTAL+1))
done

