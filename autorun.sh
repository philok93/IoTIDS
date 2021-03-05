#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)


INDEX=6

for k in {1..7}
do
    for i in {1..3}
    do
        echo "Starting $i wf-configNG-v2NBOF$(($INDEX)).cfg"
        bash ./invoke_whitefield.sh config/small/wf-configNG-v2BOF$(($INDEX)).cfg && sleep 3600
        ./scripts/mac_stats.sh > statsofnodes/statsv2NBH$(($INDEX))-r$i.txt
        #done
        bash ./scripts/wfshell stop_whitefield
        mv log t2log-ids-v2NBH$(($INDEX))-r$i
        echo "Stopped $i"
    done

    INDEX=$((INDEX+1))

done

