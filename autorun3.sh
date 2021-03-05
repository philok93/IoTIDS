#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)

INDEX=7
for i in {9..10}
do
	echo "BOF.."
	bash ./invoke_whitefield.sh config/small/wf-configNG-v2RBOF$(($INDEX)).cfg && sleep 3600
	bash ./scripts/wfshell stop_whitefield
	mv log log-ids-v41nRBOF$(($INDEX))-r$i
        mv pcap pcapv16n-RBOF$(($INDEX))-r$i
	echo "STOP $i"

done

INDEX=8
for k in {1..8}
do
	
    for i in {6..10}
    do
        #echo "Starting $i wf-configNG-v2BOF$(($INDEX)).cfg"
        #bash ./invoke_whitefield.sh config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv3Norm$(($INDEX))-v2-r$i.txt
        #bash ./scripts/wfshell stop_whitefield
        #mv log log-ids-v7Norm$(($INDEX))-r$i
	#mv pcap pcapv3-Norm$(($INDEX))-r$i
	echo "BOF.."
	bash ./invoke_whitefield.sh config/small/wf-configNG-v2RBOF$(($INDEX)).cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv4BOF$(($INDEX))-v2-r$i.txt
	bash ./scripts/wfshell stop_whitefield
	mv log log-ids-v41nRBOF$(($INDEX))-r$i
	mv pcap pcapv16n-RBOF$(($INDEX))-r$i
	#bash ./invoke_whitefield.sh config/small/wf-configNG-v2BH$(($INDEX)).cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv4BH$(($INDEX))-v2-r$i.txt
	#bash ./scripts/wfshell stop_whitefield
	#mv log log-ids-v38BH$(($INDEX))-r$i
	#mv pcap pcapv15-BH$(($INDEX))-r$i
	echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done

