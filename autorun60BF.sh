#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)



INDEX=17

for k in {1..2}
do
	
    for i in {2..3}
    do
        #echo "Starting $i wf-configNG-v2BOF$(($INDEX)).cfg"
        #bash ./invoke_whitefield.sh config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv3Norm$(($INDEX))-v2-r$i.txt
        #bash ./scripts/wfshell stop_whitefield
        #mv log log-ids-v7Norm$(($INDEX))-r$i
	#mv pcap pcapv3-Norm$(($INDEX))-r$i
	echo "BOF.."
	bash ./invoke_whitefield.sh config/wf-configNG-60BOF$(($INDEX))n.cfg && sleep 3600
	./scripts/mac_stats.sh > statsofnodes/statsv5BOF$(($INDEX))-v2-r$i.txt
	bash ./scripts/wfshell stop_whitefield
	mv log log-ids-v41n60BOF$(($INDEX))n-r$i
	mv pcap pcapv16n-60BOF$(($INDEX))n-r$i
	#echo "BHOF.."
	#bash ./invoke_whitefield.sh config/wf-configNG-60BH$(($INDEX))n.cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv5BH$(($INDEX))-v2-r$k.txt
	#bash ./scripts/wfshell stop_whitefield
	#mv log log-ids-v41n60BH$(($INDEX))-r$k
	#mv pcap pcapv16n-60BH$(($INDEX))-r$k
	
	#bash ./invoke_whitefield.sh config/small/wf-configNG-v2BH$(($INDEX)).cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv4BH$(($INDEX))-v2-r$i.txt
	#bash ./scripts/wfshell stop_whitefield
	#mv log log-ids-v38BH$(($INDEX))-r$i
	#mv pcap pcapv15-BH$(($INDEX))-r$i
	echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done

