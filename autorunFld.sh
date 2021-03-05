#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)

#changed 8 to 13 to check new perc.


INDEX=12
for i in {1..1}
do
	echo "start Fld$(($INDEX)).cfg"
	bash ./invoke_whitefield.sh config/small/wf-configNG-v2FlOF$(($INDEX)).cfg && sleep 3600
	bash ./scripts/wfshell stop_whitefield
	mv log log-ids-v42FlOF$(($INDEX))-r$i
	mv pcap pcapv15-FlOF$(($INDEX))-r$i

	
done

INDEX=13

for k in {1..3}
do
    for i in {4..4}
    do
        echo "Starting $i wf-configNG-v2FlOFd$(($INDEX)).cfg"
        bash ./invoke_whitefield.sh config/small/wf-configNG-v2FlOF$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv3Norm$(($INDEX))-v2-r$i.txt
        bash ./scripts/wfshell stop_whitefield
        mv log log-ids-v41FlOF$(($INDEX))-r$i
	mv pcap pcapv14-FlOF$(($INDEX))-r$i
	#echo "BOF..$k-$i"
	#bash ./invoke_whitefield.sh config/small/wf-configNG-v2Fld$(($INDEX)).cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv4Fld$(($INDEX))-v2-r$i.txt
	#bash ./scripts/wfshell stop_whitefield
	#mv log log-ids-v41Fld$(($INDEX))-r$i
	#mv pcap pcapv14-Fld$(($INDEX))-r$i
	
	#bash ./invoke_whitefield.sh config/small/wf-configNG-v2BH$(($INDEX)).cfg && sleep 3600
	#./scripts/mac_stats.sh > statsofnodes/statsv4BH$(($INDEX))-v2-r$i.txt
	#bash ./scripts/wfshell stop_whitefield
	#mv log log-ids-v40BH$(($INDEX))-r$i
	#mv pcap pcapv14-BH$(($INDEX))-r$i
	#echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done
