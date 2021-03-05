#!/bin/bash
# STOP_WF=$(./scripts/wfshell stop_whitefield)

INDEX=25

for k in {1..1}
do
	for i in {3..3}
	do
		
		echo "Starting $i wf-configNG-v120FlMix$(($INDEX)).cfg"
		bash ./invoke_whitefield.sh config/small/wf-configNG-120BOF$(($INDEX)).cfg && sleep 3600
		#./scripts/mac_stats.sh > statsofnodes/statsNBH$(($INDEX))-r$i.txt
		bash ./scripts/wfshell stop_whitefield
		mv pcap pcapv3-120mFlB$(($INDEX))-r$i
		mv log log120-ids3m-FlB$(($INDEX))-r$i
		echo "Stopped $i.. Start BH"
		#bash ./invoke_whitefield.sh config/small/wf-configNG-120v2BH$(($INDEX)).cfg && sleep 3600
		#./scripts/mac_stats.sh > statsofnodes/statsNBH$(($INDEX))-r$i.txt
		#bash ./scripts/wfshell stop_whitefield
		#mv pcap pcapv3-120nFlBH$(($INDEX))-r$i
		#mv log log120-ids3n-FlBH$(($INDEX))-r$i
		#echo "Stopped $i"
		#echo "Starting $i wf-configNG-v120Norm$(($INDEX)).cfg"
		#bash ./invoke_whitefield.sh config/small/wf-configNG-120Norm$(($INDEX)).cfg && sleep 3600
		##./scripts/mac_stats.sh > statsofnodes/statsNBH$(($INDEX))-r$i.txt
		#bash ./scripts/wfshell stop_whitefield
		#mv pcap pcapv3m-Norm$(($INDEX))-r$i
		#mv log log120-ids3m-Norm$(($INDEX))-r$i
		#echo "Stopped $i"
	done

	INDEX=$((INDEX+1))
done
