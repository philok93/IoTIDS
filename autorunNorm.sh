#!/bin/bash

INDEX=5
for k in {1..5}
do
	for i in {4..10}
	do
		echo "BOF.."
		bash ./invoke_whitefield.sh config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv4BOF$(($INDEX))-v2-r$i.txt
		bash ./scripts/wfshell stop_whitefield
        	mv log log-ids-v43Norm$(($INDEX))-r$i
        	mv pcap pcapv17-Norm$(($INDEX))-r$i
		echo "Stopped $i"
	done
	INDEX=$((INDEX+1))
done

INDEX=11


for k in {1..2}
do

    for i in {4..9}
    do
        #echo "Starting $i wf-configNG-v2BOF$(($INDEX)).cfg"
        #bash ./invoke_whitefield.sh config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv3Norm$(($INDEX))-v2-r$i.txt
        #bash ./scripts/wfshell stop_whitefield
        #mv log log-ids-v7Norm$(($INDEX))-r$i
        #mv pcap pcapv3-Norm$(($INDEX))-r$i
        echo "BOF.."
        bash ./invoke_whitefield.sh config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv4BOF$(($INDEX))-v2-r$i.txt
        bash ./scripts/wfshell stop_whitefield
        mv log log-ids-v43Norm$(($INDEX))-r$i
        mv pcap pcapv17-Norm$(($INDEX))-r$i
        #bash ./invoke_whitefield.sh config/small/wf-configNG-v2BH$(($INDEX)).cfg && sleep 3600
        #./scripts/mac_stats.sh > statsofnodes/statsv4BH$(($INDEX))-v2-r$i.txt
        #bash ./scripts/wfshell stop_whitefield
        #mv log log-ids-v38BH$(($INDEX))-r$i
        #mv pcap pcapv15-BH$(($INDEX))-r$i
        echo "Stopped $i"
    done

    INDEX=$((INDEX+1))
done


# for i in {1..2}
# do
#     echo "Starting $i"
#     bash ./invoke_whitefield.sh ./config/wf-contiki-ngB-25v21.cfg && sleep 2600
#     BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-B25v21.png p$i-B25v21.png scale=20
#     for j in {1..27}
# 	do
# 		./scripts/wfshell cmd_mac_stats $(($j-1)) > statsofnodes/statsB25v21-node$j-$i.txt
# 	done
#     bash ./scripts/wfshell stop_whitefield
#     mv log log-ids-B-25v21-$i
#     echo "Stopped $i"
# done

# for i in {1..2}
# do
#     echo "Starting $i"
#     bash ./invoke_whitefield.sh ./config/wf-contiki-ngN-25v21.cfg && sleep 2600
#     BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-N25v21.png p$i-N25v21.png scale=20
#     for j in {1..22}
# 	do
# 		./scripts/wfshell cmd_mac_stats $(($j-1)) > statsofnodes/statsN25v21-node$j-$i.txt
# 	done
#     bash ./scripts/wfshell stop_whitefield
#     mv log log-ids-N-25v21-$i
#     echo "Stopped $i"
# done
