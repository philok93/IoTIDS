#!/bin/bash

INDEX=5
TOTAL=37

for i in {1..10}
do
    echo "Starting $i"
    bash ./invoke_whitefield.sh ./config/small/wf-contiki-ngNorm$(($INDEX)).cfg && sleep 3600
    #BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-Norm$(($INDEX)).png p$i-Norm$(($INDEX)).png scale=20
    #mv *.png pics/small/
    for j in $(seq 0 $((TOTAL-1)));
	do
		./scripts/wfshell cmd_mac_stats $j > statsofnodes/statsNorm$(($INDEX))-node$j-$i.txt
	done
    bash ./scripts/wfshell stop_whitefield
    mv log logv2-ids-Norm$(($INDEX))-$i
    mv pcap pcap-BOF$(($INDEX))-r$i
    echo "Stopped $i"
    INDEX=$((INDEX+1))
    TOTAL=$((TOTAL+1))
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
