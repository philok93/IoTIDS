#!/bin/bash

# START_WF=$(./invoke_whitefield.sh ./config/wf-contiki-ng.cfg && sleep 1250)
# STOP_WF=$(./scripts/wfshell stop_whitefield)


for i in {1..4}
do
    echo "Starting $i"
    bash ./invoke_whitefield.sh ./config/wf-contiki-ngBOF.cfg && sleep 1500
    BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-BOF.png p$i-BOF.png scale=20
    bash ./scripts/wfshell stop_whitefield
    mv log log-ids-BOF-$i
    echo "Stopped $i"
done

for i in {1..2}
do
    echo "Starting $i"
    bash ./invoke_whitefield.sh ./config/wf-contiki-ngN.cfg && sleep 1500
    BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-norm.png p$i-norm.png scale=20
    bash ./scripts/wfshell stop_whitefield
    mv log log-ids-norm-$i
    echo "Stopped $i"
done

for i in {1..2}
do
    echo "Starting $i"
    bash ./invoke_whitefield.sh ./config/wf-contiki-ngB.cfg && sleep 1500
    BRCOLOR=cadetblue1 DEFCOLOR=chocolate1 ./scripts/wfshell plot_network_graph t$i-B.png p$i-B.png scale=20
    bash ./scripts/wfshell stop_whitefield
    mv log log-ids-B-$i
    echo "Stopped $i"
done

