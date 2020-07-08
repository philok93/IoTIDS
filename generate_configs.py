
config_name=5
ids=6 #5-15 IDS nodes
normal=39  # 30 normal
blackh=9 # 3 blackhole



for i in range(0,11):
	with open("wf-configNG-BH"+str(config_name)+".cfg","w") as f:	
		body="numOfNodes="+str(normal+1)+"\n\nfieldX=70  #field space in x direction ... currently 2D model is supp only, used in random\nfieldY=70\n"\
		"topologyType=randrect	#grid, randrect (ns3 RandomRectanglePositionAllocator)\ngridWidth=4  #Grid topology width if the topologyType=grid\n"\
		"\nnodePromiscuous[2-"+str(ids)+"]=1 #Sets promiscuous mode for node"\
		"panID=0xabcd\nNS3_captureFile=pcap/pkt\nmacPktQlen=20	#Maximum number of packets that can be outstanding on mac layer\n"\
		"macMaxRetry=3		#Max number of times the mac packet will be retried\n"\
		"\n\nnodeExec[0]=thirdparty/contiki-ng/examples/rpl-udp/udp-server-in0.whitefield $NODEID AUTO_START=1 #NORMAL SERVER\n"\
		"nodeExec[1]=thirdparty/contiki-ng/examples/rpl-udp/udp-server.whitefield $NODEID AUTO_START=1 # IDS SERVER\n"\
		"nodeExec[2-"+str(ids)+"]=thirdparty/contiki-ng/examples/rpl-udp/udp-client-ids.whitefield $NODEID AUTO_START=1 # IDS DETECTORS\n"\
		"nodeExec["+str(ids+1)+"-"+str(blackh)+"]=thirdparty/contiki-ng/examples/rpl-udp/udp-client-blackh.whitefield $NODEID AUTO_START=1\n"\
		"nodeExec["+str(blackh+1)+"-"+str(normal)+"]=thirdparty/contiki-ng/examples/rpl-udp/udp-client-in0.whitefield $NODEID AUTO_START=1\n"
		f.write(body)
		f.close()
	ids=ids+1
	blackh=blackh+1
	normal=normal+1
	config_name=config_name+1