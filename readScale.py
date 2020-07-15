import datetime
import re

# IDS_NODES=[1,2,3,4,12,13]
NORMAL_NODES_25=[]
NORMAL_NODES_48=[]
NORMAL_NODES_94=[]


NAMES=["log-ids-Norm","log-ids-BOF","log-ids-BH"]
OUTPUT_NAMES=["resultNorm","resultBOF","resultB"]

ALL_NODES=[]
ALL_IDS_NODES=[]

def fillNodes(start,end):
	tot=[]
	for i in range(start,end+1):
		tot.append(i)
	return tot

def readFiles():
	# TOTAL_NUM=37 #NORMAL5= 37, NORMAL6=38, NORMAL7=39, NORMAL8=40
	category=0
	range_ids=6
	#check each name of simulation, each scale
	for name in (NAMES):
		category+=1
		if ("BOF" in name or "BH" in name):
			TOTAL_NUM=40
			REPEATS=11
		else:
			TOTAL_NUM=37
			REPEATS=6

		for num_name in range(5,16):
			full_name=name+str(num_name) #logBH5 

			if ("Norm" in name):
				IDS_NODES=fillNodes(2,range_ids)
				NORMAL_NODES=fillNodes(range_ids+1,TOTAL_NUM-1)
			else:
				IDS_NODES=fillNodes(2,range_ids)
				BLACKH_NODES=fillNodes(range_ids+1,range_ids+3)
				NORMAL_NODES=fillNodes(range_ids+4,TOTAL_NUM-1)

			# print(IDS_NODES,BLACKH_NODES,NORMAL_NODES)
			range_ids+=1

		# for spec_names in name: #["log-ids-BOF25-","log-ids-B25-","log-ids-norm25-"]

			sumavg=[]
			k=1
			mal=0
			tot_BR_warn=0
			avg=[]
			parent_avg=[]
			dif_avg=[]

			#for each simulation (10 times)
			for k in range(1,REPEATS):

				with open("res-"+full_name[8:]+"-"+"ALL.txt","a+") as f1:

					count=0
					mals=[]
					br_warn={}
					counters=[]
					ids_warn={}
					sure_nodes={}
					count_sure=0
					nodes_drop={}
					drop=0
					count_toBR=0
					count_arrivedBR=0
					cc=0
					count_ids_of=0
					parent_sw=0
					pktBR={}
					pktFROM={}
					total_packets=0
					# print(name,full_name)

					#for each node number
					for i in range(1,TOTAL_NUM+1):
						if (len(str(format(i-1,'x')))==2):
							file1=full_name+"-r"+str(k)+"/node_00"+str(format(i-1,'x'))+".log"
						else:
							file1=full_name+"-r"+str(k)+"/node_000"+str(format(i-1,'x'))+".log"
						# nnbr=0
						flag_ids=0
						flag_norm=0

						if (i-1) in IDS_NODES:
							flag_ids=1
						elif (i-1) in NORMAL_NODES:
							flag_norm=1

						flag_fine=0
						with open(file1,"r") as f:
							for line in f:

								if (line.find("00:59:")!=-1):
									# print("fine node")
									flag_fine=1
								# if (line.find("chkns")!=-1):
								# 	x1=line.split()
								# 	node=int(x1[3].split(":")[1])
								# 	dis=int(x1[4])
								# 	dio=int(x1[5])
								# 	inter=int(x1[6])
								# if (line.find(""))
								# 	total_packets+=total_packets+dis+dio
								# 	print("Node:",node," dis:",dis,dio,"Interv:",inter)

								if (line.find("Maybe")!=-1): #when send IDS packet	
									x1=line.split()
									node=int(x1[4].split(":")[1])
									if node in (ids_warn):
										ids_warn[node]+=1
									else:
										ids_warn[int(node)]=1
									# print("fp:",ids_warn)

								if (line.find("warning")!=-1): #BR if exceed thresholds
									tot_BR_warn+=1
									x=line.split()
									# print(x)
									node=int(x[5].split("!")[0])
									#print (node)
									if node in (br_warn):
										br_warn[node]+=1
									else:
										br_warn[int(node)]=1					

								if (line.find("sure mal")!=-1): #detected more >=2 times
									x=line.split()
									# print(x)
									node=int(x[6].split("!")[0])
									sure_nodes[node]=sure_nodes.get(node,0)+1
									print(sure_nodes)
									count_sure+=1

								if (line.find("Blackhole")!=-1):
									x=line.split()
									drop+=1
									if (nodes_drop.get((x[4].split(":"))[1])):
										nodes_drop[(x[4].split(":"))[1]]=nodes_drop.get((x[4].split(":"))[1])+1
									else:
										nodes_drop[(x[4].split(":"))[1]]=1

								icmp_mes=re.search("ICMPv6(.+?)] Sending(.?).+to (.+?)(506.0)",line)
								app_mes=re.search("App(.+?)] Sending(.?).+to (.+?)(506.0)",line)
						
								icmp_mes_gen=re.search("ICMPv6(.+?)] Sending (.+) to (.+)",line)
								app_mes_gen=re.search("App(.+?)] Sending (.+) to (.+)",line)
						
								if (flag_norm and icmp_mes_gen is not None):
									total_packets+=1
									# print(icmp_mes_gen)
								elif (flag_norm and app_mes_gen is not None):
									total_packets+=1
									# print(app_mes_gen)

								if ((icmp_mes or app_mes) and flag_norm ):
									count_toBR+=1
								
								#check packets received/sent to BR	
								ip_to_br=re.search("IPv6(.+?)] packet received (.+?) .+(506.+) to .+(506.0)",line)

								flag_count_node=0
								if (ip_to_br is not None):
									node_from_str=int(ip_to_br.group(3)[4:],16)

									if (node_from_str in NORMAL_NODES):
										# print("norm",node_from_str)
										flag_count_node=1

								if (int(i-1)==0 and flag_count_node):
									count_arrivedBR+=1

									if (pktBR.get(ip_to_br.group(3)[4:])):
										pktBR[ip_to_br.group(3)[4:]]=pktBR[ip_to_br.group(3)[4:]]+1
									else:
										pktBR[ip_to_br.group(3)[4:]]=1

								if (flag_ids and line.find("OF:packet sent")!=-1):
									count_ids_of+=1
									
								if (line.find("parent switch:")!=-1 and flag_norm):
									parent_sw+=1

							if (flag_fine==0):
								print("======================ERROR=============",file1)
								# exit(0)

					print ("*"*30,"\n",file1,tot_BR_warn)
					f1.write("\nFile:"+file1+"\n")
					a=0

					f1.write("IDS alerts; "+str(count_sure))
					f1.write("Total packets sent; "+str(total_packets))
					print("IDS alerts:",count_sure,"\nNormal Total packets:",total_packets)

					perc_str=(float)(count_arrivedBR/count_toBR)
					f1.write("\nPackets to BR; "+str(count_toBR)+" Arrived:"+str(count_arrivedBR)+" Perc: "+"{:.2%}".format(perc_str))
					f1.write("\nPackets Diff; "+str(count_toBR-count_arrivedBR))
					f1.write("\nParent switch; "+str(parent_sw))
					print("Packets to BR:",count_toBR," Arrived:",count_arrivedBR," Perc: {:.2%}".format(perc_str),"\nIDS overhead:",count_ids_of)
					print("Parent switch:",parent_sw)
					parent_avg.append(parent_sw)
					dif_avg.append(count_toBR-count_arrivedBR)

					if (k==REPEATS-1):
						totavg=0
						totdif=0
						for d in parent_avg:
							totavg+=d
						for d in dif_avg:
							totdif+=d
						f1.write("\nAvg switch; "+str(totavg/len(parent_avg)))
						f1.write("\nAvg diff; "+str(totdif/len(dif_avg)))


					if ("Norm" not in name):
						perc_str=(float)(drop/total_packets)
						print("Packets dropped BlHole:"+str(drop)+ " "+"{:.2%}".format(perc_str))
						f1.write("\nPackets dropped; "+str(drop)+"\nPerc dropped; "+"{:.2%}".format(perc_str))
						# f1.write("\nNodes:\n")
						# for k,v in nodes_drop.items():
						# 	f1.write(str(k)+" packets drop:"+str(v)+"\n")

					if (len(ids_warn)==0):
						f1.write("\n")
						continue

					f1.write("Sure total:%s\n" % str(count_sure))
					f1.write("SURE NODES:\n")
					print("Sure:",sure_nodes.items())
					for k,v in sure_nodes.items():
						f1.write(str(k)+" : "+str(v))
						# f1.write()
						f1.write("\n")

					for m in br_warn:
						print ("BR malicious:",m,"Count:",(br_warn[m]))
						f1.write("Malicious id:")
						f1.write(str(m))
						f1.write(" "+str(br_warn[m])+"\n")
						# a+=1

					for idn in br_warn:
						if idn in NORMAL_NODES:
							print("FP BR:",idn)
							f1.write("FP BR id:")
							f1.write(str(idn))
							f1.write("\n")

					for idn in sure_nodes:
						if idn in NORMAL_NODES:
							print("FP Sure BR:",idn)
							f1.write("FP Sure id:")
							f1.write(str(idn))
							f1.write("\n")

					avg.append(float(tot_BR_warn)) #tot_BR_warn

					for f in ids_warn:
						if f in NORMAL_NODES:
							print("FP:",f)
							# f1.write("FP id:")
							# f1.write(str(f))
							# f1.write("\n")
					# exit(0)
							
			#Average for 10 repetitions
			print("len",len(avg),avg)
			if (len(avg)==0):
				continue
			sumavg.append(sum(avg)/len(avg))

			c=0
			for ckn in OUTPUT_NAMES[category-1]:
				with open("avg"+ckn+".txt","w") as f1:
					for i in avg:
						#print (i)
						c+=1
						f1.write("Total in "+str(c)+": "+str(i)+"\n")

					c=0
					for k in sumavg:
						#print (i)
						c+=1
						f1.write("AVG "+str(c)+": "+str(k)+"\n")

			TOTAL_NUM+=1



def readstats():

	for times in range(1,11):
	
		tot_tx=0
		tot_rx=0
		tot_succ=0
		tot_fail=0
		names=["BOF","N","B"]
		category=0
		for name in (ALL_NAMES):
			category+=1

			for spec_names in name:

				#REPETITIONS
				for k in range(1,11):
					# print("UNIR;",ALL_NODES[category-1])
					for num_node in ALL_NODES[category-1]:
						if (num_node in ALL_IDS_NODES[category-1]):
							continue
						file1="statsofnodes/stats"+spec_names[8:]+"node"+str(num_node)+"-"+str(k)+".txt"
							

						with open(file1,"r") as f:
							for line in f:
								if (line.find("MCAST_PKTS")!=-1):
									transm=(line.split(",")[0]).split("=")[1]
									rx=((line.split(",")[1]).split("=")[1]).rstrip()
									# print(transm,rx)
									tot_rx+=int(rx)
									tot_tx+=int(transm)

								if (line.find("UCAST_PKTS")!=-1):
									succ=(line.split(",")[2]).split("=")[1]
									fail=(line.split(",")[3]).split("=")[1]
									tot_succ+=int(succ)
									tot_fail+=int(fail)
									print("succ:",succ,fail)

					with open("res-"+spec_names[8:]+"-"+str(k)+".txt","w") as f1:
						f1.write("Total TX:"+str(tot_tx))
						f1.write("\nTotal RX:"+str(tot_rx))
						f1.write("\nTotal succ:"+str(tot_succ))
						f1.write("\nTotal fail:"+str(tot_fail))
						f1.close()


def check_errors():

	for name in (NAMES):
		for num_name in range(5,16):
			full_name=name+str(num_name) #logBH5 
			if ("Norm" in name):
				for i in range(1,6): #repeats
					with open(full_name+"-r"+str(i)+"/airline.log","r") as f:
						for l in f:
							if "ERROR" in l:
								print(l)
								exit(0)
					with open(full_name+"-r"+str(i)+"/airline_error.log","r") as f:
						for l in f:
							print(l)
			else:
				for i in range(1,11): #repeats
					with open(full_name+"-r"+str(i)+"/airline.log","r") as f:
						for l in f:
							if "ERROR" in l:
								print(l)
								exit(0)
					with open(full_name+"-r"+str(i)+"/airline_error.log","r") as f:
						for l in f:
							print(l)

				# with open(full_name+"-r"+str(i)+"/")


# NORMAL_NODES_25=fillNodes(10,24)
# NORMAL_NODES_48=fillNodes(18,47)
# NORMAL_NODES_94=fillNodes(34,93)
# NORMAL_NODES_25=fillNodes(7,21)
# IDS_NODES_5=fillNodes(2,6)

# IDS_NODES_25=fillNodes(2,4)
# IDS_NODES_48=fillNodes(2,7)
# IDS_NODES_94=fillNodes(2,13)


# ALL_NODES=[NORMAL_NODES_25,NORMAL_NODES_48,NORMAL_NODES_94]
# ALL_IDS_NODES=[IDS_NODES_25,IDS_NODES_48,IDS_NODES_94]

# readstats()
# check_errors()
readFiles()
