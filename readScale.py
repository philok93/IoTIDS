import datetime
import re

# IDS_NODES=[1,2,3,4,12,13]
NORMAL_NODES_25=[]
NORMAL_NODES_48=[]
NORMAL_NODES_94=[]

IDS_NODES_25=[]
IDS_NODES_48=[]
IDS_NODES_94=[]

NAMES25=["log-ids-BOF25v21-","log-ids-B25v21-","log-ids-N25v21-"]
OUTPUT_NAMES25=["resultBOF25","resultB25","resultNorm25"]
NAMES48=["log-ids-BOF48-","log-ids-B48-","log-ids-norm48-"]
OUTPUT_NAMES48=["resultBOF48","resultB48","resultNorm48"]
NAMES94=["log-ids-BOF94-","log-ids-B94-","log-ids-norm94-"]
OUTPUT_NAMES94=["resultBOF94","resultB94","resultNorm94"]

ALL_NAMES=[NAMES25,NAMES48,NAMES94]
ALL_OUTPUT=[OUTPUT_NAMES25,OUTPUT_NAMES48,OUTPUT_NAMES94]
ALL_NODES=[]
ALL_IDS_NODES=[]

def fillNodes(start,end):
	tot=[]
	for i in range(start,end+1):
		tot.append(i)
	return tot

def readFiles():

	category=0
	#check each name of simulation, each scale
	for name in (ALL_NAMES):
		category+=1

		for spec_names in name: #["log-ids-BOF25-","log-ids-B25-","log-ids-norm25-"]

			sumavg=[]
			k=1
			mal=0
			tot=0
			avg=[]

			#for each simulation (10 times)
			for k in range(1,3):

				with open("res-"+spec_names[8:]+str(k)+".txt","w") as f1:

					count=0
					mals=[]
					mals2={}
					counters=[]
					fp1={}
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
					print(name,spec_names)

					#for each node
					for i in range(1,int(spec_names.split("-")[2][-5:-3])):
						if (len(str(format(i-1,'x')))==2):
							file1=spec_names+str(k)+"/node_00"+str(format(i-1,'x'))+".log"
						else:
							file1=spec_names+str(k)+"/node_000"+str(format(i-1,'x'))+".log"
						
						nnbr=0

						with open(file1,"r") as f:
							for line in f:

								if (line.find("chkns")!=-1):
									x1=line.split()
									node=int(x1[3].split(":")[1])
									dis=int(x1[4])
									dio=int(x1[5])
									inter=int(x1[6])
									# print("Node:",node," dis:",dis,dio,"Interv:",inter)

								if (line.find("Maybe")!=-1):	
									x1=line.split()
									node=int(x1[4].split(":")[1])
									if node in (fp1):
										fp1[node]+=1
									else:
										fp1[int(node)]=1
									# print("fp:",fp1)

								if (line.find("warning")!=-1):
									tot+=1
									x=line.split()
									# print(x)
									node=int(x[5].split("!")[0])
									#print (node)
									if node in (mals2):
										mals2[node]+=1
									else:
										mals2[int(node)]=1					

								if (line.find("sure mal")!=-1):
									x=line.split()
									# print(x)
									node=int(x[6].split("!")[0])
									sure_nodes[node]=node
									count_sure+=1

								if (line.find("Blackhole")!=-1):
									x=line.split()
									drop+=1
									if (nodes_drop.get((x[4].split(":"))[1])):
										nodes_drop[(x[4].split(":"))[1]]=nodes_drop.get((x[4].split(":"))[1])+1
									else:
										nodes_drop[(x[4].split(":"))[1]]=1

								res=re.search("ICMPv6(.+?)] Sending(.?).+to (.+?)(506.0)",line)
								res3=re.search("App(.+?)] Sending(.?).+to (.+?)(506.0)",line)
								
							
								for ck in ALL_NODES[category-1]:
									if((res or res3) and int(i-1)==ck):
										nnbr+=1
						
								for ck in ALL_NODES[category-1]:
									if ((res or res3) and int(i-1)==ck):
										count_toBR+=1
								
								#check packets received/sent to BR	
								res2=re.search("IPv6(.+?)] packet received (.+?) to .+(506.0)",line)

								if (int(i-1)==0 and res2):
									count_arrivedBR+=1
									if (pktBR.get(res2.group(2)[23:])):
										pktBR[res2.group(2)[23:]]=pktBR[res2.group(2)[23:]]+1
									else:
										pktBR[res2.group(2)[23:]]=1
									# print(res2.group(2))

								for ck in ALL_IDS_NODES[category-1]:
									if (int(i-1)==ck and line.find("OF:packet sent")!=-1):
										count_ids_of+=1
									
								# if ("norm" in spec_names):
								for ck in ALL_NODES[category-1]:
									if (line.find("parent switch:")!=-1 and int(i-1)==ck):
										parent_sw+=1
								# else:		
								# 	if ((((int(i-1)>=9 and int(i-1)<=11) or int(i-1)==14 or int(i-1)==15)) and line.find("parent switch:")!=-1):
								# 		parent_sw+=1

							# print("node:",i-1,nnbr)
					print ("*"*30,"\n",file1,tot)
					f1.write("\nFile:"+file1+"\n")
					a=0
					# print(pktBR)
					print("IDS alerts:",count_sure)
					# print(nodes_drop)
					print("Packets to BR:",count_toBR," Arrived:",count_arrivedBR,"\nIDS overhead:",count_ids_of)
					print("Parent switch:",parent_sw)
					print("Packets dropped Blackhole:"+str(drop))
					
					f1.write("Packets dropped Blackhole:"+str(drop))
					f1.write("\nNodes:\n")
					for k,v in nodes_drop.items():
						f1.write(str(k)+" packets drop:"+str(v)+"\n")

					f1.write("\nSURE NODES:")
					for x,y in sure_nodes.items():
						f1.write(str(x))
						f1.write(", ")
						f1.write("\n")
						f1.write("sure count:%s\n" % str(count_sure))


						for x in mals2:
							print (" malicious:",x,"Count:",(mals2[x]))
							f1.write("Malicious id:")
							f1.write(str(x))
							f1.write(" "+str(mals2[x])+"\n")
							a+=1

						avg.append(float(tot))

						for f in fp1:
							print("FP:",f)
							f1.write("FP id:")
							f1.write(str(f))
							f1.write("\n")

							
				#Average for 10 repetitions
				print("len",len(avg),avg)
				if (len(avg)==0):
					continue
				sumavg.append(sum(avg)/len(avg))

				c=0
				for ckn in ALL_OUTPUT[category-1]:
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


# NORMAL_NODES_25=fillNodes(10,24)
# NORMAL_NODES_48=fillNodes(18,47)
# NORMAL_NODES_94=fillNodes(34,93)
NORMAL_NODES_25=fillNodes(7,21)
IDS_NODES_25=fillNodes(2,6)
# IDS_NODES_25=fillNodes(2,4)
# IDS_NODES_48=fillNodes(2,7)
# IDS_NODES_94=fillNodes(2,13)


ALL_NODES=[NORMAL_NODES_25,NORMAL_NODES_48,NORMAL_NODES_94]
ALL_IDS_NODES=[IDS_NODES_25,IDS_NODES_48,IDS_NODES_94]

# readstats()
readFiles()