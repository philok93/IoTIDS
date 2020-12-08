import datetime

def readFiles():
	
	sumavg=[]
	kk=1
	for kk in range(1,11):

		with open("result"+str(kk)+".txt","w") as f1:

			mal=0
			#for u in range(1,4):
				
			mals=[]
			counters=[]
			count=0
			tot=0
			avg=[]
			
			#for each run
			for i in range(1,6):
				file1="read_IDS_allnodes_sciptIDS"+str(kk)+"-clone-"+str(i)+".log"
				count=0
				mals=[]
				counters=[]
				tot=0
				fp1=[]
				sure_nodes={}
				count_sure=0
				count_time=0
				clone={}

				with open(file1,"r") as f:
					for line in f:
						#if (line.find("ID malicious")!=-1):
							#print (line)
						if (line.find("attacker")!=-1):
							x1=line.split()
							node=int(x1[6].split(":")[1])
							if (node not in clone):
								clone[node]=1
							else:
								clone[node]=clone[node]+1
						if (line.find("chkns")!=-1):
							#print(line)
							x1=line.split()
							if "IPde" in x1[5]:
								node=int(x1[9].split(":")[1])
							else:
								node=int(x1[5].split(":")[1])
							# if (file1=="read_IDS_allnodes_scipt52-3.log" and node==6):
							# 	print(line,node)
							#fp1.append(node)
						if (line.find("Maybe")!=-1):	
							x1=line.split()
							node=int(x1[6].split(":")[1])
							# print(x1[0])
							
							# exit(0)
							for i in range(0,len(fp1)):
								#if file1.find("testwith4mals")!=-1:
								#	print (i,mals[i],node,counters[i])
									#print (line)
								if fp1[i]==node:
									
									break
							else:
								#print("added:",node,count,mals)
								# print(x1,node)
								fp1.append(int(node))
								#mal=node
						if (line.find("warning")!=-1):
							tot+=1
							x=line.split()
							# print(x)
							#print (x)
							node=int(x[7].split("!")[0])
							#print (node)
							for i in range(0,len(mals)):
								#if file1.find("testwith4mals")!=-1:
								#	print (i,mals[i],node,counters[i])
									#print (line)
								if mals[i]==node:
									counters[i]+=1
									#print (mals)
									break
							else:
								#print("added:",node,count,mals)
								mals.append(int(node))
								count+=1
								counters.append(count)
								count=0
								#mal=node

						if (line.find("sure mal")!=-1):
							x=line.split()
							# print(x)
							# exit(0)
							node=int(x[8].split("!")[0])
							sec=(int(x[0])/(1000000.0))
							minutes=(int(x[0])/(1000000.0*60))%60.0
							minutes = float(minutes)
							print(x,sec,minutes)
							a=str(datetime.timedelta(seconds=sec))
							print(a)
							if minutes:
								count_time+=1
							sure_nodes[node]=node
							count_sure+=1

						if line.find("Test ended")!=-1:
							print("DONE GOOD",line)

			
				print ("*"*30,"\n",file1,tot)
				f1.write("\nFile:"+file1+"\n")
				a=0
				print("final:",count_time)
				
				f1.write("SURE NODES:")
				for x,y in sure_nodes.items():
					f1.write(str(x))
					f1.write(", ")
				f1.write("\n")
				f1.write("sure count:%s\n" % str(count_sure))

				for x,y in clone.items():
					f1.write("Clone nodes:"+ str(x)+" count:"+str(y)+"\n")
				f1.write("\n")


				for x in mals:
					print (" malicious:",x,"Count:",(counters[a]))
					f1.write("Malicious id:")
					f1.write(str(x))
					f1.write(" "+str(counters[a])+"\n")
					a+=1
				avg.append(float(tot))

				for f in fp1:
					f1.write("FP id:")
					f1.write(str(f))
					f1.write("\n")

				
			#Average for 10 repetitions
			#print("len",len(avg),avg)
			sumavg.append(sum(avg)/len(avg))
			#print (len(sumavg),sumavg)
			c=0
			for i in avg:
				#print (i)
				c+=1
				f1.write("Total in "+str(c)+": "+str(i)+"\n")
		
			c=0
			for k in sumavg:
				#print (i)
				c+=1
				f1.write("AVG "+str(c)+": "+str(k)+"\n")








readFiles()