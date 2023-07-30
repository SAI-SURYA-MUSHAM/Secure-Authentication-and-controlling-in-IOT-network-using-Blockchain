from flask import Flask,request
import requests
import json
import argparse
import os
import ecdsa
import hashlib
import uuid
import random
import binascii
import base64
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature
import random
import re
import copy
import tcp2


whole=" "
Destiny=" "
messages=""
second_path=" "
whole1=" "

app=Flask(__name__)
@app.route('/Node_File',methods=['POST'])
def Create_Node():
	node_number=request.data.decode("utf-8")
	#TO creat distributed ledger blocks
	folder_path= "C:/Users/surya/Project/{}".format(node_number)
	#file to store its connected IoT
	file_path1 = os.path.join(folder_path, "IOT.json")
	file_path = os.path.join(folder_path, "keys.json")

	if not os.path.exists(folder_path):
		os.makedirs(folder_path)
	folder_path1= folder_path+"/Distributed_Ledger"
	if not os.path.exists(folder_path1):
		os.makedirs(folder_path1)
	#To create a file to store keys of node in it
	if not os.path.exists(file_path):
		with open(file_path, 'a') as file:
			pass
	#To store its connected IOT device
	if not os.path.exists(file_path1):
		with open(file_path1, 'a') as file:
			pass
	#To create wallet for each node
	Directory=os.path.join(folder_path,"Balance.txt")
	if not os.path.exists(Directory):
		with open(Directory, 'w') as file:
			file.write("100")
	Path="http://127.0.0.1:{}/Key_Generation".format(node_number)
	#To call Node_Registraion API for generating keys
	requests.post(Path,data=file_path)
	return "Success"
@app.route('/Key_Generation',methods=['POST'])
def Node_Registraion():
	import os
	import ecdsa
	location=request.data.decode("utf-8")
	# Generate a private key
	private_key = ec.generate_private_key(ec.SECP256R1())
	# Serialize the private key in PEM format
	pem_private_key = private_key.private_bytes(
		encoding=Encoding.PEM,
		format=PrivateFormat.PKCS8,
		encryption_algorithm=NoEncryption())

	# Generate the corresponding public key
	public_key = private_key.public_key()

	# Serialize the public key in PEM format
	pem_public_key = public_key.public_bytes(
		encoding=Encoding.PEM,
		format=PublicFormat.SubjectPublicKeyInfo
	)
	# Generate a shared secret using ECDH
	ecdh = private_key.exchange(ec.ECDH(), public_key)
	# Derive a symmetric encryption key from the shared secret using HKDF
	encryption_key = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=b"encryption key",
		backend=default_backend()
		).derive(ecdh)
	
	#To store private and public key of a particular node in dictionary form
	keys={"private_key":pem_private_key.decode(),"public_key":pem_public_key.decode(),"Shared Key":encryption_key.hex()}
	with open(location, 'a') as file:
		json.dump(keys, file)
	print("Node ",args.port," Private and Public keys are created")
	#Store node and public keys in uncomitted transaction
	with open("C:/Users/surya/Project/Uncommited.json","a") as file:
		publickeys={args.port:[]}
		publickeys[args.port].append(pem_public_key.decode())
		publickeys[args.port].append(encryption_key.hex())
		json.dump(publickeys,file,indent =4)
	# Calling /Consensus API for consensus mechanism
	variable='Consensus'
	keys_path="C:/Users/surya/Project/{}/Balance.txt".format(args.port)
	with open(keys_path,'r') as f2:
		value=f2.read()
		value=int(value)
	path1="http://127.0.0.1:{}/{}".format(args.port,variable)
	if value>=50:
		consensus_result=requests.post(path1)
	return "success"
#API for performing consensus mechanism
@app.route('/Consensus',methods=['POST'])
def Consensus():
	file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
	file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
	data={}
	data1={}
	data['Port_No']=args.port
	with open(file_path, 'r') as file:
		hash_value=json.load(file)
	data['Block_No']=1+hash_value['Prev_block']
	data['Prev_hash']=hash_value['Prev_hash']
	with open("C:/Users/surya/Project/Uncommited.json", 'r') as file1:
		data1 = json.load(file1)
	#copying contents of uncommited transaction to non validatetd transactions file
		data.update(data1)
	#Storing merged json files in Non validated file
	with open(file_path1, 'w') as outfile:
		json.dump(data, outfile)
	#To check no of files for consensus
	file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")
	if os.path.getsize(file_path2) == 0:
		print("Consensus is successful")
		with open(file_path1,'rb') as file:
		#Creating hash
			contents = file.read()		
			hash_obj = hashlib.sha256(contents)
			file_hash = hash_obj.hexdigest()
			current={"Present_hash":file_hash}
			v1="/Distributed_Ledger/"
			v2=v1+"Block"+str(data['Block_No'])
		#store the validated data in block chain
			file_path3="C:/Users/surya/Project/{}/{}".format(args.port,v2)
			data.update(current)
			with open(file_path3,'w') as f:
				json.dump(data, f, indent=4)
		#Clearing Uncommited file
			with open("C:/Users/surya/Project/Uncommited.json", 'w') as f:
				f.truncate(0)
		#Clearing Non Validated file
			with open(file_path1, 'w') as f:
				f.truncate(0)
		#changing values in global variables
			with open(file_path,'w') as f2:
				new_data={'Prev_block':data['Block_No'],"Prev_hash":file_hash}
				json.dump(new_data, f2)
		#Adding port number and public key
			with open(file_path2,'w') as f1:
				json.dump(data1,f1)
		print(args.port," Keys are store in ledger")


			
	else:
		#Iterating through nodes for consensus
		response="ss"
		file_hash1=""
		No_Of_Nodes=0
		Value=0
		file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
		with open(file_path1,'rb') as file:
		#Creating hash
			contents = file.read()		
			hash_obj = hashlib.sha256(contents)
			file_hash1 = hash_obj.hexdigest()
			current={"Present_hash":file_hash1}
			file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")
			with open(file_path2,'r') as f5:
				temp_data = json.load(f5)
				keys = temp_data.keys()
				No_Of_Nodes=len(keys)
				for i in keys:
					temp_name="Validate"
					path_val="http://127.0.0.1:{}/{}".format(i,temp_name)
					leave=requests.post(path_val,data=file_hash1)				
					if (leave.text =='1'):
						Value = Value+1
				if Value>=(No_Of_Nodes//2):
					v1="/Distributed_Ledger/"
					v2=v1+"Block"+str(data['Block_No'])
					#store the validated data in block chain
					file_path3="C:/Users/surya/Project/{}/{}".format(args.port,v2)
					data.update(current)				
					with open(file_path3,'w') as f:
						json.dump(data, f, indent=4)
					file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")	
					with open(file_path2,'r') as f5:
						temp_data = json.load(f5)
						keys = temp_data.keys()
						for i in keys:
							c1="/Distributed_Ledger/"
							c2=c1+"Block"+str(data['Block_No'])
							file_path4="C:/Users/surya/Project/{}/{}".format(i,c2)
							with open(file_path4,'w') as f:
								json.dump(data, f, indent=4)				
		#Clearing Uncommited file
		with open("C:/Users/surya/Project/Uncommited.json", 'w') as f:
			f.truncate(0)
	#Clearing Non Validated file
		with open(file_path1, 'w') as f:
			f.truncate(0)
	#changing values in global variables
		file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
		with open(file_path,'w') as f2:
			new_data={'Prev_block':data['Block_No'],"Prev_hash":file_hash1}
			json.dump(new_data, f2)
		existing_data={}
	#Adding port number and public key
		with open(file_path2,'r') as f1:
			existing_data = json.load(f1)
		existing_data.update(data1)
		updated_data = json.dumps(existing_data, indent=4)
		with open(file_path2,'w')as fss1:
			fss1.write(updated_data)
		print(args.port," Consensus is successful and stored in ledger")
			
	return "succeess"



@app.route('/Validate',methods=['POST'])
def Validate():
	Hash=request.data.decode("utf-8")
	file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
	file_hash=""
	
	with open(file_path1,'rb') as file:
		#Creating hash
		contents = file.read()		
		hash_obj = hashlib.sha256(contents)
		file_hash = hash_obj.hexdigest()
	if Hash == file_hash:
		
		return '1'
	else:
		
		return '0'



#IOT REGISTRATION CODE IS FROM HERE
@app.route('/IOT_Registraion',methods=['POST'])
def Iot_Registraton_IOT():
	data2={}
	data={}
	data3={}
	node_number=request.data.decode("utf-8")
	folder_path= "C:/Users/surya/Project/{}".format(node_number)
	if not os.path.exists(folder_path):
		os.makedirs(folder_path)
	file_path = os.path.join(folder_path, "keys.json")
	if not os.path.exists(file_path):
		with open(file_path, 'a') as file:
			pass
	file_path = os.path.join(folder_path, "IOT_Number.txt")
	if not os.path.exists(file_path):
		with open(file_path, 'a') as file:
			pass
	#Creation of secret key with the help of private and public key
	private_key = ec.generate_private_key(ec.SECP256R1())
	# Serialize the private key in PEM format
	pem_private_key = private_key.private_bytes(
		encoding=Encoding.PEM,
		format=PrivateFormat.PKCS8,
		encryption_algorithm=NoEncryption())

	# Generate the corresponding public key
	public_key = private_key.public_key()

	# Serialize the public key in PEM format
	pem_public_key = public_key.public_bytes(
		encoding=Encoding.PEM,
		format=PublicFormat.SubjectPublicKeyInfo
	)
	# Generate a shared secret using ECDH
	ecdh = private_key.exchange(ec.ECDH(), public_key)
	# Derive a symmetric encryption key from the shared secret using HKDF
	encryption_key = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=b"encryption key",
		backend=default_backend()
		).derive(ecdh)
	print(" secret key given by manufature in generated for ",args.port," node")
	#Getting current time stamp
	timestamp = datetime.datetime.now().timestamp()
	#To cretae unique id to Iot nodes
	id = str(uuid.uuid4())
	#combine id and secret key
	iv = b"1234567890123456"
	id_key=id+encryption_key.hex()
	hash_object = hashlib.sha256()
	hash_object.update(id_key.encode())
	hash_hex = hash_object.hexdigest()
	padder = PKCS7(128).padder()
	padded_message = padder.update(id_key.encode()) + padder.finalize()
	cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encrypted_message = encryptor.update(padded_message) + encryptor.finalize()	
	file_path = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	data={args.port:[]}
	data[args.port].append(timestamp)
	data[args.port].append(id)
	data[args.port].append(encryption_key.hex())
	data[args.port].append(encrypted_message.hex())
	file_path = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	#To store hash of id and secret key
	with open(file_path, 'w') as file:
		json.dump(data,file)
	#to select a random iot
	file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")
	with open(file_path2,'r') as f5:
		temp_data = json.load(f5)
		keys = list(temp_data.keys())
		random_element = random.choice(keys)
		file_path = os.path.join(folder_path, "IOT_Number.txt")
		with open(file_path, 'a') as file:
			file.write(random_element)
	path1="http://127.0.0.1:{}/IOT_Keys_validate1".format(random_element)
	nothing=requests.post(path1,data=node_number)
	file_path3 = os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path3,'r') as f4:
		data3=json.load(f4)
	current_encrypted_msg=data3['Pr_Pu'][2]
	if encrypted_message.hex()==current_encrypted_msg:
		Iot_Private_key=data3['Pr_Pu'][0]
		Iot_Public_key=data3['Pr_Pu'][1]
		Iot_Public_key = bytes.fromhex(Iot_Public_key)
		Iot_Private_key = bytes.fromhex(Iot_Private_key)
		decryptor = cipher.decryptor()
		decrypted_message = decryptor.update(Iot_Private_key) + decryptor.finalize()
		# Unpad the decrypted message
		unpadder = PKCS7(128).unpadder()
		Iot_Private_key = unpadder.update(decrypted_message) + unpadder.finalize()
		decryptor = cipher.decryptor()
		decrypted_message = decryptor.update(Iot_Public_key) + decryptor.finalize()
		# Unpad the decrypted message
		unpadder = PKCS7(128).unpadder()
		Iot_Public_key = unpadder.update(decrypted_message) + unpadder.finalize()
		file_path = os.path.join(folder_path, "keys.json")
		data3={args.port:[]}
		data3[args.port].append(Iot_Private_key.decode())
		data3[args.port].append(Iot_Public_key.decode())
		with open(file_path,'w') as f5:
			json.dump(data3,f5)
	#Now Iot creates a message and signs the transaction
	verify={}
	verify={args.port:[]}
	verify[args.port].append(Iot_Public_key.decode())
	Sign_Data=args.port+Iot_Public_key.decode()
	
	Sign_Data=Sign_Data.encode()
	P_Key= load_pem_private_key(Iot_Private_key, password=None, backend=default_backend())
	Signature=P_Key.sign(Sign_Data, ec.ECDSA(hashes.SHA256()))
	Signature=binascii.hexlify(Signature)
	Signature=Signature.decode()
	verify[args.port].append(Signature)
	verify[args.port].append(Sign_Data.decode())
	file_path = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	with open(file_path, 'w') as file:
		file.truncate(0)
	with open(file_path,'w')as file:
		json.dump(verify,file)
	path4="http://127.0.0.1:{}/IOT_Keys_validate2".format(random_element)
	nothing=requests.post(path4,data=args.port)
	file_path = os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'w') as file:
		file.truncate(0)
	file_path = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	with open(file_path, 'w') as file:
		file.truncate(0)
	file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
	with open(file_path1,'w') as f6:
		f6.truncate(0)
	print("Node ",args.port," Private key and Public keys are generated")
	#to generate shared secret key
	generate_SK=b'hii this is my request to generate secret shared key'
	Signature_SK=P_Key.sign(Sign_Data, ec.ECDSA(hashes.SHA256()))
	Signature_SK=binascii.hexlify(Signature_SK)
	Signature_SK=Signature_SK.decode()
	key1={}
	key1["Signature"]=Signature_SK
	key1["message"]=generate_SK.decode()
	path4="http://127.0.0.1:{}/Generate_Skey".format(random_element)
	file_path7 = os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path7,'w') as file:
		json.dump(key1,file)
	something=requests.post(path4,data=args.port)

	return "succes"



@app.route('/IOT_Keys_validate1',methods=['POST'])
def IOT_Keys_validate1_FOG():
	file_path1 = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	node_number=request.data.decode("utf-8")
	encrypted_message=""
	data4={}
	with open(file_path1,'r') as f1:
		data=json.load(f1)
	if data[node_number][0]<=datetime.datetime.now().timestamp():
		with open(file_path1,'r') as f1:
			data=json.load(f1)
			ID=data[node_number][1]
			Key=data[node_number][2]
			Original_Key=binascii.unhexlify(Key)
			iv = b"1234567890123456"
			id_key=ID+Key
			hash_object = hashlib.sha256()
			hash_object.update(id_key.encode())
			hash_hex = hash_object.hexdigest()
			padder = PKCS7(128).padder()
			padded_message = padder.update(id_key.encode()) + padder.finalize()
			cipher = Cipher(algorithms.AES(Original_Key), modes.CBC(iv), backend=default_backend())
			encryptor = cipher.encryptor()
			encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
	if encrypted_message.hex()==data[node_number][3]:
		private_key = ec.generate_private_key(ec.SECP256R1())
		# Serialize the private key in PEM format
		pem_private_key = private_key.private_bytes(
			encoding=Encoding.PEM,
			format=PrivateFormat.PKCS8,
			encryption_algorithm=NoEncryption())	
		# Generate the corresponding public key
		public_key = private_key.public_key()
		# Serialize the public key in PEM format
		pem_public_key = public_key.public_bytes(
			encoding=Encoding.PEM,
			format=PublicFormat.SubjectPublicKeyInfo)
		#Encrypting private key
		iv = b"1234567890123456"
		id_key=pem_private_key.decode()
		hash_object = hashlib.sha256()
		hash_object.update(id_key.encode())
		hash_hex = hash_object.hexdigest()
		padder = PKCS7(128).padder()
		padded_message = padder.update(id_key.encode()) + padder.finalize()
		cipher = Cipher(algorithms.AES(Original_Key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		Pri_encrypted_message = encryptor.update(padded_message) + encryptor.finalize()	
		Pri_encrypted_message=Pri_encrypted_message.hex()
		#Encrypting public key
		iv = b"1234567890123456"
		id_key=pem_public_key.decode()
		hash_object = hashlib.sha256()
		hash_object.update(id_key.encode())
		hash_hex = hash_object.hexdigest()
		padder = PKCS7(128).padder()
		padded_message = padder.update(id_key.encode()) + padder.finalize()
		cipher = Cipher(algorithms.AES(Original_Key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		Pub_encrypted_message = encryptor.update(padded_message) + encryptor.finalize()	
		Pub_encrypted_message=Pub_encrypted_message.hex()
		data4={node_number:[]}
		data4[node_number].append(pem_private_key.decode())
		data4[node_number].append(pem_public_key.decode())
		folder_path= "C:/Users/surya/Project/{}".format(args.port)
		#file to store its connected IoT
		file_path1 = os.path.join(folder_path, "IOT.json")
		if os.stat(file_path1).st_size == 0:
			with open(file_path1,'w') as f5:
				json.dump(data4,f5)
		else:
			with open(file_path1, 'r') as file:
				data = json.load(file)
				with open(file_path1,'w') as f5:
					data.update(data4)
					json.dump(data,f5,indent=4)
		data1={}
		data1={'Pr_Pu':[]}  
		data1['Pr_Pu'].append(Pri_encrypted_message)
		data1['Pr_Pu'].append(Pub_encrypted_message)
		data1['Pr_Pu'].append(encrypted_message.hex())
		file_path = os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
		with open(file_path, 'w') as file:
			json.dump(data1,file)
		file_path = os.path.join("C:/Users/surya/Project", "IOT_Keys.json")
		Keys={}
		Keys={node_number:pem_public_key.decode()}
		with open(file_path, 'r') as file:
			existing_data = json.load(file)
		existing_data.update(Keys)
		with open(file_path, 'w') as file:
			 json.dump(existing_data, file)
	return "succes"



@app.route('/IOT_Keys_validate2',methods=['POST'])
def IOT_Keys_validate2_FOG():
	temp_var=0
	file_path1 = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	node_number=request.data.decode("utf-8")
	file_path = os.path.join("C:/Users/surya/Project", "IOT_Temp_Keys.json")
	with open(file_path, 'r') as file:
		data= json.load(file)
	verifying_data=node_number
	verifying_data+=data[node_number][0]
	
	verifying_data=verifying_data.encode()
	older_path= "C:/Users/surya/Project/{}".format(args.port)
	file_path1 = os.path.join(older_path, "IOT.json")
	with open(file_path1,'r')as file:
		data1=json.load(file)
	Private_key=data1[node_number][0]
	Private_key=Private_key.encode()
	Private_key=load_pem_private_key(Private_key, password=None, backend=default_backend())
	Public_key=data1[node_number][1]
	temp_key=Public_key
	Public_key=Public_key.encode()
	Public_key=serialization.load_pem_public_key(Public_key, backend=default_backend())	
	signature1 = Private_key.sign(verifying_data, ec.ECDSA(hashes.SHA256()))
	signature1 = binascii.hexlify(signature1)
	signature1=signature1.decode()
	signature2=data[node_number][1]
	signature2=signature2.encode()
	signature2=binascii.unhexlify(signature2)
	try:
		Public_key.verify(signature2, verifying_data, ec.ECDSA(hashes.SHA256()))
		temp_var=1
	except InvalidSignature:
		print(" Signature not valid")
	#to provide consensus to IoT nodes
	new_data={}
	new_data["Port_No"]=node_number
	file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
	with open(file_path, 'r') as file:
		curr_data=json.load(file)
	block_no=curr_data["Prev_block"]+1
	prev_hash=curr_data["Prev_hash"]
	curr_data["Prev_block"]=block_no
	new_data["Block_No"]=block_no
	new_data["Prev_hash"]=prev_hash
	new_data["Public_key"]=temp_key
	file_path = os.path.join("C:/Users/surya/Project", "Uncommited.json")
	with open(file_path, 'a') as file:
		json.dump(new_data,file)
	current_hash=" "
	file_path1 = os.path.join("C:/Users/surya/Project", "Uncommited.json")
	with open(file_path1,'rb') as file:
		#Creating hash
		contents = file.read()		
		hash_obj = hashlib.sha256(contents)
		current_hash = hash_obj.hexdigest()
	curr_data["Prev_hash"]=current_hash
	file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
	with open(file_path, 'w') as file:
		json.dump(curr_data,file)
	dm1={}
	dm1={"current_hash":current_hash}
	file_path1 = os.path.join("C:/Users/surya/Project", "Uncommited.json")
	with open(file_path1,'w') as f3:
		f3.truncate(0)
	file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
	with open(file_path1,'w') as file:
		json.dump(new_data,file)
	if temp_var==1:
		Value=0
		file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")
		with open(file_path2,'r') as f5:
			temp_data = json.load(f5)
			keys = temp_data.keys()
			No_Of_Nodes=len(keys)
			for i in keys:
				temp_name="IOT_Keys_consensus_2"
				path_val="http://127.0.0.1:{}/{}".format(i,temp_name)
				leave=requests.post(path_val,data=current_hash)				
				if (leave.text =='1'):
					Value = Value+1
			if Value>=(No_Of_Nodes//2):
				#store the validated data in block chain
				new_data["current_hash"]=current_hash
				file_path2 = os.path.join("C:/Users/surya/Project", "Public_keys.json")	
				with open(file_path2,'r') as f5:
					temp_data = json.load(f5)
					keys = temp_data.keys()
					for i in keys:
						c1="/Distributed_Ledger/"
						c2=new_data["Block_No"]
						c2=c1+"Block"+str(c2)
						file_path4="C:/Users/surya/Project/{}/{}.json".format(i,c2)
						with open(file_path4,'w') as f:
							json.dump(new_data, f,indent=4)
				print(node_number," node details are stored in ledger")

	return"sdf"
@app.route('/IOT_Keys_consensus_2',methods=['POST'])
def IOT_Keys_consensus_2_FOG():
	Hash=request.data.decode("utf-8")
	file_path1 = os.path.join("C:/Users/surya/Project", "non_validated.json")
	file_hash=""
	with open(file_path1,'rb') as file:
		#Creating hash
		contents = file.read()		
		hash_obj = hashlib.sha256(contents)
		file_hash = hash_obj.hexdigest()
	if Hash == file_hash:
		return '1'
	else:
		return '0'

@app.route('/Generate_Skey',methods=['POST'])
def Generate_Skey_FOG():
	node_number=request.data.decode("utf-8")
	file_path= os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'r') as file:
		sign1=json.load(file)
	Message=sign1["message"]
	Message=Message.encode()
	Signature_verify=sign1["Signature"]
	Signature_verify=Signature_verify.encode()
	Signature_verify=binascii.unhexlify(Signature_verify)
	asa=0
	file_path1 = os.path.join("C:/Users/surya/Project", "IOT_Keys.json")
	with open(file_path1, 'r') as file:
		pub_key=json.load(file)
	Public_key=pub_key[node_number]
	Public_key=Public_key.encode()
	Public_key=serialization.load_pem_public_key(Public_key, backend=default_backend())
	try:
		Public_key.verify(Signature_verify, Message, ec.ECDSA(hashes.SHA256()))
		asa=1
	except InvalidSignature:
		print("Signature is invalid")
	folder_path= "C:/Users/surya/Project/{}".format(args.port)
	file_path2 = os.path.join(folder_path, "keys.json")
	with open(file_path2,'r') as file:
		fog_key=json.load(file)
	fog_pri=fog_key["private_key"]
	fog_pri=fog_pri.encode()
	fog_pri= load_pem_private_key(fog_pri, password=None, backend=default_backend())
	file_path2 = os.path.join("C:/Users/surya/Project", "IOT_Keys.json")
	with open(file_path2,'r') as file:
		iot_key=json.load(file)
	iot_pub=iot_key[node_number]
	iot_pub=iot_pub.encode()
	iot_pub=serialization.load_pem_public_key(iot_pub, backend=default_backend())	
	secret_key = fog_pri.exchange(ec.ECDH(), iot_pub)
	secret_key1=base64.urlsafe_b64encode(secret_key)
	file_path= os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'w') as file:
		file.truncate(0)
	id =  datetime.datetime.now().timestamp()
	id=int(id )
	id=str(id)
	message = id.encode()
	message=base64.urlsafe_b64encode(message)
	padder = PKCS7(128).padder()
	padded_message = padder.update(message) + padder.finalize()
	iv = b"1234567890123456" # initialization vector
	cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encrypted_message1 = encryptor.update(padded_message) + encryptor.finalize()
	encrypted_message1=base64.urlsafe_b64encode(encrypted_message1)
	message=secret_key1
	padder = PKCS7(128).padder()
	padded_message = padder.update(message) + padder.finalize()
	iv = b"1234567890123456" # initialization vector
	cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encrypted_message2 = encryptor.update(padded_message) + encryptor.finalize()
	encrypted_message2=base64.urlsafe_b64encode(encrypted_message2)
	keys1={}
	keys1["key"]=encrypted_message2.decode()
	keys1["nounce"]=encrypted_message1.decode()
	with open(file_path,'w') as file:
		json.dump(keys1,file)
	i=node_number
	c2="Validate_SharedKey"
	path_value="http://127.0.0.1:{}/{}".format(i,c2)
	nothing=requests.post(path_value,data=args.port)
	file_path= os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'r') as file:
		nounce_verify=json.load(file)
	Verify_Nounce=nounce_verify["nounce"]
	nounce=int(id)
	nounce=nounce*2
	nounce=nounce+2
	if nounce==Verify_Nounce:
		#storing secret key
		secret_key=base64.urlsafe_b64encode(secret_key)
		secret_key=secret_key.decode('utf-8')
		folder_path= "C:/Users/surya/Project/{}".format(node_number)
		file_path = os.path.join(folder_path, "keys.json")
		with open(file_path,'r') as file:
			store=json.load(file)
		store[node_number].append(secret_key)
		with open(file_path,'w') as file:
			json.dump(store,file)
		
		folder_path= "C:/Users/surya/Project/{}".format(args.port)
		file_path = os.path.join(folder_path, "IOT.json")
		with open(file_path,'r') as file:
			store=json.load(file)
		store[node_number].append(secret_key)
		with open(file_path,'w') as file:
			json.dump(store,file)
		print(node_number," shared secret key is generated and shared with the IoT node")

	return "nothing"


@app.route('/Validate_SharedKey',methods=['POST'])
def Validate_SharedKeyIOT():
	fog_node_number=request.data.decode("utf-8")
	file_path= os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'r') as file:
		data=json.load(file)
	shared_key=data["key"]
	nounce=data["nounce"]
	file_path1= os.path.join("C:/Users/surya/Project", "Public_keys.json")
	with open(file_path1,'r') as file:
		data1=json.load(file)
	fog_node_pub=data1[fog_node_number][0]
	folder_path= "C:/Users/surya/Project/{}".format(args.port)
	file_path2 = os.path.join(folder_path, "keys.json")
	with open(file_path2,'r') as file:
		data2=json.load(file)
	Iot_Pri=data2[args.port][0]
	Iot_Pri=Iot_Pri.encode()
	Iot_Pri = load_pem_private_key(Iot_Pri, password=None, backend=default_backend())
	#generating shared secret key
	fog_node_pub=fog_node_pub.encode()
	fog_node_pub = serialization.load_pem_public_key(fog_node_pub, backend=default_backend())
	secret_key = Iot_Pri.exchange(ec.ECDH(), fog_node_pub)
	
	nounce=nounce.encode()
	nounce=base64.urlsafe_b64decode(nounce)
	
	iv = b"1234567890123456"
	cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
	decryptor=cipher.decryptor()
	decrypted_message = decryptor.update(nounce)+decryptor.finalize()
	# Unpad the decrypted message
	unpadder=PKCS7(128).unpadder()
	decrypted_message = unpadder.update(decrypted_message)+unpadder.finalize()
	decrypted_message=base64.urlsafe_b64decode(decrypted_message)
	nounce=decrypted_message.decode()
	
	nounce=int(nounce)
	nounce=nounce*2
	nounce=nounce+2
	Verifying={}
	Verifying["nounce"]=nounce
	file_path= os.path.join("C:/Users/surya/Project", "IOT_TimeStamp.json")
	with open(file_path,'w') as file:
		json.dump(Verifying,file)
	#decrypting shared key
	return "success"

@app.route('/mokri',methods=['POST'])
def create_graph():
	class UndirectedAcyclicGraph:
		def __init__(self):
			self.nodes = {}

		def add_node(self, node_id):
			if node_id not in self.nodes:
				self.nodes[node_id] = []

		def add_edge(self, node1, node2):
			if node1 != node2 and node1 in self.nodes and node2 in self.nodes:
				if node2 not in self.nodes[node1]:
					self.nodes[node1].append(node2)
					self.nodes[node2].append(node1)

		def is_acyclic(self):
			visited = set()
			for node in self.nodes:
				if node not in visited:
					if self.is_cyclic_util(node, visited, -1):
						return False
			return True

		def is_cyclic_util(self, node, visited, parent):
			visited.add(node)
			for neighbor in self.nodes[node]:
				if neighbor not in visited:
					if self.is_cyclic_util(neighbor, visited, node):
						return True
				elif parent != neighbor:
					return True
			return False

		def find_hop_path(self, source, destination):
		    visited = set()
		    path = []
		    if self.is_hop_path_util(source, destination, visited, path):
		        return path
		    return []

		def is_hop_path_util(self, current, destination, visited, path):
			visited.add(current)
			path.append(current)
			if current == destination:
				return True
			for neighbor in self.nodes[current]:
				if neighbor not in visited:
					if self.is_hop_path_util(neighbor, destination, visited, path):
						return True
			path.pop()
			return False


	def generate_graph(num_nodes, min_edges, max_edges):
		graph = UndirectedAcyclicGraph()
		p="C:/Users/surya/Project/"+args.port+"/IOT.json"
		with open(p,'r') as f5:
			temp_data = json.load(f5)
		keys = temp_data.keys()
		nodes=[]
		for i in keys:
			nodes.append(i)
		


		for node in nodes:
		    graph.add_node(node)

		for node in nodes:
		    num_edges = random.randint(min_edges, max_edges)
		    edges = random.sample(nodes, num_edges)
		    for edge in edges:
		        graph.add_edge(node, edge)
		return graph


	def print_graph(graph):
	    print("Adjacency List:")
	    for node in graph.nodes:
	        neighbors = graph.nodes[node]
	        print(f"{node}: {neighbors}")


	# Get user input for the number of nodes, minimum number of edges, and maximum number of edges


	min_edges = 1
	p="C:/Users/surya/Project/"+args.port+"/IOT.json"

	with open(p,'r') as f5:
		temp_data = json.load(f5)
	keys = temp_data.keys()
	NoOfNodes=len(keys)
	max_edges = min(1,NoOfNodes)
	num_nodes = NoOfNodes

	# Generate the graph
	graph = generate_graph(num_nodes, min_edges, max_edges)

	# Print the graph
	print_graph(graph)

	# Get user input for the source and destination nodes
	source = input("Enter the source node: ")
	destination = input("Enter the destination node: ")
	folder_path= "C:/Users/surya/Project/{}".format(source)
	file_path = os.path.join(folder_path, "IOT_Number.txt")
	with open(file_path,'r') as file:
		fog_node=file.read()
	global Destiny
	Destiny=destination
	# Find the hop path between the source and destination nodes
	hop_path = graph.find_hop_path(source, destination)
	print("initially",hop_path)
	if fog_node in hop_path:
		pass
	else:
		if len(hop_path)==2:
			hop_path.insert(1,fog_node)
			print("Route path is created")

		elif len(hop_path)==0:
			hop_path.append(source)
			hop_path.append(int(fog_node))
			hop_path.append(destination)
			print("Route path is created")
		
		elif len(hop_path)==3:
			random_number = random.randint(1, 2)
			hop_path.insert(random_number,fog_node)
			print("Route path is created")
		else:
			max_len=len(fog_node)
			max_len=max_len-1
			random_number = random.randint(1, max_len)
			hop_path.insert(random_number,fog_node)


	global whole
	whole=(' -> '.join(map(str, hop_path)))
	
	#whole+=" -> "+ tik
	# Print the hop path
	if hop_path:
	    print(f"Hop path from {source} to {destination}: {' -> '.join(map(str, hop_path))}")
	else:
	    print(f"No hop path found between {source} and {destination}.")
	return source

# Authentication verification
@app.route('/krishna',methods=['POST'])
def points():
	file_path = os.path.join("C:/Users/surya/Project", "message.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
	Signature_verify=data['signed_data']
	Signature_verify=Signature_verify.encode()
	Signature_verify=binascii.unhexlify(Signature_verify)
	link="C:/Users/surya/Project/"+args.port+"/IOT.json"
	with open(link,'r') as file:
		keys=json.load(file)
	number=data['iot_node']
	iot_node=keys[number]
	iot_node=iot_node[1]

	iot_node=iot_node.encode()
	message=data['message']
	message=message.encode()
	iot_node= serialization.load_pem_public_key(iot_node, backend=default_backend())
	file_path = os.path.join("C:/Users/surya/Project", "message.json")
	with open(file_path, 'w') as file:
			file.truncate(0)

	try:
		iot_node.verify(Signature_verify, message, ec.ECDSA(hashes.SHA256()))
		print("Signature is valid ")
		url="http://127.0.0.1:"
		url+=args.port
		url+='/mokri'
		# in below response we get source id
		response=requests.post(url,data='b')
		global whole
		numbers = re.findall(r'\d+', whole)
		routing_path= [int(number) for number in numbers]
		value={}
		global Destiny
		destiny=Destiny
		value={'path':routing_path,'source':response.text,'destination':destiny,'Fog_node':args.port}
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'w') as file:
			json.dump(value,file)
		#start to call routing
		link="http://127.0.0.1:"+response.text+'/First'
		res=requests.post(link,data='b')
	except InvalidSignature:
		print("Signature is invalid")
	return "success"

@app.route('/First',methods=['POST'])
def First():
	global messages
	messages='i am sending packets through routing'
	messages=messages.encode()
	messages=base64.urlsafe_b64encode(messages)
	padder = PKCS7(128).padder()
	padded_message = padder.update(messages) + padder.finalize()
	file_path = os.path.join("C:/Users/surya/Project", "routing.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
	print("Message is starting to routing")
	path=data['path']
	next_node=path[1]
	source=data['source']
	destiny=data['destination']
	fognode=data['Fog_node']
	path.pop(0)

	link="C:/Users/surya/Project/"
	link+=args.port
	link+="/keys.json"
	with open(link,'r') as file:
		shared_key=json.load(file)
	shared_key=shared_key[args.port]
	shared_key=shared_key[2]
	# below process is to take the shared key from the file convert to our form
	shared_key=shared_key.encode('utf-8')
	shared_key=base64.urlsafe_b64decode(shared_key)
	iv = b"1234567890123456" # initialization vector
	cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
	print("encrypted message",encrypted_message)
	encrypted_message=base64.urlsafe_b64encode(encrypted_message)
	encrypted_message=encrypted_message.decode()
	#retrive encrypted msg and convert to our form
	#encrypted_messageq=binascii.unhexlify(encrypted_message)
	#print(encrypted_messageq)
	value={'path':path,'source':source,'destination':destiny,'Fog_node':fognode,'encrypted_message':encrypted_message}
	with open(file_path, 'w') as file:
		file.truncate(0)
	with open(file_path,'w') as file:
		json.dump(value,file)
	print("now starting of routiong at source")
	# Calculate the timestamp
	timestamp = datetime.datetime.now().timestamp()
	# Convert the timestamp to a datetime object
	dt = datetime.datetime.fromtimestamp(timestamp)

	# Format the datetime object as a string
	dt_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")

	# Print the timestamp and its interpretation
	print("Timestamp:", timestamp)
	print("Interpreted DateTime:", dt_str)
	link="http://127.0.0.1:"+str(next_node)+'/Receiver'
	res=requests.post(link,data='b')
	return "success"



@app.route('/Receiver',methods=['POST'])
def Receiver():
	file_path = os.path.join("C:/Users/surya/Project", "routing.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
	ffognode=data['Fog_node']
	ddestiny=data['destination']
	if ffognode==args.port:
		print("message is in intermediate path","received by ",args.port)
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'r') as file:
			data=json.load(file)
		path=data['path']
		next_node=path[1]
		source=data['source']
		fognode=data['Fog_node']
		destiny=data['destination']
		#retrivinf encrypted message
		encrypted_message=data['encrypted_message']
		encrypted_message=encrypted_message.encode()
		encrypted_message=base64.urlsafe_b64decode(encrypted_message)
		path.pop(0)
		folder_path= "C:/Users/surya/Project/{}".format(args.port)
		file_path1 = os.path.join(folder_path, "IOT.json")
		with open(file_path1, 'r') as file:
			data12=json.load(file)
		data12=data12[source]
		data12=data12[2]
		data12=data12.encode('utf-8')
		data12=base64.urlsafe_b64decode(data12)
		iv = b"1234567890123456" # initialization vector
		cipher = Cipher(algorithms.AES(data12), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
		# Unpad the decrypted message
		unpadder = PKCS7(128).unpadder()
		decrypted_message = unpadder.update(decrypted_message) + unpadder.finalize()
		#decrypted message
		decrypted_message=base64.urlsafe_b64decode(decrypted_message)
		decrypted_message=decrypted_message.decode()
		
		folder_path= "C:/Users/surya/Project/{}".format(args.port)
		file_path1 = os.path.join(folder_path, "IOT.json")
		with open(file_path1, 'r') as file:
			data=json.load(file)
		data=data[destiny]
		data=data[2]
		data=data.encode('utf-8')
		destinarion_key=base64.urlsafe_b64decode(data)
		iv = b"1234567890123456" # initialization vector
		cipher = Cipher(algorithms.AES(destinarion_key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		decrypted_message=decrypted_message.encode()
		decrypted_message=base64.urlsafe_b64encode(decrypted_message)
		padder = PKCS7(128).padder()
		padded_message = padder.update(decrypted_message) + padder.finalize()
		encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
		encrypted_message=base64.urlsafe_b64encode(encrypted_message)
		encrypted_message=encrypted_message.decode()
		value={'path':path,'source':source,'destination':destiny,'Fog_node':fognode,'encrypted_message':encrypted_message}
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'w') as file:
			file.truncate(0)
		with open(file_path, 'w') as file:
			json.dump(value,file)
		link="http://127.0.0.1:"+str(next_node)+'/Receiver'
		res=requests.post(link,data='b')
	
	elif ddestiny==args.port:
		print("message received by destination")
		# Calculate the timestamp
		timestamp = datetime.datetime.now().timestamp()

		# Convert the timestamp to a datetime object
		dt = datetime.datetime.fromtimestamp(timestamp)

		# Format the datetime object as a string
		dt_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")

		# Print the timestamp and its interpretation
		print("Timestamp:", timestamp)
		print("Interpreted DateTime:", dt_str)
		global messages
		print(messages)
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'w') as file:
			file.truncate(0)


	
	else:
		print("message received by intermediate node",args.port)
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'r') as file:
			data=json.load(file)
		path=data['path']

		next_node=path[1]
		path=path.pop(0)
		source=data['source']
		fognode=data['Fog_node']
		destiny=data['destination']
		encrypted_message=data['encrypted_message']
		value={'path':path,'source':source,'destination':destiny,'Fog_node':fognode,'encrypted_message':encrypted_message}
		file_path = os.path.join("C:/Users/surya/Project", "routing.json")
		with open(file_path, 'w') as file:
			file.truncate(0)
		with open(file_path, 'w') as file:
			json.dump(value,file)
		link="http://127.0.0.1:"+str(next_node)+'/Receiver'
		res=requests.post(link,data='b')

	return "success"
# Initialize BGP routing table

bgp_routing_table = {}

# List of neighboring ports
neighboring_ports = [5001,5002,5003]

# BGP configuration parameters
local_as = 65000
router_id = "192.168.0.1"

@app.route('/bgp/update', methods=['POST'])
def bgp_update():
    bgp_update = request.json
    
    # Extract BGP update information
    network_prefix = bgp_update['prefix']
    next_hop = bgp_update['next_hop']
    attributes = bgp_update['attributes']
    
    # Update BGP routing table
    bgp_routing_table[network_prefix] = {
        'next_hop': next_hop,
        'attributes': attributes
    }
    
    # Propagate the BGP update to neighboring ports
    propagate_bgp_update(network_prefix, next_hop, attributes)
    
    return 'BGP update received and processed'

def propagate_bgp_update(network_prefix, next_hop, attributes):
    # Code to propagate the BGP update to neighboring ports
    # This can be done by sending POST requests to the neighboring ports

    # Example code:
    for port in neighboring_ports:
        variable="bgp/update"
        url = "http://127.0.0.1:{}/{}".format(port,variable)
        bgp_update = {
            'prefix': network_prefix,
            'next_hop': next_hop,
            'attributes': attributes
        }
        response = requests.post(url, json=bgp_update)
        if response.status_code == 200:
            print(f"BGP update propagated to port {port}")
        else:
            print(f"Failed to propagate BGP update to port {port}. Status code: {response.status_code}")

@app.route('/bgphello', methods=['GET'])
def bgp_hello():
    # Send BGP hello messages to neighboring ports
    send_hello_messages()

    return 'BGP hello messages sent'

def send_hello_messages():
    for port in neighboring_ports:
        variable="bgphello"
        url = "http://127.0.0.1:{}/{}".format(port,variable)
        response = requests.get(url)
        if response.status_code == 200:
            print(f"Received hello response from port {port}")
        else:
            print(f"Hello request to port {port} failed. Status code: {response.status_code}")

def initialize_bgp_session():
    # Send initial BGP OPEN messages to neighboring ports
    
    # Example code:
    for port in neighboring_ports:
        variable="bgpopen"
        url = "http://127.0.0.1:{}/{}".format(port,variable)
        open_message = {
            'version': 4,
            'local_as': local_as,
            'router_id': router_id
        }
        response = requests.post(url, json=open_message)
        if response.status_code == 200:
            print(f"Initialized BGP session with port {port}")
        else:
            print(f"Failed to initialize BGP session with port {port}. Status code: {response.status_code}")

def advertise_routes():
    # Advertise routes to neighboring ports
    
    # Example code:
    for prefix in neighboring_ports:
        for port in neighboring_ports:
            variable="bgpadvertise"
            url = "http://127.0.0.1:{}/{}".format(port,variable)
            
            bgp_update = {
                'prefix': prefix,
                'next_hop': prefix+23,
                'attributes': "nothing"
            }
            response = requests.post(url, json=bgp_update)
            if response.status_code == 200:
                print(f"Advertised route {prefix} to port {port}")
            else:
                print(f"Failed to advertise route {prefix} to port {port}. Status code: {response.status_code}")


@app.route('/bgp/hop-path', methods=['POST'])
def get_hop_path():
    request_data = request.json
    source_port = request_data['source_port']
    destination_port = request_data['destination_port']

    hop_path = find_hop_path(source_port, destination_port)

    response = {
        'hop_path': hop_path
    }

    return response

@app.route('/bgpopen', methods=['POST'])
def bgp_open():
    open_message = request.json
    
    # Extract relevant information from the BGP OPEN message
    version = open_message.get('version')
    local_as = open_message.get('local_as')
    router_id = open_message.get('router_id')

    # Process the BGP OPEN message
    # For example, you can perform some validation or store the information
    
    # Print the received OPEN message for demonstration purposes
    print("Received BGP OPEN message:")
    print(f"Version: {version}")
    print(f"Local AS: {local_as}")
    print(f"Router ID: {router_id}")

    return 'BGP OPEN message received'


#for initiating bgp protocol process
@app.route('/forward', methods=['POST'])
def forward():
	initialize_bgp_session()
	advertise_routes()
	return "success"


@app.route('/bgpadvertise', methods=['POST'])
def bgp_advertise():
    bgp_update = request.json
    
    # Extract relevant information from the BGP UPDATE message
    prefix = bgp_update.get('prefix')
    next_hop = bgp_update.get('next_hop')
    attributes = bgp_update.get('attributes')

    # Process the BGP UPDATE message for route advertisement
    # For example, you can update the BGP routing table or perform other operations
    
    # Print the received UPDATE message for demonstration purposes
    print("Received BGP UPDATE message:")
    print(f"Prefix: {prefix}")
    print(f"Next Hop: {next_hop}")
    print(f"Attributes: {attributes}")

    return 'BGP UPDATE message received'




#below API is for testing only
@app.route('/mokrii',methods=['POST'])
def printt():
	global whole
	numbers = re.findall(r'\d+', whole)
	path_numbers = [int(number) for number in numbers]
	print("route is",path_numbers)
	return "success"

@app.route('/BGP1',methods=['POST'])
def BGP1():
	file_path = os.path.join("C:/Users/surya/Project", "BGP_Details.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
	Signature_verify=data['signed_data']
	Signature_verify=Signature_verify.encode()
	Signature_verify=binascii.unhexlify(Signature_verify)
	link="C:/Users/surya/Project/"+args.port+"/IOT.json"
	with open(link,'r') as file:
		keys=json.load(file)
	number=data['iot_node']
	iot_node=keys[number]
	iot_node=iot_node[1]
	iot_node=iot_node.encode()
	message=data['message']
	message=message.encode()
	iot_node= serialization.load_pem_public_key(iot_node, backend=default_backend())
	file_path = os.path.join("C:/Users/surya/Project", "BGP_Details.json")
	with open(file_path, 'w') as file:
			file.truncate(0)
	final_D=input("Enter the destination Iot node to reach")
	link="C:/Users/surya/Project/"
	b=number
	link+=final_D
	link+="/IOT_Number.txt"
	with open(link, 'r') as file:
		d2=file.read()
	#storing second fog node
	
	source=number
	D1=args.port
	D2=d2
	final_destination=final_D
	#print("Here are me points",source,D1,D2,final_destination)
	try:
		iot_node.verify(Signature_verify, message, ec.ECDSA(hashes.SHA256()))
		print("Signature is valid ")
		url="http://127.0.0.1:"
		url+=args.port
		url+='/BGP2'
		# in below response we get source id
		response=requests.post(url,data=source)
		#hop path storing
		global whole
		numbers = re.findall(r'\d+', whole)
		#to store one part of routing
		routing_path1= [int(number) for number in numbers]
		value={}
		#For calculating between fog nodes
		file_path = os.path.join("C:/Users/surya/Project", "Public_keys.json")
		with open(file_path, 'r') as file:
			total_nodes=json.load(file)
		keys = len(total_nodes)
		graph = tcp2.generate_random_topology(keys)
		tcp2.print_topology(graph)
		shortest_path =tcp2.find_shortest_path(graph, int(D1), int(D2))
		shortest_path.pop(0)
		details={"source":D1,"destination":D2}
		#for third part of routing
		url="http://127.0.0.1:"
		url+=D2
		url+='/BGP4'
		# in below response we get source id
		response=requests.post(url,data=final_destination)
		numbers = re.findall(r'\d+', response.text)
		#to store one part of routing
		routing_path2= [int(number) for number in numbers]
		routing_path2.pop(0)
		#hop path storing
		routing_path1=routing_path1+shortest_path
		routing_path1=routing_path1+routing_path2
		print("this is the final routing path ",routing_path1)
		
		#follwing code is to generate secret key between iot nodes
		private_key = ec.generate_private_key(ec.SECP256R1())

		# Serialize the private key in PEM format
		pem_private_key = private_key.private_bytes(encoding=Encoding.PEM,format=PrivateFormat.PKCS8,encryption_algorithm=NoEncryption())

		# Generate the corresponding public key
		public_key = private_key.public_key()

		# Serialize the public key in PEM format
		pem_public_key = public_key.public_bytes(encoding=Encoding.PEM,format=PublicFormat.SubjectPublicKeyInfo)

		# Example private key as b
		# Decode the PEM format keys
		priv_key_pem =pem_private_key
		pub_key_pem =pem_public_key

		# Load the PEM keys
		priv_key = load_pem_private_key(priv_key_pem, password=None, backend=default_backend())
		pub_key = serialization.load_pem_public_key(pub_key_pem, backend=default_backend())

		# Derive the Secret Key
		secret_key = priv_key.exchange(ec.ECDH(), pub_key)
		print(args.port," generated the secret key ",secret_key)
		#convert to a form to store in file
		secret_key = base64.urlsafe_b64encode(secret_key)
		secret_key = secret_key.decode('utf-8')
		value={"path":routing_path1,"source":source,"Des1":D1,"Des2":D2,"Final_Des":final_destination,"Keys":secret_key,"message":"Testing message"}
		file_path = os.path.join("C:/Users/surya/Project", "BGP_Details.json")
		with open(file_path, 'w') as file:
			file.truncate(0)
		with open(file_path,'w') as file:
			json.dump(value,file)
		url="http://127.0.0.1:"
		url+=str(source)
		url+='/BGPreceiver'
		response=requests.post(url,data='b')

		#storing the block in main chain
		file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
		with open(file_path, 'r') as file:
			data=json.load(file)
		Prev_block=data["Prev_block"]
		Prev_hash=data["Prev_hash"]
		value1={"path":routing_path1,"source":source,"Des1":D1,"Des2":D2,"Final_Des":final_destination,"Keys":secret_key,"message":"Testing message","prev_hash":Prev_hash}
		json_string = json.dumps(value1)
		hash_object = hashlib.sha256(json_string.encode())
		present_hash = hash_object.hexdigest()
		#this is my current block to store in ledger
		value1={"node":args.port,"Block_No":Prev_block+1,"path":routing_path1,"source":source,"Final_Des":final_destination,"hash_value":present_hash}
		tem_data={}
		tem_data={"Prev_block":Prev_block+1,"Prev_hash":present_hash}
		file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
		with open(file_path, 'w') as file:
			json.dump(tem_data,file)
		#Storing in uncommited file
		file_path = os.path.join("C:/Users/surya/Project", "Uncommited.json")
		with open(file_path, 'w') as file:
			json.dump(value1,file)
		file_path = os.path.join("C:/Users/surya/Project", "Public_keys.json")
		with open(file_path, 'r') as file:
			data=json.load(file)
		keys = data.keys()
		No_Of_Nodes=len(keys)
		for i in keys:
			url="http://127.0.0.1:"
			url+=str(i)
			url+='/BGPValidate'
			response=requests.post(url,data='b')
		file_path = os.path.join("C:/Users/surya/Project", "Uncommited.json")
		with open(file_path, 'w') as file:
			file.truncate(0)
	except InvalidSignature:
		print("Signature is invalid")
	return "success"



#Validate the bgp routing
@app.route('/BGPValidate',methods=['POST'])
def BGPValidate():
	#to get prev block number
	file_path = os.path.join("C:/Users/surya/Project", "Global_variables.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
	#to get data
	file_path = os.path.join("C:/Users/surya/Project", "Uncommited.json")
	with open(file_path, 'r') as file:
		data1=json.load(file)
			
	Curr_block=data["Prev_block"]
	v1="/Distributed_Ledger/"
	v2=v1+"Block"+str(Curr_block)
	#store the validated data in block chain
	file_path1="C:/Users/surya/Project/{}/{}".format(args.port,v2)
	with open(file_path1,'w') as file:
		json.dump(data1,file,indent=4)
	return "Success"






#This API is to route the bgp message
@app.route('/BGPreceiver',methods=['POST'])
def BGPreceiver():
	file_path = os.path.join("C:/Users/surya/Project", "BGP_Details.json")
	with open(file_path, 'r') as file:
		data=json.load(file)
		path=data["path"]
		source=data["source"]
		Des1=data["Des1"]
		Des2=data["Des2"]
		keys=data["Keys"]
		message=data["message"]
		final_destination=data["Final_Des"]
		if args.port==source:
			# Calculate the timestamp
			timestamp = datetime.datetime.now().timestamp()

			# Convert the timestamp to a datetime object
			dt = datetime.datetime.fromtimestamp(timestamp)

			# Format the datetime object as a string
			dt_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")

			# Print the timestamp and its interpretation
			print("Timestamp:", timestamp)
			print("Interpreted DateTime:", dt_str)
			print("now it is the start of BGP routing")


			path.pop(0)
			nextnode=path.pop(0)
			#keys converting to our form
			keys=keys.encode('utf-8')
			keys=base64.urlsafe_b64decode(keys)
			message="This is a message from "+str(source)+" to"+str(final_destination)
			message=message.encode()
			message=base64.urlsafe_b64encode(message)
			padder = PKCS7(128).padder()
			padded_message = padder.update(message) + padder.finalize()
			iv = b"1234567890123456" # initialization vector
			cipher = Cipher(algorithms.AES(keys), modes.CBC(iv), backend=default_backend())
			encryptor = cipher.encryptor()
			encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
			message=base64.urlsafe_b64encode(encrypted_message)
			message=message.decode()
			print("This is the encrypted message sent by ",args.port," ",message)
			value={}
			print("secret_key",keys)
			keys=base64.urlsafe_b64encode(keys)
			keys=keys.decode('utf-8')
			value={"path":path,"source":source,"Des1":Des1,"Des2":Des2,"Final_Des":final_destination,"Keys":keys,"message":message}
			file_path = os.path.join("C:/Users/surya/Project", "BGP_Details.json")
			with open(file_path, 'w') as file:
				json.dump(value,file)
			url="http://127.0.0.1:"
			url+=str(nextnode)
			url+='/BGPreceiver'
			response=requests.post(url,data='b')
			
		elif args.port==Des1:
			print("Now the packet is with source's fog node")
			nextnode=path.pop(0)
			value={}
			value={"path":path,"source":source,"Des1":Des1,"Des2":Des2,"Final_Des":final_destination,"Keys":keys,"message":message}
			with open(file_path, 'w') as file:
				json.dump(value,file)
			url="http://127.0.0.1:"
			url+=str(nextnode)
			url+='/BGPreceiver'
			response=requests.post(url,data='b')
			
		elif args.port==Des2:
			print("the packet came to destination IOT's fog node")
			nextnode=path.pop(0)
			value={}
			value={"path":path,"source":source,"Des1":Des1,"Des2":Des2,"Final_Des":final_destination,"Keys":keys,"message":message}
			with open(file_path, 'w') as file:
				json.dump(value,file)
			url="http://127.0.0.1:"
			url+=str(nextnode)
			url+='/BGPreceiver'
			response=requests.post(url,data='b')
		
		elif args.port==final_destination:
			print("it entered final destination")
			# Calculate the timestamp
			timestamp = datetime.datetime.now().timestamp()

			# Convert the timestamp to a datetime object
			dt = datetime.datetime.fromtimestamp(timestamp)

			# Format the datetime object as a string
			dt_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")

			# Print the timestamp and its interpretation
			print("Timestamp:", timestamp)
			print("Interpreted DateTime:", dt_str)
			keys=keys.encode('utf-8')
			keys=base64.urlsafe_b64decode(keys)
			iv = b"1234567890123456" # initialization vector
			cipher = Cipher(algorithms.AES(keys), modes.CBC(iv), backend=default_backend())
			message=message.encode()
			message=base64.urlsafe_b64decode(message)
			decryptor = cipher.decryptor()
			decrypted_message = decryptor.update(message) + decryptor.finalize()
			unpadder = PKCS7(128).unpadder()
			decrypted_message = unpadder.update(decrypted_message) + unpadder.finalize()
			decrypted_message=base64.urlsafe_b64decode(decrypted_message)
			print("The message sent by ",source," after decrypting is ",decrypted_message)
			with open(file_path, 'w') as file:
				file.truncate(0)
			
		else:
			print("it entered intermediate noode")
			nextnode=path.pop(0)
			value={}
			value={"path":path,"source":source,"Des1":Des1,"Des2":Des2,"Final_Des":final_destination,"Keys":keys,"message":message}
			with open(file_path, 'w') as file:
				json.dump(value,file)
			url="http://127.0.0.1:"
			url+=str(nextnode)
			url+='/BGPreceiver'
			response=requests.post(url,data='b')


	return "success"

#this is for second fog node to final destination
@app.route('/BGP4',methods=['POST'])
def create_graph_for_BGP():
	class UndirectedAcyclicGraph:
		def __init__(self):
			self.nodes = {}

		def add_node(self, node_id):
			if node_id not in self.nodes:
				self.nodes[node_id] = []

		def add_edge(self, node1, node2):
			if node1 != node2 and node1 in self.nodes and node2 in self.nodes:
				if node2 not in self.nodes[node1]:
					self.nodes[node1].append(node2)
					self.nodes[node2].append(node1)

		def is_acyclic(self):
			visited = set()
			for node in self.nodes:
				if node not in visited:
					if self.is_cyclic_util(node, visited, -1):
						return False
			return True

		def is_cyclic_util(self, node, visited, parent):
			visited.add(node)
			for neighbor in self.nodes[node]:
				if neighbor not in visited:
					if self.is_cyclic_util(neighbor, visited, node):
						return True
				elif parent != neighbor:
					return True
			return False

		def find_hop_path(self, source, destination):
		    visited = set()
		    path = []
		    if self.is_hop_path_util(source, destination, visited, path):
		        return path
		    return []

		def is_hop_path_util(self, current, destination, visited, path):
			visited.add(current)
			path.append(current)
			if current == destination:
				return True
			for neighbor in self.nodes[current]:
				if neighbor not in visited:
					if self.is_hop_path_util(neighbor, destination, visited, path):
						return True
			path.pop()
			return False


	def generate_graph_for_BGP(num_nodes, min_edges, max_edges):
		graph = UndirectedAcyclicGraph()
		p="C:/Users/surya/Project/"+args.port+"/IOT.json"
		with open(p,'r') as f5:
			temp_data = json.load(f5)
		keys = temp_data.keys()
		nodes=[]
		for i in keys:
			nodes.append(i)
			nodes.append(args.port)
		


		for node in nodes:
		    graph.add_node(node)

		for node in nodes:
		    num_edges = random.randint(min_edges, max_edges)
		    edges = random.sample(nodes, num_edges)
		    for edge in edges:
		        graph.add_edge(node, edge)
		return graph


	def print_graph_for_BGP(graph):
	    print("Adjacency List:")
	    for node in graph.nodes:
	        neighbors = graph.nodes[node]
	        print(f"{node}: {neighbors}")


	# Get user input for the number of nodes, minimum number of edges, and maximum number of edges


	min_edges = 1
	p="C:/Users/surya/Project/"+args.port+"/IOT.json"

	with open(p,'r') as f5:
		temp_data = json.load(f5)
	keys = temp_data.keys()
	NoOfNodes=len(keys)
	max_edges = min(1,NoOfNodes)
	num_nodes = NoOfNodes

	# Generate the graph
	graph = generate_graph_for_BGP(num_nodes, min_edges, max_edges)

	# Print the graph
	print_graph_for_BGP(graph)

	# Get user input for the source and destination nodes
	source = args.port
	destination = request.data.decode('utf-8')
	print("in last",source,destination)
	folder_path= "C:/Users/surya/Project/{}".format(source)
	
	global Destiny
	Destiny=destination
	# Find the hop path between the source and destination nodes
	hop_path = graph.find_hop_path(source, destination)
	print("initially",hop_path)
	if source in hop_path:
		print("no change")
	else:
		if len(hop_path)==0:
			hop_path.append(source)
			hop_path.append(int(destination))
			

	#to store hop path
	second_path=(' -> '.join(map(str, hop_path)))
	global whole1
	whole1=second_path
	#whole+=" -> "+ tikstring_list
	
	print("second seconf second",whole1)
	# Print the hop path
	if hop_path:
	    print(f"Hop path from {source} to {destination}: {' -> '.join(map(str, hop_path))}")
	else:
	    print(f"No hop path found between {source} and {destination}.")
	return whole1



@app.route('/BGP2',methods=['POST'])
def create_graph_for_BGP2():
	class UndirectedAcyclicGraph:
		def __init__(self):
			self.nodes = {}

		def add_node(self, node_id):
			if node_id not in self.nodes:
				self.nodes[node_id] = []

		def add_edge(self, node1, node2):
			if node1 != node2 and node1 in self.nodes and node2 in self.nodes:
				if node2 not in self.nodes[node1]:
					self.nodes[node1].append(node2)
					self.nodes[node2].append(node1)

		def is_acyclic(self):
			visited = set()
			for node in self.nodes:
				if node not in visited:
					if self.is_cyclic_util(node, visited, -1):
						return False
			return True

		def is_cyclic_util(self, node, visited, parent):
			visited.add(node)
			for neighbor in self.nodes[node]:
				if neighbor not in visited:
					if self.is_cyclic_util(neighbor, visited, node):
						return True
				elif parent != neighbor:
					return True
			return False

		def find_hop_path(self, source, destination):
		    visited = set()
		    path = []
		    if self.is_hop_path_util(source, destination, visited, path):
		        return path
		    return []

		def is_hop_path_util(self, current, destination, visited, path):
			visited.add(current)
			path.append(current)
			if current == destination:
				return True
			for neighbor in self.nodes[current]:
				if neighbor not in visited:
					if self.is_hop_path_util(neighbor, destination, visited, path):
						return True
			path.pop()
			return False


	def generate_graph_for_BGP2(num_nodes, min_edges, max_edges):
		graph = UndirectedAcyclicGraph()
		p="C:/Users/surya/Project/"+args.port+"/IOT.json"
		with open(p,'r') as f5:
			temp_data = json.load(f5)
		keys = temp_data.keys()
		nodes=[]
		for i in keys:
			nodes.append(i)
			nodes.append(args.port)
		


		for node in nodes:
		    graph.add_node(node)

		for node in nodes:
		    num_edges = random.randint(min_edges, max_edges)
		    edges = random.sample(nodes, num_edges)
		    for edge in edges:
		        graph.add_edge(node, edge)
		return graph


	def print_graph_for_BGP2(graph):
	    print("Adjacency List:")
	    for node in graph.nodes:
	        neighbors = graph.nodes[node]
	        print(f"{node}: {neighbors}")


	# Get user input for the number of nodes, minimum number of edges, and maximum number of edges


	min_edges = 1
	p="C:/Users/surya/Project/"+args.port+"/IOT.json"

	with open(p,'r') as f5:
		temp_data = json.load(f5)
	keys = temp_data.keys()
	NoOfNodes=len(keys)
	max_edges = min(1,NoOfNodes)
	num_nodes = NoOfNodes

	# Generate the graph
	graph = generate_graph_for_BGP2(num_nodes, min_edges, max_edges)

	# Print the graph
	print_graph_for_BGP2(graph)

	# Get user input for the source and destination nodes
	source = request.data.decode('utf-8')
	destination = args.port
	folder_path= "C:/Users/surya/Project/{}".format(source)
	file_path = os.path.join(folder_path, "IOT_Number.txt")
	with open(file_path,'r') as file:
		fog_node=file.read()
	global Destiny
	Destiny=destination
	# Find the hop path between the source and destination nodes
	hop_path = graph.find_hop_path(source, destination)
	
	if fog_node in hop_path:
		pass
	else:
		if len(hop_path)==0:
			hop_path.append(source)
			hop_path.append(int(fog_node))
			

	#to store hop path
	global whole
	whole=(' -> '.join(map(str, hop_path)))
	
	#whole+=" -> "+ tik
	# Print the hop path
	if hop_path:
	    print(f"Hop path from {source} to {destination}: {' -> '.join(map(str, hop_path))}")
	else:
	    print(f"No hop path found between {source} and {destination}.")
	return whole1

if __name__== "__main__":
	parser=argparse.ArgumentParser()
	parser.add_argument("-n","--node",help="Node")
	parser.add_argument("-p","--port",help="port")
	args=parser.parse_args()
	if args.port and args.node:
		port=args.port
		node=args.node
		app.run(port=port)
		print(args.node," is started successfully")
	else:
		print("port number not specified")