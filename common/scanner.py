import http.client
import hashlib
import socket
import sqlite3
		
def _blacklist(suspicous_file_path):
	blacklist_string_file = "etc/blacklist.txt"
	f = open(blacklist_string_file,"r");
	fsusp = open(suspicous_file_path,"rb");
	str_1 = f.readlines()
	str_2 = fsusp.read()
	f.close()
	fsusp.close()
	detected = []
	for badstr in str_1:
		if str_2.find(badstr.strip('\n').encode()) != -1:
			detected.append(badstr.strip('\n'));
	return (detected)
	
	
def SignatureScan(_Data,Signature):
	import binascii
	field_name = Signature.split(":")[0]	##UPX
	field_signid = Signature.split(":")[1]	##60BE006040008DBE
	rebased = binascii.a2b_hex(field_signid)
	if (_Data.find(rebased) != -1):
		return field_name
	else:
		return None