from ctypes import *
import os
from hashlib import md5
from time import asctime,sleep
from __include__ import *
from const import *
from collections import namedtuple as StructObject
from logging import *


class _Logger:
	def __init__(self):
		self.logger = getLogger("HookerLog")
		self.logger.setLevel("INFO")
		self.fh = FileHandler(filename = "../log/PN.log",encoding='utf-8');
		self.fh.setLevel("INFO")
		self.formatter = Formatter("%(asctime)s - %(message)s")
		self.fh.setFormatter(self.formatter)
		self.logger.addHandler(self.fh);
		
	def info(self,data):
		self.logger.info(data)


_log = _Logger()
rest = ColorRest()
SendObject = StructObject("SendObjectStruct",'Modules, Process_Ident, Process_Name, Process_EXE_PATH,Process_HASH_SUM,Asctime');
def ImageDigest(lpFileName):
	if os.path.exists(lpFileName):
		f = open(lpFileName,"rb")
		data = f.read()
		digest = md5(data).hexdigest().upper()
		return digest

										
def __GetProcessImageFileName(dwProcessID):
	hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,False,dwProcessID)
	if hProcess == 0:return -1
	lpBuffer = create_unicode_buffer(255)
	pathsize = c_int(sizeof(lpBuffer))
	if (windll.kernel32.QueryFullProcessImageNameW(hProcess,0,byref(lpBuffer),byref(pathsize)) == 0):	#QueryFullProcessImageName(hProcess, dwFlags, byref(self.pathBuffer), byref(pathsize))
		windll.kernel32.CloseHandle(hProcess)
		return 0
	else:
		windll.kernel32.CloseHandle(hProcess)
		return (lpBuffer.value)
	
	
class Init():
	def HOOK(self):
		names,id = [],[];
		for x in Proyekt_PDHooker_Initializer().EnumProcess():
			names.append(x[0]);
			id.append(x[1]);
			R = [];
		while (1):
			sleep(0.1)
			for k in Proyekt_PDHooker_Initializer().EnumProcess():
				if not (k[1]) in id:
					return (k[1],k[0])
					
while (2 > 1 & 2 < 3):
	try:
		hook = Init().HOOK()
		l = [j for j in Proyekt_PDHooker_Initializer().EnumModules(hook[0])]
		Point = SendObject(l,hook[0],hook[1],__GetProcessImageFileName(hook[0]),ImageDigest(__GetProcessImageFileName(hook[0])),asctime())
		COLOR(226)

		__log__ = ("Yeni Proses qeydə alındı: PID:{} Name:{} Path:{} MD5:{}".format(Point[1],Point[2].decode(),Point[3],Point[4]))
		_log.info(__log__)
		print("[+]PID:{} Name:{} Path:{} MD5:{}".format(Point[1],Point[2].decode(),Point[3],Point[4]))
		COLOR(rest)
	except KeyboardInterrupt:
		exit(1)