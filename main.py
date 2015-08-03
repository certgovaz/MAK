from winstruct import *
from prototype import *
from cc import *
from ctypes import *
from threading import Thread
import os,hashlib
from common.scanner import _blacklist,SignatureScan
from common.regdump import REnum
from common.colored_text import *
from datetime import datetime
from time import asctime
import struct,socket
from collections import namedtuple


	
	
def dirmon(lpDirectoryPath):
	"""Bu funksiya qovluq monitoring-nin daha tekminlesmish versiyasidir.
	Kitabxana fayli olaraq deyl bir basha executable uzerinden fealiyyet gosterir.
	SubDirectory izlemeleri ucun 2 ci parametri True olaraq vermelisiniz lakin buna baxmayaraq sistemin az yuklenmesinin qarsisini almaq ucun
	default olaraq bu parametr False olaraq prosese oturulur.
	"""
	return os.system("start dirmon.exe %s" % lpDirectoryPath)

def terminateall(pid_list):
		for x in pid_list:
			hProcess = OpenProcess(PROCESS_TERMINATE,False,x)
			if hProcess == NULL:
				return -1
			else:
				if ZwTerminateProcess(hProcess,True) == STATUS_SUCCESS:
					CloseHandle(hProcess)
				else:
					return -1

def curdir():
	DirectoryBuffer = create_unicode_buffer(MAX_PATH)
	GetCurrentDirectoryW(sizeof(DirectoryBuffer), byref(DirectoryBuffer))
	return (DirectoryBuffer.value)


def setcurrentdir(LpDIR):
	SetCurrentDirectoryW(LpDIR)
	return None

	
	
def cls():
		os.system("cls")
	
def KillThread(hEventName):
	"""Monitor ucun yaradilmish threadlari dayandirmaq(terminate) ucun nezerde tutulub.
	yaradilan threadlara parametr olaraq verilen Event adini hEventName parametrine oturmeyiniz kifayetdir.
	SetEvent funksiyasi ugurla heyata kecirilirse 1 eks teqdirde ise 0 deyeri ile geri qayidacaq
	"""
	SUCCESS = 1
	ERROR = 0
	hEvent = OpenEvent(EVENT_ALL_ACCESS, False, hEventName.encode())
	
	Result = SetEvent(hEvent)
	if Result != 0:
		color_init.set(10)
		print("OK Thread stopped")
		color_init.reset()
		return 1
	else:
		color_init.set(12)
		print("Cannot stop(find) Thread")
		color_init.reset()
		return 0
		
def select():
	"""
	Bu funksiya istifadecilerin rahat bir sekilde sistemde olan fayllari secmek ucun(select) nezerde tutulub.
	"""
	cpath = curdir()
	dll = cdll.dialog
	dll.SelectFile.restype = c_char_p
	BUFFER = dll.SelectFile()
	setcurrentdir(cpath)
	return BUFFER.decode()
	
	
def ps():
	"""Bu funksiya novbeti klasslardan istifade etmek ucun lazim olan prosesin ID nomresini oyrenmek ucun nezerde tutulub.
	Beleki cari sistemde fealiyyyet gosteren proseslerin adlari ve ID nomrelerini generator obyektinde saxlayir.
	Generator obyektin yaradilma sebebi snapshot yalniz CreateToolhelp32Snapshot funksiyasi cagrildigi anda sistemde olan prosesleri enum edir.
	Buna gorede generator object daha meqsede uygun olacaq.
	"""
	all_process = 0
	ProcessEntry = PROCESSENTRY32()
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32)
	ret = []
	Process_Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,all_process)
	if (Process_Snapshot == INVALID_HANDLE_VALUE):
		CloseHandle(Process_Snapshot);
		return INVALID_HANDLE_VALUE
	else:
		if Process32First(Process_Snapshot, byref(ProcessEntry)) == 1:
			#print("PID\tParentPID\tProcessName\n###\t#########\t###########")
			color_init.set(12)	#color set
			while (Process32Next(Process_Snapshot, byref(ProcessEntry)) == 1):
				#print("{}\t{}\t\t{}".format(ProcessEntry.th32ProcessID,ProcessEntry.th32ParentProcessID,ProcessEntry.szExeFile.decode()))
				yield (ProcessEntry.th32ProcessID,ProcessEntry.szExeFile.decode(),ProcessEntry.th32ParentProcessID)
				# result = ("PID->{}\tProcessName->{}\tParentPID{}".format(ProcessEntry.th32ProcessID,ProcessEntry.szExeFile.decode(),ProcessEntry.th32ParentProcessID))
				# yield(result)
			CloseHandle(Process_Snapshot)
			color_init.reset()	#color reset
		else:
			CloseHandle(Process_Snapshot)
			return -1
			
			
class PROCESS:
	def __init__(self,dwPID):
		assert isinstance(dwPID,int),'%s is not integer(DWORD)' % dwPID
		self.global_id = dwPID
			
			
			
	def path(self,dwFlags = 0):
		PID = self.global_id
		Result = 0
		self.pathBuffer = create_unicode_buffer(MAX_PATH)
		pathsize = c_int(sizeof(self.pathBuffer))
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,False,PID)
		if hProcess == NULL:
			return -1
		else:
			Result = QueryFullProcessImageName(hProcess, dwFlags, byref(self.pathBuffer), byref(pathsize))
			if Result != 0:
				CloseHandle(hProcess)
				return (self.pathBuffer.value)
			else:
				CloseHandle(hProcess)
				return -1
				
	def digest(self,bAlg = "md5"):
		with open(self.pathBuffer.value,"rb") as f:
			if bAlg == "md5":
				digest = hashlib.md5(f.read()).hexdigest()
			if bAlg == "sha1":
				digest = hashlib.sha1(f.read()).hexdigest()
			return digest.upper()
			
	def blackimport(self):
		file = self.pathBuffer.value
		listed = []
		for x in _blacklist(file):
			if x != None:
				print(x)
			else:
				return SUCCESS
			
	def modules(self):
		PID = self.global_id
		h_Process = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,PID)
		ModuleEntry = MODULEENTRY32()
		ModuleEntry.dwSize = sizeof(MODULEENTRY32)
		mlist = []
		if h_Process == INVALID_HANDLE_VALUE:
			return INVALID_HANDLE_VALUE
		else:
			if Module32First(h_Process, byref(ModuleEntry)) == 1:
				while (Module32Next(h_Process, byref(ModuleEntry)) == 1):
					yield (ModuleEntry)	#Generator Object
							
				CloseHandle(h_Process)
			else:
				CloseHandle(h_Process)
				return -1
				
				
	def dep(self,epid = None):
		
		
		PID  = self.global_id
		perm = c_int(0)
		DEP = c_int()
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, True,PID)
		if hProcess == NULL:
			return -1
		else:
			BOOLResult = GetProcessDEPPolicy(hProcess, byref(DEP),byref(perm))
			if BOOLResult == True:
				CloseHandle(hProcess)
				if DEP.value == 0:
					color_init.set(12)
					print("DEP Disabled")
					color_init.reset()
				elif DEP.value == 1:
					color_init.set(10)
					print("DEP Enabled")
					color_init.reset()
				elif DEP.value == 2:
					color_init.set(10)
					print("PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION")
					color_init.reset()
				else:
					
					print("Enabled, DEP-ATL thunk emulation disabled, Permanent")
			else:
				CloseHandle(hProcess)
				return False
				
	def process_time(self):
		PID = self.global_id
		lpCreateTime = FILETIME()
		lpExitTime = FILETIME()
		lpKernelTime = FILETIME()
		lpUserTime = FILETIME()
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,False,PID)
		if hProcess == NULL:
			return -1
		else:
			BOOLResult = GetProcessTimes(hProcess, byref(lpCreateTime), byref(lpExitTime), byref(lpKernelTime),
																							byref(lpUserTime));
			return [lpCreateTime]
			
	def systime(self,data):
		lpc = data[0]	#->CreateTime
		
		
		stime = SYSTEMTIME()
		utime = SYSTEMTIME()
		FileTimeToSystemTime(byref(data[0]),byref(stime))
		SystemTimeToTzSpecificLocalTime(None,byref(stime),byref(utime))
		history = "/".join([str(utime.wYear), str(utime.wMonth), str(utime.wDay)])
		t = ":".join([str(utime.wHour), str(utime.wMinute), str(utime.wSecond)])
		return [history,t]
		
	def terminate(self):
		PID = self.global_id
		hProcess = OpenProcess(PROCESS_TERMINATE,False,PID)
		if hProcess == NULL:
			return -1
		if ZwTerminateProcess(hProcess,True) == STATUS_SUCCESS:
			return STATUS_SUCCESS
					
	def karantin(self):
		file = self.pathBuffer.value
		q_operation = ("{} a -p{} {} \"{}\"".format(QArchiver,QPassword,QDirectory + FILE._hash(file),file))
		os.system(q_operation)
		dinpup = input("Delete file? [y or n] ");
		if dinpup == 'n':
			return None
		else:
			hProcess = OpenProcess(PROCESS_TERMINATE,False,self.global_id)
			if hProcess == NULL:
				return -1
			if ZwTerminateProcess(hProcess,True) == STATUS_SUCCESS:
				os.remove(self.pathBuffer.value)
				CloseHandle(hProcess)
				if os.path.exists(self.pathBuffer):
					return -1
				else:
					CloseHandle(hProcess)
					return 1
		
		
	def enum_threads(self):
		PID = self.global_id
		ThreadEntry = THREADENTRY32()
		ThreadEntry.dwSize = sizeof(THREADENTRY32)
		hThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,PID)
		if hThread == INVALID_HANDLE_VALUE:
			return INVALID_HANDLE_VALUE
		else:
			if (Thread32First(hThread, byref(ThreadEntry)) == 1):
				while(Thread32Next(hThread, byref(ThreadEntry)) == 1):
					if ThreadEntry.th32OwnerProcessID == PID:
						yield (ThreadEntry)
				CloseHandle(hThread)
			else:
				CloseHandle(hThread)
				
	def	threadsuspend(self,Thread_ID,resume = False):
		h_Thread = windll.kernel32.OpenThread(THREAD_SUSPEND_RESUME,False,Thread_ID);
		if h_Thread == None:
			return -1
		else:
			if resume == False:
				if windll.kernel32.SuspendThread(h_Thread) == -1:
					return -1
			else:
				if windll.kernel32.ResumeThread(h_Thread) == -1:
					return -1
			return None
			
			
	def threadterminate(self,Thread_ID):
		h_Thread = OpenThread(THREAD_TERMINATE,False,Thread_ID)
		if h_Thread == NULL:
			return -1
		else:
			if TerminateThread(h_Thread,True) == 0:
				return -1
			else:
				return None
				
	def PBI(self):
		PID = self.global_id
		process_basic_information = PROCESS_BASIC_INFORMATION()
		retsize = c_int()
		h_Process = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,False,PID)
		if h_Process == NULL:
			return -1
		else:
			NTSTATUS = NtQueryInformationProcess(h_Process,0, byref(process_basic_information), sizeof(process_basic_information), byref(retsize))
			if NTSTATUS != 0:
				CloseHandle(h_Process)
				return -1
			else:
				CloseHandle(h_Process)
				return process_basic_information
				
	def PEB(self,PROCESS_ENVIRONMENT_BLOCK_ADDRESS):
		PID = self.global_id
		__PEB = PROCESS_ENVIRONMENT_BLOCK()
		h_Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,False,PID)
		if h_Process == NULL:
			return -1
		else:
			NTSTATUS = NtReadVirtualMemory(h_Process,PROCESS_ENVIRONMENT_BLOCK_ADDRESS, byref(__PEB),sizeof(__PEB),0)
			if NTSTATUS != 0:
				CloseHandle(h_Process)
				return -1
			else:
				CloseHandle(h_Process)
				return __PEB
				
	def fileinfo(self):
		file = self.pathBuffer.value
		stat = os.stat(file)
		statinfo = (40 * "#" + "\nFile size:%s\nFile create time:%s\nFile modified time:%s\nAccess time:%s\n" % (stat.st_size,datetime.fromtimestamp(stat.st_ctime),
		datetime.fromtimestamp(stat.st_mtime),datetime.fromtimestamp(stat.st_atime)) + 40 * "#")
		print (statinfo)
		
		
	def signscan(self):
		file = self.pathBuffer.value
		db_file = open(signature_file,"r")
		binary_diff_file = open(file,"rb")
		db_data = db_file.read()
		bin_data = binary_diff_file.read()
		db_file.close();
		binary_diff_file.close()
		#db_data     bin_data
		for s in db_data.split("\n"):
			result = SignatureScan(bin_data,s)
			if not result == None:
				return result
			else:
				return -1
				
				
	def TIB(self,ThreadID):
		"""Bu metod ThreadID si verilmish Threading Thread Information Block neticelerini struct olaraq geri qaytarir"""
		hThread = OpenThread(THREAD_QUERY_INFORMATION, False, ThreadID)
		ThreadInformationBlock = TIB()
		if hThread == NULL:
			return -1
		else:
			if NtQueryInformationThread(hThread, 0, byref(ThreadInformationBlock), sizeof(ThreadInformationBlock),NULL) == 0:
				CloseHandle(hThread)
				return ThreadInformationBlock
			else:
				CloseHandle(hThread)
				return -1
				
				
	def TSA(self, ThreadID):
		hThread = OpenThread(THREAD_QUERY_INFORMATION,False,ThreadID)
		if hThread == NULL:
			return -1
		else:
			ThreadStartAddress = c_int()
			if NtQueryInformationThread(hThread, 9, byref(ThreadStartAddress), sizeof(ThreadStartAddress),NULL) == NULL:
				CloseHandle(hThread)
				return ThreadStartAddress.value
			else:
				CloseHandle(hThread)
				return -1
				
	def enum_handles(self):
		PID = self.global_id	#Process PID Number
		SYSTEM_HANDLE_INFORMATION_STRUCTURE = SYSTEM_HANDLE_INFORMATION_POINTER()
		structure_size = DWORD(sizeof(SYSTEM_HANDLE_INFORMATION_STRUCTURE))
		QueryResult = ZwQuerySystemInformation(SHI, byref(SYSTEM_HANDLE_INFORMATION_STRUCTURE), sizeof(SYSTEM_HANDLE_INFORMATION_STRUCTURE), byref(structure_size))
		if QueryResult != 0:
			structure_size = DWORD(structure_size.value * 4)
			resize(SYSTEM_HANDLE_INFORMATION_STRUCTURE,structure_size.value)
			QueryResult = ZwQuerySystemInformation(SHI, byref(SYSTEM_HANDLE_INFORMATION_STRUCTURE), sizeof(SYSTEM_HANDLE_INFORMATION_STRUCTURE), byref(structure_size))
		
		if QueryResult != 0:
			return -1
		
		castedObject = cast(SYSTEM_HANDLE_INFORMATION_STRUCTURE.Handles,POINTER(SYSTEM_HANDLE_INFORMATION_LOCAL * SYSTEM_HANDLE_INFORMATION_STRUCTURE.NumberOfHandles))
		for k in castedObject.contents:
			if k.ProcessID == PID:
				yield(k)
				
	def handle_name(self,HandleID):
		PID = self.global_id
		objnameStructure = ObjectNameInformationStr()
		objnameStructureSIZE = DWORD(sizeof(objnameStructure))
		DuplicateHandleObject = c_void_p()
		hProcess = OpenProcess(PROCESS_DUP_HANDLE, False, PID)
		if hProcess == NULL:
			return -1
		else:
			Duplicate = DuplicateHandle(hProcess,HandleID,GetCurrentProcess(), byref(DuplicateHandleObject), NULL, False, DUPLICATE_SAME_ACCESS)
			if Duplicate == 0:
				CloseHandle(hProcess)
				return -1
			else:
				ObjectQuery = NtQueryObject(DuplicateHandleObject.value, ObjectNameInformation, byref(objnameStructure), sizeof(objnameStructure), byref(objnameStructureSIZE))
				if ObjectQuery != 0:
					objnameStructureSIZE = DWORD(objnameStructureSIZE.value * 4)
					resize(objnameStructure,objnameStructureSIZE.value)
					ObjectQuery = NtQueryObject(DuplicateHandleObject.value, ObjectNameInformation, byref(objnameStructure), sizeof(objnameStructure), byref(objnameStructureSIZE))
				if ObjectQuery != 0:
					CloseHandle(hProcess)
					return -1
				else:
					retdata = c_wchar_p(objnameStructure.Name.Buffer)
					if retdata.value == None:
						CloseHandle(hProcess)
						return -1
					else:
						#DuplicateHandle(hProcess,HandleID,NULL,NULL,NULL,False,DUPLICATE_CLOSE_SOURCE)
						CloseHandle(hProcess)
						return [HandleID,retdata.value]
						
						
	def dumpmemory(self,DUMP_FORMAT = 0):
		PID = self.global_id
		EnumDumpFormat = {0 : MiniDumpNormal,1 : MiniDumpWithFullMemory};
		hFile = CreateFile(Dump_File % asctime().replace(" ","").replace(":","_") , FILE_GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)
		if hFile == INVALID_HANDLE_VALUE:
			return -1
		else:
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL, PID)
			if hProcess == NULL:
				CloseHandle(hFile)
				return -1
			else:
				DUMP = MiniDumpWriteDump(hProcess, PID, hFile,EnumDumpFormat[DUMP_FORMAT], NULL, NULL, NULL)
				if DUMP != 1:
					CloseHandle(hFile)
					color_init.set(12)
					print('Cannot create dump file')
					color_init.reset()
					return -1
				else:
					CloseHandle(hFile)
					color_init.set(10)
					print('Successfully dumped')
					color_init.reset()
					return 1
		
	def module_info(self,hMOD):	
		PID = self.global_id
		MI = MODULE_INFO()
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False , PID)
		if hProcess == NULL:
			return -1
			
		bRet = GetModuleInformation(hProcess,hMOD,byref(MI),sizeof(MI))
		if bRet == 0:
			CloseHandle(hProcess)
			return -1
		else:
			CloseHandle(hProcess)
			return MI
			
			
	def readmem(self,lpBaseAddress,HowMuchwithByte):
		PID = self.global_id
		Buffer = c_buffer(HowMuchwithByte)
		hProcess = OpenProcess(PROCESS_VM_READ,False,PID)
		if hProcess == NULL:
			return -1
		else:
			bRet = ReadProcessMemory(hProcess,lpBaseAddress, byref(Buffer), sizeof(Buffer),NULL)
			if bRet == 0:
				CloseHandle(hProcess)
				return 0
			else:
				CloseHandle(hProcess)
				return Buffer.raw
		
		
		
		
		
		
	
class FILE:
					
	def _hash(lpFilename):
		with open(lpFilename,"rb") as f:
			ext_digest = hashlib.md5(f.read()).hexdigest()
			return (ext_digest.upper())
			
	def fuzzy(Fuzzing_FILE_PATH):
		file = c_char_p(Fuzzing_FILE_PATH.encode())
		fuzzy_buffer = create_string_buffer(FUZZY_MAX_RESULT)
		fuzzy_dll = CDLL(SSDEEP)
		if fuzzy_dll.fuzzy_hash_filename(file, byref(fuzzy_buffer)) == 0:
			return (fuzzy_buffer.value)
		else:
			return -1
			
	def fuzzy_compare(char_fuzzy_result_1, char_fuzzy_result_2):
		
		computes = CDLL(SSDEEP).fuzzy_compare(char_fuzzy_result_1, char_fuzzy_result_2)
		return computes
		
		
	def shred(filepath):
		import random
		if not os.path.exists(filepath):
			return 1
		else:
			#File shred method
			
			f = open(filepath, 'rb+')
			file_length = len(f.read())
			f.seek(0) 	#Return file start point
			for _ in range(file_length):				##ROUND 1
				f.write(chr(random.randint(0,9)).encode())
				f.flush()
			f.seek(0)
			for _ in range(file_length):				##ROUND 2
				f.write(chr(random.randint(10,100)).encode())
				f.flush()
			f.seek(0)
			for _ in range(file_length):				##ROUND 3
				f.write(b'\x00')
				f.flush()
			f.close()
			""""
			Fayli silmek ucun lazim olan dustur
			>>> x = 6
			>>> j = "0"
			>>>
			>>> for _ in range(5):
			...     os.rename(j,x * "0")
			...     j = x * "0"
			...     x -=1
			"""
			os.remove(filepath)
			
	def pipes():
		_FILE_DATA = FILE_DATA()
		hPipeObject = FindFirstFile(Pipe_channel, byref(_FILE_DATA))
		print(15 * "*" + " PIPE Object " + 15 * "*")
		if hPipeObject == -1:
			return -1
		else:
			while 1:
				color_init.set(14)
				print(_FILE_DATA.cFileName)
				if FindNextFile(hPipeObject, byref(_FILE_DATA)) == 0:
					break
			color_init.reset()
			FindClose(hPipeObject)
			
			
	def enumdd():
		array_size = 1024
		DeviceBaseAddress = (c_void_p * array_size)()
		cbNeeded = c_int(0)
		DriverName = c_buffer(MAX_PATH)
		
		bRet = EnumDeviceDrivers(byref(DeviceBaseAddress), sizeof(DeviceBaseAddress), byref(cbNeeded))
		if bRet == 0:
			return -1
		else:
			for dd in range(0, cbNeeded.value):
				if DeviceBaseAddress[dd]:
					if (GetDeviceDriverFileNameA(DeviceBaseAddress[dd], byref(DriverName), MAX_PATH)) == 0:
						return -1
					else:
						Debug(hex(DeviceBaseAddress[dd]) + ' ' + DriverName.value.decode())
			return 1
						
						
						
	def enumservices():
		SERVICE_TYPE = {1 : 'SERVICE_KERNEL_DRIVER',2:'SERVICE_FILE_SYSTEM_DRIVER',16:'SERVICE_WIN32_OWN_PROCESS',
												32:'SERVICE_WIN32_SHARE_PROCESS',256:'SERVICE_INTERACTIVE_PROCESS'}
		start_count = 0
		SizeNeeded = DWORD(0)
		Returned = DWORD(0)
		Resume = DWORD(0)
		
		SC_HANDLE = OpenSCManager(NULL,NULL,SC_MANAGER_ENUMERATE_SERVICE)
		if SC_HANDLE == NULL:
			return -1
		bEnum = EnumServicesStatus(SC_HANDLE, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,NULL,NULL, byref(SizeNeeded),byref(Returned),byref(Resume))
		if bEnum != 0:
			return -2
		Buffer = create_unicode_buffer(SizeNeeded.value)
		bEnumSec = EnumServicesStatus(SC_HANDLE,SERVICE_TYPE_ALL, SERVICE_STATE_ALL,byref(Buffer), sizeof(Buffer), byref(SizeNeeded), byref(Returned),byref(Resume))
		
		Services = cast(Buffer,POINTER(ENUM * Returned.value))
		
		while (start_count < Returned.value):
			DisplayName = Services.contents[start_count].lpDisplayName.decode()
			ServiceName =  Services.contents[start_count].lpServiceName.decode()
			Type = Services.contents[start_count].ServiceStatus.dwServiceType
			Final = "Display:({})\t\tService:({})\tType:{}".format(DisplayName,ServiceName,Type)
			Debug(Final)
			start_count +=1
		CloseHandle(SC_HANDLE)
		return 1
		
						
						
class NET:
	
	def TCP():
		STATUS_ENUM = {1:'TCP_STATE_CLOSED',2:'TCP_STATE_LISTEN',3:'TCP_STATE_SYN_SENT',4:'TCP_STATE_SYN_RCVD',5:'TCP_STATE_SYN_RCVD',6:'TCP_STATE_ESTAB',7:'TCP_STATE_FIN_WAIT2',8:'TCP_STATE_CLOSE_WAIT',
						9:'TCP_STATE_CLOSING',10:'TCP_STATE_LAST_ACK',11:'TCP_STATE_TIME_WAIT',12:'TCP_STATE_DELETE_TCB'}
		new_size = 1
		return_dw_size = c_ulong(0)
		if GetTcpTable(NULL, byref(return_dw_size), 1):
			pass	
		new_size = return_dw_size.value
		
		class MIB_TCPTABLE(Structure):
			_fields_ = [('dwNumEntries',DWORD),
						('table',MIB_TCPROW * new_size),]
						
		TCPTableEntry = MIB_TCPTABLE()
		TCPTableEntry.dwNumEntries = 0
		if GetTcpTable(byref(TCPTableEntry), byref(return_dw_size), NULL) != NO_ERROR:
			return -1
		count = TCPTableEntry.dwNumEntries
		start_count = 0
		print("\n======================================================================================================\n")
		while start_count < count:
			table = TCPTableEntry.table[start_count]
			start_count += 1
			if DWORD(table.dwRemoteAddr).value == 0:
				continue
			else:
				local_host = table.dwLocalAddr
				local_port = table.dwLocalPort
				remote_host = table.dwRemoteAddr
				remote_port = table.dwRemotePort
				local_host = socket.inet_ntoa(struct.pack('L',local_host))
				remote_host = socket.inet_ntoa(struct.pack('L',remote_host))
				local_port = socket.ntohs(local_port)
				remote_port = socket.ntohs(remote_port)
				state = table.dwState
				print("\t{}\t{}\t\t\t{}\t{}\tState:{}".format(local_host,local_port,remote_host,remote_port,STATUS_ENUM[state]))
				
		print("\n======================================================================================================\n")
		
		
	def UDP():
		return_dw_size = DWORD(0)
		
		if GetUdpTable(NULL, byref(return_dw_size), NULL):
			pass
			
		new_struct_size = return_dw_size.value
		
		class MIB_UDPTABLE(Structure):
			_fields_ = [('dwNumEntries',DWORD),
						('table',MIB_UDPROW * new_struct_size),]
						
						
		UDPTableEntry = MIB_UDPTABLE()
		UDPTableEntry.dwNumEntries = 0
		if GetUdpTable(byref(UDPTableEntry), byref(return_dw_size), NULL) != NO_ERROR:
			return -1
			
		count = UDPTableEntry.dwNumEntries
		start_count = 0
		print("\n============================================================\n")
		while start_count < count:
			table = UDPTableEntry.table[start_count]
			start_count += 1
			if DWORD(table.dwLocalAddr).value == 0:
				continue
			else:
				local_host = socket.inet_ntoa(struct.pack('L',table.dwLocalAddr))
				local_port = socket.ntohs(table.dwLocalPort)
				print("\t{}\t{}".format(local_host,local_port))
		print("\n============================================================\n")
		
	
	def adapterinfo():
		AdapterList = (IP_ADAPTER_INFO * MAX_ADAPTER)()
		BufferLen = c_ulong(sizeof(AdapterList))
		iRet = GetAdaptersInfo( byref(AdapterList[0]),
								byref(BufferLen))
		
		if iRet == 0:
			for adapter in AdapterList:
				iplist = adapter.IpAddressList
				GatewayList = adapter.GatewayList
				DhcpList = adapter.DhcpServer
				while 1:
					IpAddress = iplist.IpAddress
					adaptername = adapter.AdapterName
					Gateway = GatewayList.IpAddress
					Dhcp = DhcpList.IpAddress
					Desc = adapter.Description
					if IpAddress:
						yield (IpAddress.decode(),adaptername.decode(),Gateway.decode(),Dhcp.decode(),Desc.decode())
					iplist = iplist.Next
					if not iplist:
						break
		
	def hosts():
		if not os.path.exists(hosts):
			return -1
		else:
				f = open(hosts,'r')
				lines = f.readlines()
				line_count = 0
				print('\n')
				for ln in lines:
					line_count += 1
					data = ln.strip('\r\n\t')
					print(line_count,'\t',data)
				f.close()
				
class REG:
	def dump(RegistryUniqID,EnumSubKeys = False):
		f= open(regdump_file,"r")
		a = f.read().split("\n")
		f.close()
		
		for x in a:
			j = x.split("->")
			if len(j) <= 2 and j[0] == RegistryUniqID:
				REnum(j[1])
			else:
				if len(j) > 2 and j[0] == RegistryUniqID:
					REnum(j[1],EnumSubKeys)