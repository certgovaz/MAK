import os
import sys
from ctypes import *
from hashlib import md5
from cc import QDirectory,QPassword,QArchiver,curdir
from winstruct import PROCESSENTRY32
from common.colored_text import *
from winreg import *



def RegDeleteKey(RegKey):
	HKey = RegKey.split('\\')[0]
	KEY = None
	if HKey == 'HKEY_LOCAL_MACHINE':
		KEY = HKEY_LOCAL_MACHINE
	elif HKey == 'HKEY_CURRENT_USER':
		KEY = HKEY_CURRENT_USER
	elif HKey == 'HKEY_CLASSES_ROOT':
		KEY = HKEY_CLASSES_ROOT
	elif HKey == 'HKEY_CURRENT_CONFIG':
		KEY = HKEY_CURRENT_CONFIG
	else:
		KEY = HKEY_USERS
	SubKey = "\\".join(RegKey.split("\\")[1:])
	try:
		KeyHandle = OpenKey(KEY,SubKey,0,KEY_ALL_ACCESS)
		DeleteKey(KeyHandle,'')
		color_init.set(10)
		print('Registry Key %s is deleted' % RegKey)
		color_init.reset()
	except FileNotFoundError:
		color_init.set(12)
		print('Key not found %s' % RegKey)
		color_init.reset()
	
def RegDeleteValue(_key,Value):
	HKey = _key.split('\\')[0]
	KEY = None
	if HKey == 'HKEY_LOCAL_MACHINE':
		KEY = HKEY_LOCAL_MACHINE
	elif HKey == 'HKEY_CURRENT_USER':
		KEY = HKEY_CURRENT_USER
	elif HKey == 'HKEY_CLASSES_ROOT':
		KEY = HKEY_CLASSES_ROOT
	elif HKey == 'HKEY_CURRENT_CONFIG':
		KEY = HKEY_CURRENT_CONFIG
	else:
		KEY = HKEY_USERS
	SubKey = "\\".join(_key.split("\\")[1:])
	try:
		KeyHandle = OpenKey(KEY,SubKey,0,KEY_ALL_ACCESS)
		DeleteValue(KeyHandle,Value)
		color_init.set(10)
		print('Registry value %s is deleted' % Value)
		color_init.reset()
	except FileNotFoundError:
		color_init.set(12)
		print('Key not found %s' % _key)
		color_init.reset()

def RebootDelete(LpFilePath):
	if not os.path.exists(LpFilePath):
		color_init.set(12)
		print("%s file not found".format(LpFilePath))
		color_init.reset()
	else:
		HKEY = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\CurrentControlSet\Control\Session Manager",0,winreg.KEY_SET_VALUE)
		winreg.SetValueEx(HKEY,'PendingFileRenameOperations',0,winreg.REG_MULTI_SZ,[('\\??\\' + LpFilePath),('')])
		winreg.CloseKey(HKEY)



def qua(lpFileName):
	file = lpFileName
	if os.path.exists(lpFileName):
		f = open(lpFileName,"rb")
		data = f.read()
		f.close()
		digest = md5(data).hexdigest()
		q_operation = ("{} a -p{} {} \"{}\"".format(QArchiver,QPassword,QDirectory + digest,file))
		color_init.set(10)
		print(q_operation)
		os.system(q_operation)
		color_init.reset()
	else:
		color_init.set(12)
		print("%s not found." % lpFileName)
		color_init.reset()
		
		
def delete_file(lpFilepath):
	if os.path.exists(lpFilepath):
		os.remove(lpFilepath)
		color_init.set(13)
		print("%s deleted successfully" % lpFilepath)
		color_init.reset()
	else:
		color_init.set(12)
		print("%s file not found" % lpFilepath)
		color_init.reset()

def debug(PID):
	BOOL = windll.kernel32.DebugActiveProcess(int(PID))
	if BOOL != 0:
		color_init.set(13)
		print("Process ID %s debugged" % PID)
		color_init.reset()
	else:
		color_init.set(13)
		print("Cannot access ID %s" % PID)
		color.reset()
		
def process_kill_pid(dwPID):
	HANDLE = windll.kernel32.OpenProcess(0x0001,False,int(dwPID))
	if HANDLE == 0:
		color_init.set(12)
		print("Cannot handle process %s" % dwPID)
		color_init.reset()
	else:
		if windll.kernel32.TerminateProcess(HANDLE, 1) != 0:
			windll.kernel32.CloseHandle(HANDLE)
			color_init.set(13)
			print("Process terminated %s" % dwPID)
			color_init.reset()
		else:
			windll.kernel32.CloseHandle(HANDLE)
			color_init.set(12)
			print("Cannot terminate process %s" % dwPID)
			color_init.reset()
	
def process_kill_name(strProcess_Name):
	Snapshot = windll.kernel32.CreateToolhelp32Snapshot(0x00000002,0);
	ProcessEntry = PROCESSENTRY32()
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32)
	if Snapshot == -1:
		color_init.set(12)
		print("Cannot create snapshot")
		color_init.reset()
	else:
		if windll.kernel32.Process32First(Snapshot, byref(ProcessEntry)) == 1:
			while (windll.kernel32.Process32Next(Snapshot, byref(ProcessEntry)) == 1):
					if ProcessEntry.szExeFile.decode().lower() == strProcess_Name.lower():
						color_init.set(10)
						print("Process %s is detected" % strProcess_Name)
						color_init.reset()
						process_kill_pid(int(ProcessEntry.th32ProcessID))
	windll.kernel32.CloseHandle(Snapshot)
					

def main(ScriptFile):
	f = open(sys.argv[1],"r")
	a = f.read()
	f.close()
	
	##Bu bolmede cari komandalar parse edilerek lazimi funksiyalara gonderilir.
	for scriptParser in a.split("\n"):
		if scriptParser.startswith("delete_file") and scriptParser.endswith(";"):
			argd = scriptParser.split("\"")[1]
			delete_file(argd)
		elif scriptParser.startswith("process_kill_pid") and scriptParser.endswith(";"):
			argpd = scriptParser.split("\"")[1]
			process_kill_pid(argpd)
		elif scriptParser.startswith("process_kill_name") and scriptParser.endswith(";"):
			KPN = scriptParser.split("\"")[1]
			process_kill_name(KPN)
		elif scriptParser.startswith("qua") and scriptParser.endswith(";"):
			QUA = scriptParser.split("\"")[1]
			qua(QUA)
		elif scriptParser.startswith("debug") and scriptParser.endswith(";"):
			DEBUG_ID = scriptParser.split("\"")[1]
			debug(DEBUG_ID)
		elif scriptParser.startswith("reboot_delete") and scriptParser.endswith(";"):
			PendingFILE = scriptParser.split("\"")[1]
			RebootDelete(PendingFILE)
		elif scriptParser.startswith("reg_delete_key") and scriptParser.endswith(";"):
			KEYs = scriptParser.split("\"")[1]
			RegDeleteKey(KEYs)
		elif scriptParser.startswith("reg_delete_value") and scriptParser.endswith(";"):
			key = scriptParser.split("\"")[1]
			Value = scriptParser.split("\"")[3]
			RegDeleteValue(key,Value)
		else:
			pass

os.chdir(curdir)

color_init = color()
main(sys.argv[1])
os.system("pause")