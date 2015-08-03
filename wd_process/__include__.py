from ctypes import *
from ctypes.wintypes import DWORD,WORD,HANDLE,BYTE,HMODULE
from const import *

##Structures		
class _FILETIME(Structure):
	_fields_ = [('dwLowDateTime',DWORD),('dwHighDateTime',DWORD),];
	
class _SYSTEMTIME(Structure):
	_fields_ = [('wYear',WORD,),
				('wMonth',WORD),
				('wDayOfWeek',WORD),
				('wDay',WORD),
				('wHour',WORD),
				('wMinute',WORD),
				('wSecond',WORD),
				('wMilliseconds',WORD),];
				
class PROCESSENTRY32(Structure):
	_fields_ = [('dwSize',DWORD),
				('cntUsage',DWORD),
				('th32ProcessID',DWORD),
				('th32DefaultHeapID',DWORD),
				('th32ModuleID',DWORD),
				('cntThreads',DWORD),
				('th32ParentProcessID',DWORD),
				('pcPriClassBase',c_int),
				('dwFlags',DWORD),
				('szExeFile',c_char * MAXPATH)];

				
class MODULEENTRY32(Structure):
	_fields_ =[('dwSize',DWORD),
				('th32ModuleID',DWORD),
				('th32ProcessID',DWORD),
				('GlblcntUsage',DWORD),
				('ProccntUsage',DWORD),
				('modBaseAddr',BYTE),
				('modBaseSize',DWORD),
				('hModule',HMODULE),
				('szModule',c_wchar * MAX_MODULE_NAME32),
				('szExePath',c_wchar * MAXPATH),];
				


class Proyekt_PDHooker_Initializer():
		##Global Error_code => -1
		##Global Sucess_code = 1
		def OpenProcess(self,dwDesiredAccess,dwProcessId):
			bInheritHandle = False
			dRet = windll.kernel32.OpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId)
			if (dRet == NULL):
				return -1
			else:
				return dRet
				
		def CloseHandle(self,lpHandleName):
			dRet = windll.kernel32.CloseHandle(lpHandleName)
			if (dRet > 0):
				return 1
			else:
				return -1
			
		def EnumProcess(self):
			#Bu funksiya Windows Emeliyyat sistemde(cari) fealiyyet gosteren prosesleri ve onlarin ID(pid)deyerlerini list obyektinde saxlayir ve return olaraq geri qaytarir.
			CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
			Process32First = windll.kernel32.Process32First
			Process32Next = windll.kernel32.Process32Next
			PE32 = PROCESSENTRY32(); PE32.dwSize = sizeof(PROCESSENTRY32);
			_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,False);
			if _handle == -1:
				return -1
			else:
				Process32First(_handle,byref(PE32));
				while(1 > 0):
					yield (PE32.szExeFile,PE32.th32ProcessID)
					if Process32Next(_handle,byref(PE32)) == 0:
						break;
				Proyekt_PDHooker_Initializer().CloseHandle(_handle);	#Close opening handle object
				return (PE32)	#RETURN GENERATOR OBJECT
				
		def EnumModules(self,dwProcessID):
			CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
			Module32First = windll.kernel32.Module32FirstW
			Module32Next = windll.kernel32.Module32NextW
			ME32 = MODULEENTRY32(); ME32.dwSize = sizeof(MODULEENTRY32); _handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,dwProcessID);
			if _handle == -1:
				return -1
			else:
				Module32First(_handle,byref(ME32));
				while (1 > 0):
					yield(ME32.szModule,ME32.szExePath,ME32.modBaseAddr)
					if Module32Next(_handle,byref(ME32)) == 0:
						break
				Proyekt_PDHooker_Initializer().CloseHandle(_handle);	#Close Open handle Object
				return (ME32)
				
				
				
		# def _GetProcTime(self,dwProcessID):
			# handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,dwProcessID);
			# lpCreationTime = _FILETIME()
			# lpExitTime = _FILETIME()
			# lpKernelTime = _FILETIME()
			# lpUserTime = _FILETIME()
			# windll.kernel32.GetProcessTimes(handle,byref(lpCreationTime),byref(lpExitTime),byref(lpKernelTime),byref(lpUserTime));
			# SysTime = _SYSTEMTIME();
			# windll.kernel32.FileTimeToSystemTime(byref(lpKernelTime),byref(SysTime));
			# #SysTime=>Process Creation Time in System time Mode
			# RET = (str(SysTime.wYear) + ":" + str(SysTime.wMonth) + ":" + str(SysTime.wHour) \
				# + ":" + str(SysTime.wMinute) + ":" + str(SysTime.wSecond));
			# return RET
			
				
class _CONSOLE_SCREEN_BUFFER_INFO(Structure):
	_fields_ = [('dwSize',c_int),('dwCursorPosition',c_int),
	('wAttributes',WORD),('srWindow',c_void_p),('dwMaximumWindowSize',c_int),]
				

def COLOR(wAttributes):
	STD_OUTPUT_HANDLE = int(-11)
	ColorStruct = _CONSOLE_SCREEN_BUFFER_INFO();
	HANDLE = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE);
	windll.kernel32.SetConsoleTextAttribute(HANDLE,wAttributes);

def ColorRest():
	STD_OUTPUT_HANDLE = int(-11)
	ColorStruct = _CONSOLE_SCREEN_BUFFER_INFO();
	HANDLE = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE);
	windll.kernel32.GetConsoleScreenBufferInfo(HANDLE,byref(ColorStruct))
	return int(ColorStruct.wAttributes);