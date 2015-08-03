from ctypes import *


SystsemProcessInformation = 6

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          c_ushort),
        ("MaximumLength",   c_ushort),
        ("Buffer",          c_wchar_p),
    ]


class FILETIME(Structure):
	_fields_ = [('dwLowDateTime',c_ulong),
				('dwHighDateTime',c_ulong),]

				
				
class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess",   c_void_p),
        ("UniqueThread",    c_void_p),]				
				
class SYSTEM_THREAD_INFO(Structure):
		_fields_ = [('KernelTime',c_ulonglong),
					('UserTime',c_ulonglong),
					('CreateTime',c_ulonglong),
					('WaitTime',c_ulong),
					('StartAddress',c_void_p),
					('ClientID',CLIENT_ID),
					('Priority',c_long),
					('BasePriority',c_long),
					('ContextSw',c_ulong),
					('tstate',c_ulong),
					('WaitReason',c_long),]
				
				
				
				
class PROCESS_INFORMATION_BLOCK(Structure):
	_fields_ = [('NextEntryOffset',c_ulong),
				('NumberOfThreads',c_ulong),
				('WorkingSetPrivateSize',c_ulonglong),
				('HardFaultCount',c_ulong),
				('NumberOfThreadsHighWaterMarks',c_ulong),
				('CycleTime',c_ulonglong),
				('CreateTime',FILETIME),
				('UserTime',FILETIME),
				('KernelTime',FILETIME),
				('image',UNICODE_STRING),
				('BasePriority',c_long),
				('uniqid',c_void_p),
				('parentid',c_void_p),
				('HandleCount',c_ulong),
				('SessionID',c_ulong),
				('UniqueProcessKey',c_ulonglong),
				('PeakVirtualSize',c_size_t),
				('VirtualSize',c_size_t),
				('PageFaultCount',c_ulong),
				('PeakWorkingSetSize',c_size_t),
				('WorkingSetSize',c_size_t),
				('QuotaPeakPagedPoolUsage',c_size_t),
				('QuotaPagedPoolUsage',c_size_t),
				('QuotaPeakNonPagedPoolUsage',c_size_t),
				('QuotaNonPagedPoolUsage',c_size_t),
				('PageFileUsage',c_size_t),
				('PeakPageFileUsage',c_size_t),
				('PrivatePageCount',c_size_t),
				('ReadOperationCount',c_ulonglong),
				('WriteOperationCount',c_ulonglong),
				('OtherOperationCount',c_ulonglong),
				('ReadTransferCount',c_ulonglong),
				('WriteTransferCount',c_ulonglong),
				('OtherTransferCount',c_ulonglong),
				('th',SYSTEM_THREAD_INFO),]
	
LPPIB = POINTER(PROCESS_INFORMATION_BLOCK)

	
def enum(ReadBuffer,bufflen):
	print(15 * "*" + " ProcessList(Native) " + 15 * "*")
	while bufflen > 0:
		si = cast(ReadBuffer,LPPIB)[0]
		yield si
		ne = si.NextEntryOffset
		if ne <=0:
			break
		ReadBuffer = ReadBuffer[ne:]
		bufflen -=ne

def init():
	returnBufferSize = c_ulong(0)
	windll.ntdll.NtQuerySystemInformation(5,None,None, byref(returnBufferSize))
	buffer = c_buffer(returnBufferSize.value)
	buffer_size = sizeof(buffer)
	windll.ntdll.NtQuerySystemInformation(5,byref(buffer),buffer_size,byref(returnBufferSize))
	return buffer