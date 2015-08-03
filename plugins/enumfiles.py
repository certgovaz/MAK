from ctypes import *
from ctypes.wintypes import *

#############################################################
ntdll = WinDLL("ntdll")
kernel32 = WinDLL("kernel32.dll")
NTSTATUS = c_long
STATUS_BUFFER_OVERFLOW = NTSTATUS(0x80000005).value
STATUS_NO_MORE_FILES = NTSTATUS(0x80000006).value
STATUS_INFO_LENGTH_MISMATCH = NTSTATUS(0xC0000004).value
ErrorCode = ntdll.RtlNtStatusToDosError
ErrorCode.restype = c_ulong
INVALID_HANDLE_VALUE = -1
#############################################################
class retStructure(Structure):
	_fields_ = [('FileName',c_wchar_p),
				('FileAttr',c_ulong),
				('FileCreateTime',LARGE_INTEGER),]


class IO_STATUS_BLOCK(Structure):
	class _STATUS(Union):
		_fields_ = [('Status',NTSTATUS),
					('Pointer',c_void_p),]
	_anonymous_ = '_Status',
	_fields_ = [('_Status',_STATUS),
				('Information',WPARAM),]


class FILE_DIRECTORY_INFORMATION(Structure):
    _fields_ = (('Next', ULONG),
                ('FileIndex', ULONG),
                ('CreationTime', LARGE_INTEGER),
                ('LastAccessTime', LARGE_INTEGER),
                ('LastWriteTime', LARGE_INTEGER),
                ('ChangeTime', LARGE_INTEGER),
                ('EndOfFile', LARGE_INTEGER),
                ('AllocationSize', LARGE_INTEGER),
                ('FileAttributes', ULONG),
                ('FileNameLength', ULONG),
                ('_FileName', WCHAR * 1))
				
PIO = POINTER(IO_STATUS_BLOCK)		
FDI = POINTER(FILE_DIRECTORY_INFORMATION)
###########################################################

def parse(buf,buflen):
	while buflen > 0:
		delta = FDI()
		offset = 0
		data = cast(buf,FDI)[0]
		attr = addressof(data) + FILE_DIRECTORY_INFORMATION._FileName.offset
		#print(c_wchar_p(attr))
		new_buffer = c_wchar * (data.FileNameLength // sizeof(c_wchar))
		new = new_buffer.from_address(attr).value
		print("FileAttr:{}\tCreateTime:{}\tFileName:{}".format(data.FileAttributes,data.CreationTime,new))
		ne = data.Next
		if ne <= 0:
			break
		buf = buf[ne:]
		buflen -= ne



def EnumFiles(LpDirectory):
	io = IO_STATUS_BLOCK()
	buffer = (c_char * 512)()
	
	
	hFile = kernel32.CreateFileW(LpDirectory,
									 0x80000000,      # GENERIC_READ
									 1,               # FILE_SHARE_READ
									 None,
									 3,               # OPEN_EXISTING
									 0x02000000,      # BACKUP_SEMANTICS
									 None)
									 
	if hFile == INVALID_HANDLE_VALUE:
		return -1
	else:
		while True:
			status = ntdll.NtQueryDirectoryFile(hFile,
												None,
												None,
												None,
												byref(io),
												byref(buffer),
												sizeof(buffer),
												1,
												False,
												None,
												False)
												
			if (io.Information == 0 and status >= 0 or 
					status == STATUS_BUFFER_OVERFLOW):
						buffer = (c_char * sizeof(buffer) * 2)()
			elif status == STATUS_NO_MORE_FILES:
				break
			elif status >= 0:
				parse(buffer,len(buffer))
			else:
				return ErrorCode(status)
		kernel32.CloseHandle(hFile)