from ctypes import *


INVALID_HANDLE_VALUE = -1
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004
MAX_PATH = 260
PROCESS_TERMINATE  = 0x0001
STATUS_SUCCESS = 0x00000000
MAX_MODULE_NAME32 = 255
NULL = 0
THREAD_QUERY_INFORMATION = 0x0040
EVENT_ALL_ACCESS = 0x1F0003
THREAD_SUSPEND_RESUME = 0x0002
THREAD_TERMINATE = 0x0001
NULL = 0
DUPLICATE_SAME_ACCESS = 0x00000002
DUPLICATE_CLOSE_SOURCE = 0x00000001

##DLL PATH
DLL_dialog = "lib/dialog.dll"
DLL_regmon = "lib/regmon.dll"
DLL_monitor = "lib/monitor.dll"
SSDEEP = "lib/fuzzy.dll"

##DEP Status
DEP_DISABLED = 0
PROCESS_DEP_ENABLE = 0x00000001
PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION = 0x00000002

#Ctypes types

BYTE		= c_ubyte
LPVOID      = c_void_p
BOOLEAN     = BYTE
UCHAR       = BYTE
PVOID		= LPVOID
LONGLONG    = c_int64
HANDLE      = LPVOID
DWORD		= c_int
WORD		= c_uint16
ULONGLONG   = c_uint64
PPS_POST_PROCESS_INIT_ROUTINE = PVOID
USHORT      = c_ushort
WCHAR       = c_wchar
ULONG		= c_ulong
NTSTATUS    = c_long
BOOL = c_int

#Karantin config

QDirectory = "etc\\.qua\\";
QPassword = "infected";
QArchiver = "etc\\7z.exe"

signature_file = "etc/db_signature.txt"


#NtQuerysystem

SHI = 0x0010

#Object

ObjectNameInformation = 1

#Fuzzy defines
SPAMSUM_LENGTH = 64
FUZZY_MAX_RESULT   = (2 * SPAMSUM_LENGTH + 20)


#Pipe enum
Pipe_channel = c_wchar_p('//./pipe/*')


#Windows ApI FILE
FILE_GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x80

#Memory Dump
MiniDumpNormal = 0x00000000
MiniDumpWithFullMemory = 0x00000002
Dump_File = "log/%s.dmp"


#TCP UDP Enum
NO_ERROR = 0

#hosts

hosts = 'c:\\Windows\\system32\\drivers\\etc\\hosts'



#Services

SERVICE_DRIVER = 0x0000000B
SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
SERVICE_KERNEL_DRIVER = 0x0000001
SERVICE_WIN32 = 0x00000030
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020
SERVICE_TYPE_ALL = SERVICE_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_KERNEL_DRIVER | SERVICE_WIN32 | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS

SERVICE_STATE_ALL = 0x00000003
SC_MANAGER_ENUMERATE_SERVICE  = 0x0004


#Registry
regdump_file = "etc/regdump.txt"

#AdaptersInfo
MAX_ADAPTER_NAME_LENGTH = 260
MAX_DESCRIPTION_LENGTH = 130
MAX_ADAPTER = 10


#AutoScriptConf
curdir = 'C:\MMS'


#Virustotal
vt_apikey = 'your_virustotal_apikey'
vt_domain_scan_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
vt_url_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
vt_hash_scan_url = 'https://www.virustotal.com/vtapi/v2/file/rescan'