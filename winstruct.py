from ctypes import *
from ctypes.wintypes import DWORD,WORD,BYTE,HMODULE,HINSTANCE,HWND,LPCSTR,LPSTR,LPARAM
from cc import *

class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink",   c_void_p),
        ("Blink",   c_void_p),
]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",          USHORT),
        ("MaximumLength",   USHORT),
        ("Buffer",          c_void_p),
    ]
	
class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess",   c_void_p),
        ("UniqueThread",    c_void_p),
]
	



class PROCESSOR_NUMBER(Structure):
    _fields_ = [
        ("Group",       WORD),
        ("Number",      BYTE),
        ("Reserved",    BYTE),
]

class MODULEENTRY32(Structure):
	_fields_ =[('dwSize',DWORD),
				('th32ModuleID',DWORD),
				('th32ProcessID',DWORD),
				('GlblcntUsage',DWORD),
				('ProccntUsage',DWORD),
				('modBaseAddr',BYTE),
				('modBaseSize',DWORD),
				('hModule',HMODULE),
				('szModule',c_char * (MAX_MODULE_NAME32 + 1)),
				('szExePath',c_char * MAX_PATH),]
				
				
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
				('szExeFile',c_char * MAX_PATH),]
				
class THREADENTRY32(Structure):
	_fields_ = [('dwSize',DWORD),
				('cntUsage',DWORD),
				('th32ThreadID',DWORD),
				('th32OwnerProcessID',DWORD),
				('tpBasePri',c_long),
				('tpDeltaPri',DWORD),
				('dwFlags',DWORD),]
				
class GUID(Structure):
    _fields_ = [
        ("Data1",   DWORD),
        ("Data2",   WORD),
        ("Data3",   WORD),
        ("Data4",   BYTE * 8),
]
				
class FILETIME(Structure):
	_fields_ = [('dwLowDateTime',DWORD),
				('dwHighDateTime',DWORD),]
				
class SYSTEMTIME(Structure):
	_fields_ = [('wYear',WORD),
				('wMonth',WORD),
				('wDayOfWeek',WORD),
				('wDay',WORD),
				('wHour',WORD),
				('wMinute',WORD),
				('wSecond',WORD),
				('wMilliseconds',WORD),]
				
				
class PROCESS_BASIC_INFORMATION(Structure):
	_fields_ = [('Reserved1',c_long),
				('PebBaseAddress',c_void_p),
				('AffinityMask',c_size_t),
				('BasePriority',c_int),
				('UniqueProcessId',c_size_t),
				('InheritedFromUniqueProcessId',c_size_t),];
				
				
				
class PROCESS_BASIC_INFORMATION(Structure):
	_fields_ = [('Reserved1',c_long),
				('PebBaseAddress',c_void_p),	#Convert to hex
				('AffinityMask',c_size_t),
				('BasePriority',c_int),
				('UniqueProcessId',c_size_t),
				('InheritedFromUniqueProcessId',c_size_t),];	#Parent Process_ID
				
				
				
class PROCESS_ENVIRONMENT_BLOCK(Structure):
    _fields_ = [
        ("InheritedAddressSpace",               BOOLEAN),
        ("ReadImageFileExecOptions",            UCHAR),
        ("BeingDebugged",                       BOOLEAN),
        ("BitField",                            UCHAR),
        ("Mutant",                              HANDLE),
        ("ImageBaseAddress",                    c_void_p),
        ("Ldr",                                 c_void_p),
        ("ProcessParameters",                   c_void_p),
        ("SubSystemData",                       c_void_p),
        ("ProcessHeap",                         c_void_p),
        ("FastPebLock",                         c_void_p),
        ("AtlThunkSListPtr",                    c_void_p),
        ("IFEOKey",                             c_void_p),
        ("CrossProcessFlags",                   DWORD),
        ("KernelCallbackTable",                 c_void_p),
        ("SystemReserved",                      DWORD),
        ("AtlThunkSListPtr32",                  c_void_p),
        ("ApiSetMap",                           c_void_p),
        ("TlsExpansionCounter",                 DWORD),
        ("TlsBitmap",                           c_void_p),
        ("TlsBitmapBits",                       DWORD * 2),
        ("ReadOnlySharedMemoryBase",            c_void_p),
        ("HotpatchInformation",                 c_void_p),
        ("ReadOnlyStaticServerData",            c_void_p),
        ("AnsiCodePageData",                    c_void_p),
        ("OemCodePageData",                     c_void_p),
        ("UnicodeCaseTableData",                c_void_p),
        ("NumberOfProcessors",                  DWORD),
        ("NtGlobalFlag",                        DWORD),
        ("CriticalSectionTimeout",              LONGLONG),
        ("HeapSegmentReserve",                  DWORD),
        ("HeapSegmentCommit",                   DWORD),
        ("HeapDeCommitTotalFreeThreshold",      DWORD),
        ("HeapDeCommitFreeBlockThreshold",      DWORD),
        ("NumberOfHeaps",                       DWORD),
        ("MaximumNumberOfHeaps",                DWORD),
        ("ProcessHeaps",                        c_void_p),
        ("GdiSharedHandleTable",                c_void_p),
        ("ProcessStarterHelper",                c_void_p),
        ("GdiDCAttributeList",                  DWORD),
        ("LoaderLock",                          c_void_p),
        ("OSMajorVersion",                      DWORD),
        ("OSMinorVersion",                      DWORD),
        ("OSBuildNumber",                       WORD),
        ("OSCSDVersion",                        WORD),
        ("OSPlatformId",                        DWORD),
        ("ImageSubsystem",                      DWORD),
        ("ImageSubsystemMajorVersion",          DWORD),
        ("ImageSubsystemMinorVersion",          DWORD),
        ("ActiveProcessAffinityMask",           DWORD),
        ("GdiHandleBuffer",                     DWORD * 34),
        ("PostProcessInitRoutine",              PPS_POST_PROCESS_INIT_ROUTINE),
        ("TlsExpansionBitmap",                  c_void_p),
        ("TlsExpansionBitmapBits",              DWORD * 32),
        ("SessionId",                           DWORD),
        ("AppCompatFlags",                      ULONGLONG),
        ("AppCompatFlagsUser",                  ULONGLONG),
        ("pShimData",                           c_void_p),
        ("AppCompatInfo",                       c_void_p),
        ("CSDVersion",                          UNICODE_STRING),
        ("ActivationContextData",               c_void_p),
        ("ProcessAssemblyStorageMap",           c_void_p),
        ("SystemDefaultActivationContextData",  c_void_p),
        ("SystemAssemblyStorageMap",            c_void_p),
        ("MinimumStackCommit",                  DWORD),
        ("FlsCallback",                         c_void_p),
        ("FlsListHead",                         LIST_ENTRY),
        ("FlsBitmap",                           c_void_p),
        ("FlsBitmapBits",                       DWORD * 4),
        ("FlsHighIndex",                        DWORD),
        ("WerRegistrationData",                 c_void_p),
        ("WerShipAssertPtr",                    c_void_p),
        ("pContextData",                        c_void_p),
        ("pImageHeaderHash",                    c_void_p),
        ("TracingFlags",                        DWORD),]
		
		
class TIB(Structure):
	_fields_ = [('ExitStatus',NTSTATUS),
				('TebBaseAddress',c_void_p),
				('ClientId',CLIENT_ID),
				('AffinityMask',c_size_t),
				('Priority',c_int32),
				('BasePriority',c_int32),]
				
				
				
class SYSTEM_HANDLE_INFORMATION_LOCAL(Structure):
	_fields_ = [('ProcessID',c_ushort),
				('CreateBackTrackIndex',c_ushort),
				('ObjectTypeNumber',c_ubyte),
				('Flags',c_ubyte),
				('Handle',c_ushort),
				('ObjectAddr',c_void_p),
				('AccessMask',c_int),]
				
class SYSTEM_HANDLE_INFORMATION_POINTER(Structure):
  _fields_ = [
    ("NumberOfHandles", c_ulong),
    ("Handles", SYSTEM_HANDLE_INFORMATION_LOCAL * 1),]
	
	
class ObjectNameInformationStr(Structure):
	_fields_ = [('Name',UNICODE_STRING),]
	
	
	
class FILE_DATA(Structure):
	_fields_ = [('dwFileAttribute',c_ulong),
				('ftCreateTime',FILETIME),
				('ftLastAccessTime',FILETIME),
				('ftlastWrite',FILETIME),
				('FileSizeH',c_ulong),
				('FileSizeL',c_ulong),
				('dwReserved',c_ulong),
				('dwReserved1',c_ulong),
				('cFileName',c_wchar * 256),
				('cAlternateFileName',c_wchar * 14),]
				
				
				
class MODULE_INFO(Structure):
	_fields_ = [('lpBaseAddress',c_void_p),
	('SizeOfImage',c_ulong),
	('EntryPoint',c_void_p),]
	
	
	
class MIB_TCPROW(Structure):
	_fields_ = [('dwState',c_ulong),
				('dwLocalAddr',c_ulong),
				('dwLocalPort',c_ulong),
				('dwRemoteAddr',c_ulong),
				('dwRemotePort',c_ulong)]
				
				
class MIB_UDPROW(Structure):
	_fields_ = [('dwLocalAddr',c_ulong),
				('dwLocalPort',c_ulong),]
				
				
				
class SERVICE_STATUS(Structure):
	_fields_ = [('dwServiceType',DWORD),
				('dwdwCurrentState',DWORD),
				('dwControlsAccepted',DWORD),
				('dwWin32ExitCode',DWORD),
				('dwServiceSpecificExitCode',DWORD),
				('dwCheckPoint',DWORD),
				('Hint',DWORD),]


class ENUM(Structure):
	_fields_ = [('lpServiceName',c_char_p),
				('lpDisplayName',c_char_p),
				('ServiceStatus',SERVICE_STATUS),]
				
				
				
class IP_ADDRESS_STRING(Structure):
		pass
LP_IP_ADDRESS_STRING = POINTER(IP_ADDRESS_STRING)	
IP_ADDRESS_STRING._fields_ = [('Next',LP_IP_ADDRESS_STRING),
			('IpAddress',c_char * 16),
			('IpMask',c_char * 16),
			('Context',c_ulong),]
			
			
class IP_ADAPTER_INFO(Structure):
		pass
LP_IP_ADAPTER_INFO = POINTER(IP_ADAPTER_INFO)
IP_ADAPTER_INFO._fields_ = [('Next',LP_IP_ADAPTER_INFO),
							('ComboIndex',c_ulong),
							('AdapterName',c_char * MAX_ADAPTER_NAME_LENGTH),
							('Description',c_char * MAX_DESCRIPTION_LENGTH),
							('AddressLength',c_uint),
							('Address',c_byte * 8),
							('Index',c_ulong),
							('Type',c_uint),
							('DhcpEnabled',c_uint),
							('CurrentIpAddress',POINTER(IP_ADDRESS_STRING)),
							('IpAddressList',IP_ADDRESS_STRING),
							('GatewayList',IP_ADDRESS_STRING),
							('DhcpServer',IP_ADDRESS_STRING),
							('HaveWins',c_long),
							('PrimaryWinsServer',IP_ADDRESS_STRING),
							('SecondaryWinsServer',IP_ADDRESS_STRING),
							('LeaseObtained',c_long),
							('LeaseExpires',c_long)]