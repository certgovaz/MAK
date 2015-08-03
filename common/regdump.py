from winreg import *
from ctypes import *

def REnum(RegPath,SubKeys=False):
	types = {1 : "REG_SZ",
			 4 : "REG_DWORD",
			 3 : "REG_BINARY",
			 0 : "REG_NONE",
			 8 : "REG_RESOURCE_LIST",
			 9 : "REG_FULL_RESOURCE_DESCRIPTOR",
			 7 : "REG_MULTI_SZ",
			 6 : "REG_LINK",
			 2 : "REG_EXPAND_SZ"};
	q = RegPath.split('\\')
	HKEY = None
	if q[0] == 'HKEY_LOCAL_MACHINE':
		HKEY = HKEY_LOCAL_MACHINE
	else:
		HKEY = HKEY_CURRENT_USER
	a = "\\".join(q[1:])
	print(a)
	kHandle = OpenKey(HKEY,a,0,KEY_ALL_ACCESS)
	if SubKeys == False:
		Info = QueryInfoKey(kHandle)
		print(75 * "#" + "\nSubkey {} : values {} : keyLastModifiedTime: {}\n".format(Info[0],Info[1],Info[2]) + 75 * "#")
		for i in range(Info[1]):
			dump = EnumValue(kHandle,i)
			print("%s:%s(%s)" % (dump[0],dump[1],types[dump[2]]))
	else:
		Info = QueryInfoKey(kHandle)
		print(75 * "#" + "\nSubkey {} : values {} : keyLastModifiedTime: {}\n".format(Info[0],Info[1],Info[2]) + 75 * "#")
		for i in range(Info[0]):
			dump_subkey = EnumKey(kHandle,i)
			print(dump_subkey)
	CloseKey(kHandle)