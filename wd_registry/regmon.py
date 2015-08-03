from winreg import *
from time import sleep
from logging import *
from ctypes import *
from threading import Thread
import sys



breakObject = 0

class _Logger:
	def __init__(self):
		self.logger = getLogger("HookerLog")
		self.logger.setLevel("INFO")
		self.fh = FileHandler(filename = "../log/RN.log",encoding='utf-8');
		self.fh.setLevel("INFO")
		self.formatter = Formatter("%(asctime)s - %(message)s")
		self.fh.setFormatter(self.formatter)
		self.logger.addHandler(self.fh);
		
	def info(self,data):
		self.logger.info(data)
log = _Logger()

class RegNotify(Thread):
	def __init__(self,RegistryKey):
		Thread.__init__(self)
		self.key = RegistryKey
		self.ValueContainer = []
		self.DataContainer = []
		#HKEY_LOCAL_MACHINE
		HKey = RegistryKey.split('\\')[0]
		#Software\\Microsoft\\Windows\\Run
		SubKey = "\\".join(RegistryKey.split("\\")[1:])
		self.KeyHandle = OpenKey(HKEY_LOCAL_MACHINE,
								SubKey,
								0,
								KEY_READ)
		ValuesInKey = QueryInfoKey(self.KeyHandle)[1]
		for read_count in range(ValuesInKey):
			vObject = EnumValue(self.KeyHandle,read_count)
			self.ValueContainer.append(vObject[0])
			self.DataContainer.append(vObject[1])

	def run(self):
		global breakObject
		print("Start monitoring fallowing key:%s" % (self.key))
		while 1:
				if breakObject == 1:
					CloseKey(self.KeyHandle)
					break
				sleep(0.2)
				NewValuesInKey = QueryInfoKey(self.KeyHandle)[1]
				if NewValuesInKey > len(self.ValueContainer):
					for new_read_count in range(NewValuesInKey):
						NewVObject = EnumValue(self.KeyHandle,new_read_count)
						if NewVObject[0] not in self.ValueContainer:
							self.ValueContainer.append(NewVObject[0])
							self.DataContainer.append(NewVObject[1])
							#print("[+] " + NewVObject[0],NewVObject[1])
							log.info("[+] (%s)\t\t[%s(%s)]" % (self.key,NewVObject[0],NewVObject[1]))
							# print("Added (%s -> %s)" % (NewVObject[0],NewVObject[1]))
				if NewValuesInKey < len(self.ValueContainer):
					NewDeletedObject = []
					for row_count in range(NewValuesInKey):
						data = EnumValue(self.KeyHandle,row_count)
						NewDeletedObject.append(data[0])
					for x in self.ValueContainer:
						if x not in NewDeletedObject:
							value_data = self.DataContainer[self.ValueContainer.index(x)]
							log.info("[-] (%s)\t\t[%s(%s)]" % (self.key,x,value_data))
							# print("Deleted (%s -> %s)" % (x,value_data))
							self.DataContainer.remove(value_data)
							self.ValueContainer.remove(x)


f = open("Keys.txt","r")
lines = f.readlines()
f.close()

for j in lines:
	RegNotify(j.strip('\n')).start()	#starting monitoring threads
							


Event = windll.kernel32.CreateEventW(None,True,False,'moci555')
windll.kernel32.WaitForSingleObject(Event,-1)
sleep(1)
windll.kernel32.CloseHandle(Event)
breakObject = 1