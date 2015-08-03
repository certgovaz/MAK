from ctypes import *
import os

class COORD(Structure):
		_fields_ = [('x',c_short),('y',c_short),]

class SMALL(Structure):
		_fields_ = [('Left',c_short),
					('Reserved2',c_short),
					('Reserved3',c_short),
					('Reserved4',c_short),]
				
				
class SCREEN_BUFFER_INFO(Structure):
		_fields_ = [('size',COORD),
					('CursorPos',COORD),
					('wAttr',c_ushort),
					('srWindows',SMALL),
					('DwMaxWinSize',COORD),]

class color:
	def __init__(self):
		Handle = windll.kernel32.GetStdHandle(-11)
		self.BUFFER = SCREEN_BUFFER_INFO()
		windll.kernel32.GetConsoleScreenBufferInfo(Handle, byref(self.BUFFER))

	def set(self,code):
		self.cHandle = windll.kernel32.GetStdHandle(-11)
		windll.kernel32.SetConsoleTextAttribute(self.cHandle,code)

	def reset(self):
		windll.kernel32.SetConsoleTextAttribute(self.cHandle,self.BUFFER.wAttr)
		
color_init = color()