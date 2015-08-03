import socket,os
from time import sleep


def _read():
	log_dirmon = b''
	log_process = b''
	log_registry = b''
	if os.path.exists("log/dirmon.log"):
		f= open("log/dirmon.log","rb")
		log_dirmon = f.read()
		log_dirmon = log_dirmon.replace(b"\n",b"</br>")
		f.close()
	if os.path.exists("log/PN.log"):
		f = open("log/PN.log","rb")
		log_process = f.read()
		log_process= log_process.replace(b'\n',b'</br>')
		f.close()
	if os.path.exists("log/RN.log"):
		f = open("log/RN.log","rb")
		log_registry = f.read()
		log_registry = log_registry.replace(b'\n',b'</br>')
		f.close()
	return (b'<table border=2 CELLPADDING=3 width="100%" BGCOLOR=#FFFF00><tr><td>Directory Monitor(Smart)</tr></td></table>' + \
	log_dirmon + b'<table border=2 CELLPADDING=3 width="100%" BGCOLOR=#9999CC><tr><td>New Process Notification</tr></td></table>' + log_process + \
	b'<table border=2 CELLPADDING=3 width="100%" BGCOLOR=#33CCCC><tr><td>Registry Change Notification(Smart)</tr></td></table>' + log_registry)

	
def LogServer():
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.bind((conf[0],int(conf[1])))
	s.listen(1)
	
	while 1:
		conn,addr = s.accept()
		print(addr)
		send = 'HTTP/1.1 200 OK\r\nServer: Python 3.4.1 (Malware Müşahidə Sistemi)\r\nContent-Type: text/html; charset="UTF-8"\r\nConnection:close\r\n\r\n<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body bgcolor="FDFBFF"><font color="233BCA">Malware Müşahidə sistemi v1.0.0</br><a href="http://cert.gov.az">cert.gov.az</a></br><a href="magic_exit">Exit</a></br><hr><font color="000000">'.encode('utf-8') + _read() + b'\r\n'
		conn.sendall(send)
		if conn.recv(1024).find(b'magic_exit') != -1:
			break
		conn.close()
	s.close()
	
if __name__ == '__main__':
	conf_file = open("etc/webserv.conf",'r')
	conf = conf_file.read().split(':')
	conf_file.close()
	LogServer()