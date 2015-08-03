import urllib.request
import urllib.parse
from cc import vt_apikey,vt_domain_scan_url,vt_url_scan_url,vt_hash_scan_url

class vt:
	def __init__(self):
		self.apikey = vt_apikey
		
	def domain(self,DomainName):
		maldomain = DomainName
		params = urllib.parse.urlencode({'domain' : maldomain,'apikey' : self.apikey})
		response = urllib.request.urlopen('%s?%s' % (vt_domain_scan_url,params))
		jRet = response.read().decode()
		return (jRet)
		
	def url(self,url_To_scan):
		parser,temp_JSON =[],[]
		malurl = url_To_scan
		params = urllib.parse.urlencode({'url':malurl,'apikey':self.apikey})
		request = urllib.request.Request(vt_url_scan_url,params.encode())
		response = urllib.request.urlopen(request)
		jRet = response.read().decode()
		return (jRet)
		# for keys in json.JSONDecoder().decode(jRet):
			# parser.append(keys)
		
		# for temp_j in json.JSONDecoder().raw_decode(jRet):
			# temp_JSON.append(temp_j)
		
		# color_init.set(226)
		# for count in parser:
			# print(count,temp_JSON[0][count],sep="->")
		# color_init.reset()
		
	def hash(self,hash_sum):
		malhash = hash_sum
		params = urllib.parse.urlencode({'resource' : malhash,'apikey' : self.apikey})
		request = urllib.request.Request(vt_hash_scan_url,params.encode())
		response = urllib.request.urlopen(request)
		jRet = response.read().decode()
		return jRet