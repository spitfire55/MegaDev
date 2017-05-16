import subprocess, sys, urllib2, time, random

def run_command(cmd):
	return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

def output_data(before, num_elipses):
	sys.stdout.write(before)
	sys.stdout.flush()
	sys.stdout.write("." * num_elipses + " ")
	sys.stdout.flush()

def failed(out):
	print out
	print "Connectivity test FAILED"
	quit(1)

# services we want to verify are running
up_services = ["logstash", "elasticsearch", "kibana"]
for service in up_services:
	output_data("Testing run status of service %s" % service, 3)
	if "Active: active (running)" not in run_command("systemctl status %s.service" % service):
		failed("not running")
	else:
		print "running"

# make sure kibana web service is running on correct port
kibana_port = 5601
output_data("Trying to connect to Kibana", 3)
try:
	response = urllib2.urlopen("http://localhost:%d" % kibana_port)

	if "kbn-name: kibana" not in str(response.info()):
		# some other web service running on this port
		failed("kibana not running on port %d" % kibana_port)

	print "success"
except SystemExit:
	# something called quit() within the try block
	quit(1)
except:
	# nothing listening to this port
	failed("failed to connect to port %d" % kibana_port)
