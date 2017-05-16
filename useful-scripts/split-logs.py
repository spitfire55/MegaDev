import csv
import time, datetime
import os, sys
import shutil

def parseLogs(name, write_dir):
	f = open(name, 'rt')
	time_interval = 60 * 10 # interval to split logs by
	last_time = 0 # last log time

	if os.path.exists(write_dir):
		shutil.rmtree(write_dir) # remove write_dir
	os.makedirs(write_dir) # create empty write_dir

	curr_file = False
	curr_writer = False
	count = 0
	total_count = 0

	reader = csv.DictReader(f)
	for row in reader:
		try:
			timestamp = time.mktime(datetime.datetime.strptime(row['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())
			if timestamp - last_time > time_interval:
				if curr_file != False:
					print "Finished parsing time interval. Number of rows: " + str(count)
					total_count += count
					count = 0
					curr_file.close()
					last_time = timestamp
				print "Starting to parse " + str(int(timestamp)) + "-" + str(int(timestamp + time_interval))
				curr_file = open(write_dir + "/logs-" + str(int(timestamp)) + "-" + str(int(timestamp + time_interval)) + ".csv", "w")
				curr_writer = csv.DictWriter(curr_file, fieldnames=reader.fieldnames, quoting=csv.QUOTE_ALL)
				headers = dict((n,n) for n in reader.fieldnames)
				curr_writer.writerow(headers)

			curr_writer.writerow(row)
			count += 1

			if count % 100000 == 0:
				print "Current number of rows: " + str(count)
		except:
			print "Error parsing row:", row
			pass

	curr_file.close()
	f.close()

	print "\nFinished parsing all.  Total number of rows: " + str(total_count + count)

def splitLogs(parsedPath, startTime, endTime, savePath):
	valid_logs = []
	for filename in os.listdir(parsedPath):
		start, end = filename.split(".")[0].split("-")[1:]
		if max(int(start), int(startTime)) <= min(int(end), int(endTime)): # see if time ranges intersect
			valid_logs.append((filename, int(start), int(end)))
	sorted_logs = sorted(valid_logs, key=lambda x: x[1])

	f = open(savePath, "w")
	curr_writer = False
	count = 0

	for s in sorted_logs:
		curr_file = open(parsedPath + "/" + s[0], "r")
		curr_reader = csv.DictReader(curr_file)

		for row in curr_reader:
			try:
				if not curr_writer:
					curr_writer = csv.DictWriter(f, fieldnames=curr_reader.fieldnames, quoting=csv.QUOTE_ALL)
					headers = dict((n,n) for n in curr_reader.fieldnames)
					curr_writer.writerow(headers)

				timestamp = time.mktime(datetime.datetime.strptime(row['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())
				if timestamp >= int(startTime) and timestamp <= int(endTime):
					curr_writer.writerow(row)
					count += 1

					if count % 10000 == 0:
						print "Current number of rows: " + str(count)
			except:
				print "Error parsing row:", row
				pass

		curr_file.close()

	f.close()
		

def usage():
	this = os.path.basename(__file__)
	print "Usage: python " + this + " <options>\n"
	print "Options"
	print "\t-parse <log-file> <parsed-path>"
	print "\t\tParses log-file and saves resulting partitions in parsed-path directory"
	print "\t-split <parsed-path> <start-time> <end-time> <save-path>"
	print "\t\tFinds all events in the parsed-path directory with a timestamp between"
	print "\t\tstart-time and end-time and saves the resulting file in save-path"
	quit()

if __name__ == "__main__":
	if len(sys.argv) == 1: # just the file name
		usage()
	elif sys.argv[1] == "-parse" and len(sys.argv) == 4:
		parseLogs(*sys.argv[2:])
	elif sys.argv[1] == "-split" and len(sys.argv) == 6:
		splitLogs(*sys.argv[2:])
	else:
		usage()