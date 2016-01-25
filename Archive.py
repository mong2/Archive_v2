import sys
import os
import re
import json
import time
import ConfigParser
import dateutil.parser
from api import Api
from oauth import APIToken

start_time = time.time()

class CmdLine:
    def __init__(self):
        self.authFilename = "archive.auth"
        self.starting = None
        self.ending = None
        self.reportModule = None
        self.allowedReportTypes = ["sva", "csm", "fim", "sam"]

    def processArgs(self, argv):
        allOK = True
        self.progdir = os.path.dirname(sys.argv[0])
        for arg in argv[1:]:
            if (arg.startswith("--auth=")):
                self.authFilename = arg.split("=")[1]
            elif (arg.startswith("--starting")):
                self.starting = arg.split("=")[1]
            elif (arg.startswith("--ending")):
                self.ending = arg.split("=")[1]
            elif (arg.startswith("--base=")):
                self.base = arg.split("=")[1]
            elif (arg.startswith("--reportType")):
                self.reportModule = arg.split("=")[1]
            elif (arg == "-h") or (arg == "-?"):
                allOK = False
            else:
                print >>sys.stderr, "Unknown argument: %s" % arg
                allOK = False
        return allOK

    def usage(self, progname):
        print >> sys.stderr, "Usage: %s [flag] [...]" % os.path.basename(progname)
        print >> sys.stderr, "Where flag is one or more of the following options:"
        print >> sys.stderr, "--auth=<filename>\tSpecify name of file containing API credentials"
        print >> sys.stderr, "--starting=<datetime>\tSpecify a no-earlier-than date for issues (ISO8601)"
        print >> sys.stderr, "--ending=<datetime>\tSpecify a no-later-than date for issues (ISO8601)"
        print >> sys.stderr, "--reportType=<type>\tSpecify type of report, allowed = %s" % self.allowedReportTypes


class ArchiveData:
	def __init__(self):
		config = ConfigParser.ConfigParser()
		config.read(self.authFilename)

		key_id = config.get('client','key_id')
		secret_key = config.get('client', 'secret_key')

		api_hostname = config.get('client', 'api_hostname')

		oauth = APIToken(api_hostname)
		token = oauth.get_token(key_id, secret_key)

		self.api = Api(token)
		self.directory = os.getcwd()
		return None

	def create_module_dictionary(self):
		module_dictionary = {}
		modules = cmd.reportModule.split(',')

		for module in modules:
			module_dictionary[module] = []
		return module_dictionary

	def get_url(self):
		url = ""
		if cmd.reportModule:
			url += "?issue_type=%s" % (cmd.reportModule)
		if cmd.starting:
			if url:
				url += "&since=%s" % (cmd.starting)
			else:
				url += "?since=%s" % (cmd.starting)
			if cmd.ending:
				url += "&until=%s" % (cmd.ending)
		return url

	def get_issues(self, endoint):
		module_dictionary = {}
		pagination = True
		count = 1
		full_path = "v2/issues" + endoint

		while pagination == True:
			resp = self.api.get(full_path + "&per_page=100&page=%d" % (count))
			if resp.status_code != 200:
				print "Error: %s" % resp.status_code
				break
			else:
				data = resp.json()

			if "next" not in data["pagination"]:
				pagination = False
			else:
				count += 1

			if "issues" in data:
				issue_data = data["issues"]

			for i in issue_data:
				issue_type = str(i["issue_type"])
				if issue_type == "csm":
					agent_url = i["agent_url"] + "/sca"
				elif issue_type == "sva":
					agent_url = i["agent_url"] + "/svm"
				else:
					agent_url = i["agent_url"] + '/' + issue_type
				agent_url = agent_url.split('com/')[1]

				module_dictionary.setdefault(issue_type,[])
				if agent_url not in module_dictionary[issue_type]:
					module_dictionary[issue_type].append(str(agent_url))

		return module_dictionary

	def get_detail(self, module_dictionary):
		for k in module_dictionary:
			server_list = module_dictionary[k]
			for i in server_list:
				resp = self.api.get(i)
				if resp.status_code != 200:
					print "Error: %s" % resp.status_code
					break
				else:
					data = resp.json()
					if "scan" in data:
						scan_data = data["scan"]
				scan_time = dateutil.parser.parse(scan_data["created_at"])
				filename = self.directory + "/output/" + str(scan_time.year) + '-' + str(scan_time.month) + '-' + str(scan_time.day)
				filename += '/' + scan_data["server_hostname"] + '/' + scan_data["module"] + "--" + scan_data["id"] + ".json"
				if not os.path.exists(os.path.dirname(filename)):
					os.makedirs(os.path.dirname(filename))
				with open(filename, "w") as f:
					json.dump(scan_data, f)
		return None

	def run(self, cmd):
		endpoint = self.get_url()
		print "---- Collecting all the issues ----"
		module_dictionary = self.get_issues(endpoint)
		print "---- Writing all the issues into files -----"
		self.get_detail(module_dictionary)
		return None

if __name__ == "__main__":
	cmd = CmdLine()
	if not cmd.processArgs(sys.argv):
		cmd.usage(sys.argv[0])
	else:
		resp = ArchiveData()
		resp.run(cmd)
	print ("--- %s seconds ---" % (time.time() - start_time))