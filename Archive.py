#!/usr/bin/env python
import sys
import re
import os
import json
import time
import threading
import dateutil.parser
import cpapi
import cputils
import logbook

LOGGER = logbook.Logger('archive')
LOG = logbook.FileHandler('monitoring.log')
LOG.push_application()
START_TIME = time.time()

class CmdLine:
    def __init__(self):
        self.auth_filename = "archive.auth"
        self.report_module = "sva,csm"
        self.url_base = "https://api.cloudpassage.com"
        self.output_path = os.getcwd()
        self.allowed_report_type = ["sva", "csm"]

    def process_args(self, argv):
        all_ok = True
        self.progdir = os.path.dirname(sys.argv[0])
        for arg in argv[1:]:
            if arg.startswith("--auth="):
                self.auth_filename = arg.split("=")[1]
            elif arg.startswith("--base="):
                self.base = arg.split("=")[1]
            elif arg.startswith("--reportType"):
                self.report_module = arg.split("=")[1]
                cputils.verify_module(self.report_module, self.allowed_report_type)
            elif arg.startswith("--output_path="):
                self.output_path = os.path.abspath(arg.split("=")[1])
            elif (arg == "-h") or (arg == "-?"):
                all_ok = False
            else:
                print >>sys.stderr, "Unknown argument: %s" % arg
                all_ok = False
        return all_ok

    def usage(self, progname):
        print >> sys.stderr, "Usage: %s [flag] [...]" % os.path.basename(progname)
        print >> sys.stderr, "Where flag is one or more of the following options:"
        print >> sys.stderr, "--auth=<filename>\tSpecify name of file containing API credentials"
        print >> sys.stderr, "--base=<url>\t\tSpecify the URL of the Halo REST API"
        print >> sys.stderr, "--output_path=<file_path>\t\t\
                             Specify the file directory for archived.\
                             The default file path is the same as Archive_issues"



class ArchiveData:
    def __init__(self):
        self.api = cpapi.CPAPI()
        print "Saving output files to %s" % CMD.output_path

    def list_servers(self):
        count = 1
        server_list = []
        finish = False
        url = "%s:%d/v1/servers?per_page=5&page=1" %(self.api.base_url, self.api.port)
        (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
        if data:
            LOGGER.info("First API was successful! Data is good.")
        while (data is None) and (count < 4):
            LOGGER.warn("Failed to connect to %s" % url)
            self.api.authenticateClient()
            (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
            LOGGER.warn(err_msg)
            LOGGER.warn("retry: %d time" % count + "on %d" % url)
            if data:
                LOGGER.info("Successfully retreive server list from %d" % url)
            count += 1
        while(data != None) and (finish == False):
            if 'servers' in data:
                list_servers = json.loads(data)
                servers = list_servers['servers']
                for server in servers:
                    server_list.append((server['id'], server))
                if 'pagination' in list_servers:
                    if 'next' in list_servers['pagination']:
                        url = list_servers['pagination']['next']
                        count_pagingation = 1
                        (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
                        while (data is None) and (count_pagingation < 4):
                            self.api.authenticateClient()
                            LOGGER.warn(err_msg)
                            LOGGER.warn("retry: %d time" % count_pagingation + "on %s" % url)
                            (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
                            if data:
                                LOGGER.info("Successfully retreive server list from %s" % url)
                            count_pagingation += 1
                        if count == 4:
                            LOGGER.warn("Failed to connect to", url)
                    else:
                        finish = True
                else:
                    finish = True
        return server_list

    def get_server_module(self, server_list, module):
        server_id = server_list[0]
        server_info = server_list[1]
        new_findings = []
        count = 1
        url = "%s:%d/v1/servers/%s/%s" % (self.api.base_url, self.api.port, server_id, module)
        (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
        while (data is None) and (count < 4):
            self.api.authenticateClient()
            LOGGER.warn(err_msg)
            LOGGER.warn("retry: %d time" % count + "on %s" % url)
            (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
            if data:
                LOGGER.info("Successfully retreive server issue from %s" % url)
            count += 1
        if data:
            scan_data = json.loads(data)
            if 'scan' in scan_data:
                findings = scan_data['scan']['findings']
                scan_time = dateutil.parser.parse(scan_data['scan']['created_at'])
                if findings:
                    for finding in findings:
                        if finding['status'] == 'bad':
                            new_findings.append(finding)
                    if new_findings:
                        if module == 'svm':
                            for new_finding in new_findings:
                                new_finding['age'] = self.get_issue_duration("sva", new_finding['package_name'], scan_data['id'])
                        if module == "sca":
                            for new_finding in new_findings:
                                new_finding['age'] = self.get_issue_duration("csm", new_finding['rule_name'], scan_data['id'])
                        scan_data['scan']['findings'] = new_findings
                        cputils.write_file(CMD.output_path, scan_time, scan_data, False)
                        LOGGER.info("Successfully archive %s scan from: %s" % (module, url))
                if server_info:
                    cputils.write_file(CMD.output_path, scan_time, server_info, True)
                    LOGGER.info("Successfully retreive server data from %s" % server_id)
        else:
            LOGGER.warn("Failed to connect to %s" % url)
        return None

    def get_issue_duration(self, module, name, agent_id):
        count = 1
        duration = None
        url = "%s:%d/v2/issues?issue_type=%s&name=%s&agent_id=%s" % (self.api.base_url, self.api.port, module, name, agent_id)
        url = re.sub(r"\s+", '%20', url)
        (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
        while (data is None) and (count < 4):
            self.api.authenticateClient()
            LOGGER.warn(err_msg)
            LOGGER.warn("retry: %d time" % count + "on %s" % url)
            (data, auth_error, err_msg) = self.api.doGetRequest(url, self.api.authToken)
            if data:
                LOGGER.info("Successfully retreive issue from %s" % url)
            count += 1
        if data:
            issue_data = json.loads(data)
            if 'issues' in issue_data:
                issues = issue_data['issues']
                for issue in issues:
                    created_at = dateutil.parser.parse(issue['created_at'])
                    last_seen = dateutil.parser.parse(issue['last_seen_at'])
                    duration = last_seen - created_at
                    return str(duration.days)

    def multi_threading(self, function, arg1, arg2):
        threads = []
        for i in arg1:
            thread = threading.Thread(target=function, args=(i, arg2))
            threads.append(thread)
            thread.start()
        thread.join()
        return thread

    def chunk(self, length, number):
        x = []
        for i in xrange(0, len(length), number):
            x.append(length[i:i+number])
        return x

    def run(self, cmd):
        threads = []
        (credential_list, err_msg) = cputils.processAuthFile(cmd.auth_filename, cmd.progdir)
        if err_msg:
            print >> sys.stderr, err_msg
            return False
        if len(credential_list) < 1:
            return False
        # print credentials
        credentials = credential_list[0]
        self.api.base_url = cmd.url_base
        self.api.key_id = credentials['id']
        self.api.secret = credentials['secret']
        resp = self.api.authenticateClient()
        if not resp:
            return False

        print "Start archiving issues."
        LOGGER.info("start archiving issues.")
        server_list = self.list_servers()
        print "--- %s servers ---" % (len(server_list))
        LOGGER.info("--- %s servers ---" % (len(server_list)))
        server_chuncks = self.chunk(server_list, 10)
        for server_chunck in server_chuncks:
            temp = self.multi_threading(self.get_server_module, server_chunck, 'sca')
            temp = self.multi_threading(self.get_server_module, server_chunck, 'svm')


if __name__ == "__main__":
    CMD = CmdLine()
    if not CMD.process_args(sys.argv):
        CMD.usage(sys.argv[0])
    else:
        REP = ArchiveData()
        REP.run(CMD)
        print "--- %s seconds ---" % (time.time() - START_TIME)
        LOGGER.info("--- %s seconds ---" % (time.time() - START_TIME))

