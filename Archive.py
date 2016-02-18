#!/usr/bin/env python
# modified date : 2015-02-17 v5

import sys
import os
import re
import json
import time
import util
import ConfigParser
import dateutil.parser
import logbook
from datetime import date
from api import Api
from oauth import APIToken

logger = logbook.Logger('archive')
log = logbook.FileHandler('monitoring.log')
log.push_application()

start_time = time.time()

class CmdLine:
    def __init__(self):
        self.authFilename = "archive.auth"
        self.starting = date.today()
        self.reportModule = None
        self.output_path = os.getcwd()
        self.allowedReportTypes = ["sva", "csm", "fim", "sam", "agent", "fw"]

    def processArgs(self, argv):
        allOK = True
        self.progdir = os.path.dirname(sys.argv[0])
        for arg in argv[1:]:
            if (arg.startswith("--auth=")):
                self.authFilename = arg.split("=")[1]
            elif (arg.startswith("--starting")):
                self.starting = arg.split("=")[1]
                util.verifyISO8601(self.starting)
            elif (arg.startswith("--base=")):
                self.base = arg.split("=")[1]
            elif (arg.startswith("--reportType")):
                self.reportModule = arg.split("=")[1]
                util.verify_module(self.reportModule, self.allowedReportTypes)
            elif (arg.startswith("--output_path")):
                self.output_path = arg.split("=")[1]
            elif (arg == "-h") or (arg == "-?"):
                allOK = False
            else:
                print >>sys.stderr, "Unknown argument: %s" % arg
                allOK = False
        return allOK

    def usage(self, progname):
        print >> sys.stderr, "Usage: %s [flag] [...]" % os.path.basename(progname)
        print >> sys.stderr, "Where flag is one or more of the following options:"
        print >> sys.stderr, "--auth=<filename>\tSpecify name of file containing API credentials. "
        print >> sys.stderr, "--starting=<datetime>\tSpecify a no-earlier-than date for issues (ISO8601).Defsult setting will be current date"
        print >> sys.stderr, "--reportType=<type>\tSpecify type of report, allowed = %s" % self.allowedReportTypes
        print >> sys.stderr, "--output_path=<file_path>\t\tSpecify the file directory for archived scans. The default file path is the same as Archive_v2"


class ArchiveData:
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read(cmd.authFilename)

        self.key_id = config.get('client','key_id')
        self.secret_key = config.get('client', 'secret_key')

        self.api_hostname = config.get('client', 'api_hostname')

        self.directory = cmd.output_path
        self.scan_time = None
        return None

    def authentication(self):
        oauth = APIToken(self.api_hostname)
        token = oauth.get_token(self.key_id, self.secret_key)
        self.api = Api(token)
        return self.api

    def get_url(self):
        url = ""
        if cmd.reportModule:
            url += "?issue_type=%s" % (cmd.reportModule)
        return url

    def get_issues_2(self, endpoint):
        issues_list = []
        pagination = True
        count = 1
        full_path = "v2/issues" + endpoint
        while pagination == True:
            if '?' in full_path:
                resp = self.api.get(full_path + "&per_page=100&page=%d" % (count))
            else:
                resp = self.api.get(full_path + "?per_page=100&page=%d" % (count))
            while True:
                try:
                    if resp.status_code != 200:
                        raise ValueError(resp.status_code)
                    data = resp.json()
                except ValueError as e:
                    print "Error: %s. Retrying...." % e
                    self.authentication()
                    continue
                break

            if "pagination" in data:
                if "next" in data['pagination']:
                    count += 1
                else:
                    pagination = False
                if "issues" in data:
                    issue_data = data['issues']

                for i in issue_data:
                    last_seen_time = dateutil.parser.parse(i["last_seen_at"]).date()
                    issue_type = i["issue_type"]
                    if last_seen_time == cmd.starting:
                        issue_url = i['url'].split('com/')[1]

                        if issue_url not in issues_list:
                            issues_list.append(issue_url)
        return issues_list
    def get_issues_detail(self, issues_list):
        for i in issues_list:
            while True:
                try:
                    resp = self.api.get(i)
                    if resp.status_code != 200:
                        raise ValueError(resp.status_code)
                    data = resp.json()
                except ValueError as e:
                    print "Error: %s. Retrying ..." % e
                    self.authentication()
                    continue
                break
            if 'findings' in data:
                latest_finding = data['findings'][-1]
                finding_url = latest_finding['finding'].split('com/')[1]
                agent_url = data['agent_url'].split('com/')[1]
                while True:
                    try:
                        finding_resp = self.api.get(finding_url)
                        agent_resp = self.api.get(agent_url)
                        if (finding_resp.status_code != 200) or (agent_resp.status_code != 200):
                            raise ValueError(resp.status_code)
                        finding_data = finding_resp.json()
                        agent_data = agent_resp.json()
                    except ValueError as e:
                        print "Error: %s. Retrying ..." % e
                        self.authentication()
                        continue
                    break
                issue_type = data['issue_type']
                server_hostname = agent_data['server']['hostname']
                util.write_file_2(self.directory, cmd.starting, server_hostname, issue_type, finding_data, False)
                util.write_file_2(self.directory, cmd.starting, server_hostname, issue_type, agent_data, True)

        return None

    def get_issues(self, endpoint):
        module_dictionary = {}
        server_list = []
        pagination = True
        count = 1
        full_path = "v2/issues" + endpoint
        while pagination == True:
            error_count = 0
            while True:
                try:
                    if '?' in full_path:
                        resp = self.api.get(full_path + "&per_page=100&page=%d" % (count))
                    else:
                        resp = self.api.get(full_path + "?per_page=100&page=%d" % (count))
                    if resp.status_code != 200:
                        raise ValueError(resp.status_code)
                    data = resp.json()
                    if error_count > 0:
                        logger.info("Retry was successful...")
                except ValueError as e:
                    print "Error: %s. Retrying...." % e
                    logger.info("Error: %s. Retrying...." %e)
                    self.authentication()
                    error_count += 1
                    continue
                break

            #check pagination
            if "pagination" in data:
                if "next" in data["pagination"]:
                    count += 1
                else:
                    pagination = False
            else:
                pagination = False

            if "issues" in data:
                issue_data = data["issues"]

            for i in issue_data:
                last_seen_time = dateutil.parser.parse(i["last_seen_at"]).date()
                issue_type = i["issue_type"]
                if last_seen_time == cmd.starting:
                    if issue_type == "csm":
                        agent_url = i["agent_url"] + "/sca"
                    elif issue_type == "sva":
                        agent_url = i["agent_url"] + "/svm"
                    else:
                        agent_url = i["agent_url"] + '/' + issue_type
                    agent_url = agent_url.split('com/')[1]
                    server_url = i["agent_url"].split('com/')[1]

                    module_dictionary.setdefault(issue_type,[])
                    if agent_url not in module_dictionary[issue_type]:
                        module_dictionary[issue_type].append(str(agent_url))

                    if server_url not in server_list:
                        server_list.append(str(server_url))
        return module_dictionary, server_list

    def get_detail(self, module_dictionary):
        for k in module_dictionary:
            server_list = module_dictionary[k]
            for i in server_list:
                new_findings =[]
                new_details = []
                error_count = 0
                while True:
                    try:
                        resp = self.api.get(i)
                        if resp.status_code != 200:
                            raise ValueError(resp.status_code)
                        data = resp.json()
                        if error_count > 0:
                            logger.info("Retry was successful. Endpoint: %s" % i)
                    except ValueError as e:
                        print "Error: %s. Retrying...." % e
                        logger.info("Error: %s. Retrying.... endpoint: %s" % (e, i))
                        self.authentication()
                        error_count += 1
                        continue
                    break
                if "scan" in data:
                    scan_data = data["scan"]
                    findings = scan_data["findings"]
                    for finding in findings:
                        if finding['status'] == 'bad':
                            new_findings.append(finding)

                    for i in new_findings:
                        if 'details' in i:
                            details = i['details']
                            for detail in details:
                                if detail['status'] == 'bad':
                                    new_details.append(detail)
                            i['details'] = new_details

                    scan_data['findings'] = new_findings
                    # remove_indexes = [i for i, finding in enumerate(findings) if finding['status'] != 'bad']
                    # findings = [v for i, v in enumerate(findings) if i not in remove_indexes]
                    # for finding in findings:
                    #   if 'details' in finding:
                    #       details = finding['details']
                    #       remove_detail_indexes = [i for i, detail in enumerate(details) if detail['status'] != 'bad']
                    #       print json.dumps(findings, indent=2)
                    #       finding['details'] = [v for i, v in enumerate(details) if i not in remove_detail_indexes]

                    # scan_data['findings'] = findings
                    util.write_file(self.directory, cmd.starting, data, False)
        return None

    def get_server_info(self, server_list):
        for server in server_list:
            error_count = 0
            while True:
                try:
                    resp = self.api.get(server)
                    if resp.status_code != 200:
                        raise ValueError(resp.status_code)
                    data = resp.json()
                    if error_count > 0:
                        logger.info("Retry was successful. Endpoint: %s" % server)
                except ValueError as e:
                    print "Error: %s. Retrying...." % e
                    logger.info("Error: %s. Retrying.... Endpoint: %s" % (e, server))
                    self.authentication()
                    error_count += 1
                    continue
                break
            if "server" in data:
                util.write_file(self.directory, cmd.starting, data, True)
        return None

    def run(self, cmd):
        self.authentication()
        endpoint = self.get_url()
        print "Output will be store in %s" % cmd.output_path
        logger.info("Output will be store in %s" % cmd.output_path)
        print "---- Collecting all the issues ----"
        logger.info("---- Collecting all the issues ----")
        module_dictionary,server_list = self.get_issues(endpoint)
        print "---- Writing all the issues into files -----"
        logger.info("---- Writing all the issues into file ----")
        self.get_detail(module_dictionary)
        print "---- Writing all the server information ----"
        logger.info("---- Writing all the server information ----")
        self.get_server_info(server_list)
        return None

if __name__ == "__main__":
    cmd = CmdLine()
    if not cmd.processArgs(sys.argv):
        cmd.usage(sys.argv[0])
    else:
        resp = ArchiveData()
        resp.run(cmd)
    print ("---- %s seconds ----" % (time.time() - start_time))
    logger.info("---- %s seconds ----" % (time.time() - start_time))