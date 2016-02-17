import re
import os
import sys
import json
import datetime
import dateutil.parser

def write_file_2(directory, scan_time, server_hostname, issue_type, data, server_info):
    filename = directory + "/output/" + str(scan_time) + "/"
    if server_info:
        filename += server_hostname + "/server_info.json"
    else:
        filename += server_hostname + "/" + issue_type+'--' + data["id"] + '.json'

    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    with open(filename, "w") as f:
        json.dump(data, f)
    return None

def write_file(directory, scan_time, data, server_info):
    filename = directory + "/output/" + str(scan_time) + "/"
    if server_info:
        filename += data["server"]["hostname"] + "/server_info.json"
    else:
        filename += data["scan"]["server_hostname"] + "/" + data["scan"]["module"] +'--' + data["scan"]["id"] + '.json'

    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    with open(filename, "w") as f:
        json.dump(data, f)
    return None

def verify_module(modules_str, allowedReportTypes):
    modules = modules_str.split(',')
    for module in modules:
        if module not in allowedReportTypes:
            print "Error: There's a typo in the report type. The allowed report types are %s" % allowedReportTypes
            sys.exit(1)
    return None

def verifyISO8601(tstr):
    if (tstr == None) or (len(tstr) == 0):
        return (False, "Empty timestamp, ISO8601 format required")
    iso_regex = "(\d{4})-(\d{2})-(\d{2})(T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?(Z|[+-]\d{4})?)?$"
    m = re.match(iso_regex, tstr)
    print m
    if (m == None):
        return (False, "Timestamp (%s) does not match ISO8601 format" % tstr)

    year = m.group(1)
    month = m.group(2)
    day = m.group(3)
    hour = m.group(5)
    minute = m.group(6)
    second = m.group(7)
    if (year == None) or (int(year) < 1900) or (int(year) > 2100):
        return (False, "Invalid year (%s)" % year)
    if (month == None) or (int(month) < 1) or (int(month) > 12):
        return (False, "Invalid month (%s)" % month)
    if (day == None) or (int(day) < 1) or (int(day) > 31):
        return (False, "Invalid day of month (%s)" % day)
    if (hour != None):
        if (int(hour) < 0) or (int(hour) > 23):
            return (False, "Invalid hour (%s)" % hour)
        if (minute != None):
            if (int(minute) < 0) or (int(minute) > 59):
                return (False, "Invalid minute (%s)" % minute)
            if (second != None):
                if (int(second) < 0) or (int(second) > 59):
                    return (False, "Invalid second (%s)" % second)
    now = getNowAsISO8601()
    if (now < tstr):
        return (False, "Timestamp (%s) is in the future" % tstr)
    return (True, "")

def formatTimeAsISO8601(dt):
    tuple = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % tuple

def getNowAsISO8601():
    return formatTimeAsISO8601(datetime.datetime.utcnow())