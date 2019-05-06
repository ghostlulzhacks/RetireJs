import requests
from bs4 import BeautifulSoup
import re
import json
import sys
from packaging import version as versionLib
import argparse

def openJSONFile():
    with open("jsrepository.json", 'r') as f:
        dataJson = json.load(f)
    return dataJson


def retire_js(url):
    dataJson = openJSONFile()
    scanDomain = url
    if url.startswith("http"):
        r = requests.get(url,verify=False,timeout=5)
    else:
        try:
            r = requests.get("https://"+url,verify=False,timeout=5)
        except:
            try:
                r = requests.get("http://"+url,timeout=5)
            except:
                return 0

    url = r.request.url
    url = url.split("//")[0] + "//" +  url.split("//")[-1].split("/")[0]

    soup = BeautifulSoup(r.content, 'html.parser')
    scripts = soup.find_all('script')

    for script in scripts:
        try:
                #Format .js url based on script src
            if "http" in str(script.attrs['src']):
                javascriptFile(str(script.attrs['src']),dataJson,scanDomain)

            elif  str(script.attrs['src']).startswith('//'):
                javascriptFile(url + str(script.attrs['src']).replace("//","/"),dataJson,scanDomain)

            elif not str(script.attrs['src']).startswith('/'):
                javascriptFile(url + "/" + str(script.attrs['src']),dataJson,scanDomain)

            elif str(script.attrs['src']).startswith('/'):
                javascriptFile(url +str(script.attrs['src']),dataJson,scanDomain)
        except:
            pass

def javascriptFile(url,dataJson,scanDomain):
    vreg = "[0-9][0-9.a-z_\\\\-]+"
    try:
        r = requests.get(url,verify=False,timeout=25)
    except:
        return 0

    #loop javascript frameworks
    for name in dataJson:
        try:
            #get version regexes
            for regg in dataJson[name]["extractors"]["filecontent"]:
                try:
                    reg =  re.sub(r'[^\x00-\x7f]',r'', regg).replace(u"version",vreg)
                    if reg.startswith("/"):
                        reg = reg.replace("/","",1)

                    m = re.search(reg, r.content)
                    mm = re.search(vreg, m.group(0))
                    version =  mm.group(0)
                    vulnerableVersion(dataJson,name,version,url,scanDomain)
                except:
                    pass

        except:
            pass
    return 0

def vulnerableVersion(dataJson,name,version,url,scanDomain):
    for vuln in dataJson[name]["vulnerabilities"]:

        below = 9999
        atAbove =  1

        try:
            below =vuln["below"]

        except:
            pass
        try:
            atAbove = vuln["atOrAbove"]
        except:
            pass

        try:
            if versionLib.parse(str(version)) < versionLib.parse(str(below)) and versionLib.parse(str(version)) >= versionLib.parse(str(atAbove)):
                jsonArray = {}
                jsonArray['name'] = str(name)
                jsonArray['version'] = str(version)
                jsonArray['vulnerabilities'] = str(vuln["identifiers"]["summary"])
                jsonArray['url'] = str(url)
                jsonArray['domain'] = str(scanDomain)
                try:
                    jsonArray['CVE'] = "".join(str(cve + " ") for cve in vuln["identifiers"]["CVE"])
                except:
                    jsonArray['CVE'] = "None"

                if json.dumps(jsonArray)  not in foundvulns:
                    print json.dumps(jsonArray)
                    foundvulns.append(json.dumps(jsonArray))

        except Exception as e:
            print e



parser = argparse.ArgumentParser(description='Find vulnerable javascript files')
parser.add_argument('-d','--domain',help='domain name')
parser.add_argument('-f','--file',help='file containing list of domain names')
args = parser.parse_args()


foundvulns = []

if args.file:
    with open(args.file) as f:
        for line in f:
            line = line.rstrip('\n')
            retire_js(line)

elif args.domain:
    retire_js(args.domain)
