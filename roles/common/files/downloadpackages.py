#!/usr/bin/env python

import os, sys,re
from optparse import OptionParser, OptionGroup
is_urllib_request = False
try:
    # For Python 3.0 and later
    from urllib.request import urlopen, install_opener, build_opener, Request, ProxyHandler
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode
    is_urllib_request = True
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib import urlencode
    from urllib2 import urlopen, install_opener, build_opener, Request, ProxyHandler, HTTPError, URLError


api_server    = 'API_SERVER'
api_key       = 'API_KEY'
api_secret    = 'API_SECRET'
client_id     = 'CLIENT_ID'
proxy_prefix  = 'PROXY'
proxy_server  = 'PROXY_SERVER'
proxy_port    = 'PROXY_PORT'
proxy_user    = 'PROXY_USERNAME'
proxy_passwd  = 'PROXY_PASSWORD'
connection    = 'PROXY_TYPE'
proxy_proto   = 'PROXY_PROTO'
agent_version = 'none'
proxy_passwd_d=''
proxy_port = proxy_port.replace("PROXY_PORT", "3128")
proxy_proto = proxy_proto.replace("PROXY_PROTO","http")
usage = "Use the proper command line arguments. \nUsage: %prog  [-K key] [-S secret] [-s server] [-l <log-directory>] [-m 'proxy' -x <proxy-server> -p <proxy-port>]\n"
parser = OptionParser(usage=usage)
group = OptionGroup(parser, 'Optional parameters')
group.add_option("-K", "--key", dest="key", default="", help="Oauth API key authorization.")
group.add_option("-S", "--secret", dest="secret", default="", help="Oauth API secret.")
group.add_option("-c", "--clientid", dest="clientid", default="", help="Client unique ID.")
group.add_option("-s", "--server", dest="server", default="", help="Cloud server to connect. Example: api.opsramp.io")
group.add_option("-m", "--connection-mode", dest="connection", default="", help="The mode of connection - [direct] or proxy or gateway.")
group.add_option("-x", "--proxy_server", dest="pserver", default="", help="Proxy server address to connect")
group.add_option("-p", "--proxy_port", dest="pport", default="", help="Proxy server port to connect")
group.add_option("-U", "--proxy_username", dest="pusername", default="", help="Proxy server authentication username to connect")
group.add_option("-P", "--proxy_password", dest="ppassword", default="", help="Proxy server authentication password to connect")
group.add_option("-f", "--features", dest="features", default="", help="features set to enable")
group.add_option("-t", "--protocol_type", dest="prototype", default="", help="Proxy protocol supported type(http/https)")

parser.add_option_group(group)
(options, _args) = parser.parse_args()

if options.key != "":
    api_key = str(options.key.strip())

if options.secret != "":
    api_secret = str(options.secret.strip())

if options.clientid != "":
    client_id = str(options.clientid.strip())
if options.server != "":
    api_server = str(options.server.strip())
if options.pserver != "":
    proxy_server = str(options.pserver.strip())

if options.connection != "":
    connection = str(options.connection.strip())

if options.pport != "":
    proxy_port = str(options.pport.strip())

if options.pusername != "":
    proxy_user = str(options.pusername.strip())

if options.ppassword != "":
    proxy_passwd = str(options.ppassword.strip())

if options.prototype != "":
    proxy_proto = str(options.prototype.strip())
try:
    if connection.lower() == "proxy" and proxy_passwd != proxy_prefix + '_PASSWORD':
        import base64
        proxy_passwd_d=base64.b64decode(proxy_passwd)
except Exception as e:
    print("Failed to decode proxypassword: %s" %(e))
    file.close()
    sys.exit(2)

pwd=os.getcwd()+"/roles/common/files/"
def saveagentversion(version):
    try:
        fp=open(pwd+"../vars/agentversion.yml","w+")
        fp.write("agentVersion: "+version+"\n")
        fp.close()
    except Exception:
        pass

def generate_minjson_adapter():
    class json(object):
        @staticmethod
        def loads(data):
            return safeRead(data)

    return json


try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = generate_minjson_adapter()

def executeCommand(cmd):
    try:
        if sys.version_info < (2, 7):
            import commands
            result = commands.getstatusoutput(cmd)
            return result[0] >> 8 , result[1]
        else:
            #args = shlex.split(cmd)
            import subprocess
            result = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            return 0, str(result).strip()
    except Exception:
        return -1, ""

def disable_cert_check_context():
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE
        return context
    except:
        return None

def downloadFile(download_url, dest, headers={}):
    try:
        block_sz = 8192

        ''' HTTP GET request for file download '''
        req = Request(download_url, None, headers)
        if proxy_server not in ['', proxy_prefix + '_SERVER']:
            if proxy_user != proxy_prefix + "_USERNAME":
                proxy_url = proxy_proto + "://%s:%s@%s:%s" % (proxy_user, proxy_passwd_d, proxy_server, proxy_port)
            else:
                proxy_url = proxy_proto + "://%s:%s" % (proxy_server, proxy_port)

            proxy_handler = ProxyHandler({'http': proxy_url, 'https': proxy_url})
            opener = build_opener(proxy_handler)
            install_opener(opener)


        resp = None
        python_version = sys.version_info
        if (python_version[0] == 2 and python_version >= (2,7,9)) or (python_version[0] == 3 and python_version >= (3,4,3)):
            #resp = urlopen(req, context=allow_tls_only_context(), timeout=30)
            resp = urlopen(req, context=disable_cert_check_context(), timeout=30)
        elif python_version >= (2,6):
            resp = urlopen(req, timeout=30)
        else:
            resp = urlopen(req)

        ''' Write response content to file '''
        fd = open(dest, 'wb')
        while True:
            buffer = resp.read(block_sz)
            if not buffer:
                break
            fd.write(buffer)
        fd.close()

        resp.close()
        return True
    except HTTPError:
        print ("downloadFile: HTTP Error Exception")
        if os.path.exists("/usr/bin/curl"):
            print ("Downloading file - %s using curl" % (dest))
            if executeCommand("curl -k -H 'authorization: %s' %s -o %s" % (headers['authorization'], download_url, dest))[0] == 0:
                print ("File - %s has been successfully downloaded using curl" % (dest))
                return True
        return False
    except URLError:
        print ("downloadFile: URL Error Exception")
        return False

def httpRequest(url, headers={}, data=None):
    try:
        http_headers = {
            'Content-Type' : 'application/json',
            'Accept'       : '*/*'
        }
        http_headers.update(headers)
        req = Request(url, data, http_headers)
        if proxy_server not in ['', proxy_prefix + '_SERVER']:
            if proxy_user != proxy_prefix + '_USERNAME':
                proxy_url = proxy_proto + "://%s:%s@%s:%s" % (proxy_user, proxy_passwd_d, proxy_server, proxy_port)
            else:
                proxy_url = proxy_proto + "://%s:%s" % (proxy_server, proxy_port)
            proxy_handler = ProxyHandler({'http': proxy_url, 'https': proxy_url})
            install_opener(build_opener(proxy_handler))

        python_version = sys.version_info
        if (python_version[0] == 2 and python_version >= (2,7,9)) or (python_version[0] == 3 and python_version >= (3,4,3)):
            #return urlopen(req, context=allow_tls_only_context(), timeout=30).read()
            return urlopen(req, context=disable_cert_check_context(), timeout=30).read()
        elif python_version >= (2,6):
            return urlopen(req, timeout=30).read()
        else:
            return urlopen(req).read()
    except Exception:
        raise
def get_access_token():
    """ Block of code used to get Access Token from OpsRamp cloud by invoking OpsRamp Token API call """
    try:
        data = urlencode({
            "client_id"     : api_key,
            "client_secret" : api_secret,
            "grant_type"    : "client_credentials"
        })

        if is_urllib_request:
            data = data.encode()

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_url = "https://" + api_server + "/auth/oauth/token"

        resp = httpRequest(token_url, headers, data).decode()
        response = json.loads(resp)
        access_token = response["access_token"]
        token_type   = response["token_type"]
        return str(token_type) + " " + str(access_token)
    except Exception:
        raise

def get_agent_version(version_url, access_token):
    """ Block of code used to get agent version from OpsRamp cloud by invoking OpsRamp Token API call """
    try:
        headers = {
            "Accept"        : "application/json",
            "Content-Type"  : "application/json",
            "authorization" : access_token
        }
        return json.loads(httpRequest(version_url, headers).decode())
    except Exception:
        raise

def delete_old_packages(availablepackages,finalDeletionList):
    try:
        for package in finalDeletionList:
            os.remove(pwd+package)
            availablepackages.remove(package)
        return availablepackages
    except Exception:
        pass

def chech_and_delete_agentpackages(availablepackages,dllist,agentVersionRegex):
    downloadlist=""
    dellist=""
    try:
        for package in availablepackages:
            if re.search(agentVersionRegex,package):
                if package == dllist[0] or package == dllist[1]:
                    downloadlist+=package+";"
                else:
                    dellist+=package+";"
        if downloadlist != "":
            downloadlist = downloadlist.rstrip(";")
            finallist = downloadlist.split(";")
            dllist.remove(finallist[0])
            if len(finallist) ==2:
                dllist.remove(finallist[1])
        if dellist != "":
            dellist = dellist.rstrip(";")
            finalDeletionList=dellist.split(";")
            availablepackages=delete_old_packages(availablepackages,finalDeletionList)
    except Exception:
        pass     
    return availablepackages,dllist

def initiateAgentdownload(distmap,distribution,access_token):
    try: 
        for package in dllist:

            version_details = get_agent_version("https://%s/api/v2/tenants/%s/agents/LINUX/info?distName=%s&architecture=%s" %(api_server, client_id,distribution,distmap[package]), access_token)

            pkg_size = int(version_details['size'])
            checksum=str(version_details['checksum'])
            status = downloadFile("https://%s/api/v2/tenants/%s/agents/LINUX/download/%s" % (api_server, client_id, package), pwd+package,{'authorization': access_token, 'Accept': 'application/octet-stream'})
        
            if os.path.exists(pwd+package):
                if os.path.getsize(pwd+package) != pkg_size:
                    print("Download failed:\n"+"Downloaded file size: "+str(os.path.getsize(pwd+package))+"\n"+"Actual file size: "+str(pkg_size)+"\n")
                    if os.path.exists(pwd+package):
                        os.remove(pwd+package)
                        sys.exit(1)
            elif status == False:
                sys.exit(1)
    except Exception:
        pass
#Resetting agent version
saveagentversion("none")
availablepackages=os.listdir(pwd)
access_token = get_access_token()
version_url = "https://%s/api/v2/tenants/%s/agents/LINUX/info?distName=%s&architecture=%s" % (api_server, client_id, "redhat", "i386")
version_details = get_agent_version(version_url, access_token)

agent_version = str(version_details['version'])


dllist=['opsramp-agent-'+agent_version+'.i386.rpm','opsramp-agent-'+agent_version+'.x86_64.rpm']
availablepackages,dllist = chech_and_delete_agentpackages(availablepackages,dllist,"opsramp-agent-((\d\.)+){2}(\d)+-(\d)+\.(i386|x86_64)\.rpm")
if dllist != "":
    distmap={'opsramp-agent-'+agent_version+'.i386.rpm':"i386",'opsramp-agent-'+agent_version+'.x86_64.rpm': "x86_64" }
    initiateAgentdownload(distmap,"redhat",access_token)        

#Downloading Debian packages
dllist=['opsramp-agent_'+agent_version+'_amd64.deb','opsramp-agent_'+agent_version+'_i686.deb']
availablepackages,dllist = chech_and_delete_agentpackages(availablepackages,dllist,"opsramp-agent_((\d\.)+){2}(\d)+-(\d)+_(i686|amd64)\.deb")

if dllist != "":
    distmap={'opsramp-agent_'+agent_version+'_amd64.deb':"amd64",'opsramp-agent_'+agent_version+'_i686.deb': "i686" }
    initiateAgentdownload(distmap,"ubuntu",access_token)

#Saving Agent version in File
saveagentversion(agent_version)
