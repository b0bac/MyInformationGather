import time
import tkinter
import datetime
import threading
from DomainUtils import GetSubDomain
from ScanUtils import Ping, PortTcpScan
from DNSUtils import GetARecord, GetCNameRecord
from HttpUtils import HttpScan


class Scanner:
    def __init__(self, token, domain, flag, box, size, logger):
        self.TopLevelDomain = domain
        print(self.TopLevelDomain)
        self.VirusTotalToken = token
        self.PortFlag = flag
        self.EnterprisePort = [21, 22, 23, 25, 53, 80, 81, 110, 111, 123, 123, 135, 137, 139, 161, 389, 443, 445, 465,
                               500, 515, 520, 523, 548, 623, 636, 873, 902, 1080, 1099, 1433, 1521, 1604, 1645, 1701,
                               1883, 1900, 2049, 2181, 2375, 2379, 2425, 3128, 3306, 3389, 4730, 5060, 5222, 5351, 5353,
                               5432, 5555, 5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8080, 8081, 8443,
                               8545, 8686, 9000, 9001, 9042, 9092, 9100, 9200, 9418, 9999, 11211, 27017, 37777, 50000,
                               50070, 61616]
        self.ConsequenceBox = box
        self.IDNumber = 0
        self.size = size
        self.logger = logger
        self.filename = "%s"%str(self.TopLevelDomain)+ "_" +str(datetime.datetime.today()).replace(" ","_").split(".")[0]+".csv"
        with open(self.filename, 'w') as fw:
            fw.write("主域名,子域名,CNAME,地址,端口,页面标题\n")

    def LogWriter(self, message):
        self.logger.config(state='normal')
        self.logger.insert(tkinter.END, message)
        self.logger.config(state="disable")

    def PortScan(self, ip, port, cname, subdomain):
        try:
            if PortTcpScan(ip, port):
                self.LogWriter("[+] 探测到活跃端口: %s\n" % str(port))
                title, message = HttpScan(ip, port)
                self.LogWriter(message)
                if title is not None:
                    self.LogWriter("[+] 探测到页面标题: %s\n" % str(title))
                    self.ConsequenceBox.insert('', 'end',
                                           values=[str(self.IDNumber), self.TopLevelDomain, subdomain, cname, ip, str(port),
                                                   title])
                    with open(self.filename, 'a') as fw:
                        fw.write("%s,%s,%s,%s,%s,%s\n"%(str(self.TopLevelDomain), subdomain, cname, ip, str(port), title))
                    self.IDNumber += 1
                else:
                    self.ConsequenceBox.insert('', 'end',
                                           values=[str(self.IDNumber), self.TopLevelDomain, subdomain, cname, ip, str(port), ""])
                    with open(self.filename, 'a') as fw:
                        fw.write("%s,%s,%s,%s,%s,%s\n"%(str(self.TopLevelDomain), subdomain, cname, ip, str(port), ""))
                    self.IDNumber += 1
            self.size -= 1
        except Exception as exception:
            self.LogWriter("[-] 捕获异常: %s, , 异常点 CoreUtils.Scan.Line.57\n"%str(exception))

    def Scan(self):
        print(self.TopLevelDomain)
        try:
            _list = GetSubDomain(self.TopLevelDomain, self.VirusTotalToken)
        except Exception as exception:
            self.LogWriter("[-] 捕获异常: %s, 异常点 CoreUtils.Scan.Line.63\n" % str(exception))
        cnamelist = []
        iplist = []
        print(self.TopLevelDomain)
        self.LogWriter("[+] 获取顶级域名: %s\n"%str(self.TopLevelDomain))
        for domain in _list:
            try:
                cnamelist = GetCNameRecord(domain)
            except Exception as exception:
                self.LogWriter("[-] 捕获异常: %s, 异常点 CoreUtils.Scan.Line.71\n" % str(exception))
                continue
            if len(cnamelist) == 0:
                continue
            for cname in cnamelist:
                self.LogWriter("[+] 获取新的CNAME: %s\n" % str(cname))
                try:
                    iplist = GetARecord(cname)
                except Exception as exception:
                    self.LogWriter("[-] 捕获异常: %s, 异常点 CoreUtils.Scan.Line.80\n" % str(exception))
                    continue
                if len(iplist) == 0:
                    continue
                for ipaddress in iplist:
                    self.LogWriter("[+] 解析到地址: %s\n" % str(ipaddress))
                    if Ping(ipaddress):
                        self.LogWriter("[+] 探测到活跃地址: %s\n" % str(ipaddress))
                        if self.PortFlag == 2:
                            for port in self.EnterprisePort:
                                self.LogWriter("[+] 探测端口: %s\n" % str(port))
                                while True:
                                    if self.size <= 20:
                                        thread = threading.Thread(target=self.PortScan, args=(ipaddress, port, cname, domain))
                                        thread.start()
                                        time.sleep(0.5)
                                        break
                                    else:
                                        continue
                        elif self.PortFlag == 1:
                            for port in range(1, 65536):
                                while True:
                                    if self.size <= 20:
                                        thread = threading.Thread(target=self.PortScan, args=(ipaddress, port, cname, domain, self.TopLevelDomain))
                                        thread.start()
                                        time.sleep(0.5)
                                        break
                                    else:
                                        continue
