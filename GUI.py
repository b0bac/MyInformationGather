import os
import tkinter
import threading
from CoreUtils import Scanner
from tkinter import ttk, messagebox


def ShowMessageBox(title, message):
    messagebox.showinfo(title, message)

class GUIShell:
    def __init__(self):
        self.Windows = tkinter.Tk()
        self.Windows.geometry("1365x770")
        self.Windows.title("土拨鼠渗透测试信息收集器v1.0")
        self.TopLevelDomain = None
        self.VirusTotalToken = None
        self.PortFlag = 1
        self.PortFlagVar = tkinter.IntVar()
        self.Columns = ['1', '2', '3', '4', '5', '6', '7']
        self.ScrollBar = tkinter.Scrollbar(self.Windows)
        self.TopLevelDomainLabel = tkinter.Label(self.Windows, text="请输入目标主域名:")
        self.TopLevelDomainInput = tkinter.Entry(self.Windows, width=40)
        self.VirusTotalTokenLabel = tkinter.Label(self.Windows, text="请输入Virustotal接口令牌:")
        self.VirusTotalTokenInput = tkinter.Entry(self.Windows, width=40)
        self.AllPortLabel = tkinter.Label(self.Windows, text="全端口")
        self.AllPortEnable = tkinter.Radiobutton(self.Windows, value=1, variable=self.PortFlagVar,
                                                 command=self.SetPortFlag)
        self.CommonPortLabel = tkinter.Label(self.Windows, text="常用端口")
        self.CommonPortEnable = tkinter.Radiobutton(self.Windows, value=2, variable=self.PortFlagVar,
                                                    command=self.SetPortFlag)
        self.ConsequenceBox = ttk.Treeview(self.Windows, columns=self.Columns, yscrollcommand=self.ScrollBar.set,
                                           show='headings')
        self.ConsequenceBox.column('1', width=50, anchor='center')
        self.ConsequenceBox.column('2', width=200, anchor='center')
        self.ConsequenceBox.column('3', width=250, anchor='center')
        self.ConsequenceBox.column('4', width=250, anchor='center')
        self.ConsequenceBox.column('5', width=250, anchor='center')
        self.ConsequenceBox.column('6', width=100, anchor='center')
        self.ConsequenceBox.column('7', width=250, anchor='center')
        self.ConsequenceBox.heading('1', text='序号')
        self.ConsequenceBox.heading('2', text='主域名')
        self.ConsequenceBox.heading('3', text='子域名')
        self.ConsequenceBox.heading('4', text='CNAME')
        self.ConsequenceBox.heading('5', text='IP地址')
        self.ConsequenceBox.heading('6', text='端口号')
        self.ConsequenceBox.heading('7', text='页面标题')
        self.ScrollBar.config(command=self.ConsequenceBox.yview)
        self.LogText = tkinter.Text(self.Windows, height=35, relief=tkinter.RAISED, width=192, bg="gray")
        self.LogText.config(state="disable")
        self.ScanButton = tkinter.Button(self.Windows, text='开始收集', bg='green', command=self.StartScan)
        self.Banner = tkinter.Label(self.Windows, text="渗透的本质是信息收集  土拨鼠渗透测试自动化信息收集工具V1.0版本 沟通请联系微信 lab_hacker",
                                    fg='red')
        self.ThreadSizeLabel = tkinter.Label(self.Windows, text="线程数:")
        self.ThreadSize = 10
        self.ThreadSizeVar = tkinter.IntVar()
        self.ThreadSelector = tkinter.OptionMenu(self.Windows, self.ThreadSizeVar, 10, 20, 30, 40, 50)
        self.ConsequenceDownloadToFileButton = tkinter.Button(self.Windows, text='结果下载', bg='green',
                                                              command=self.ConsequenceFileDownload)
        self.Scanner = None
        self.BeginFlag = False

    def ConsequenceFileDownload(self):
        if self.BeginFlag:
            filename = str(os.getcwd()) + '/' + self.Scanner.filename
            ShowMessageBox("文件下载", filename)
        else:
            ShowMessageBox("文件下载", "尚未开始收集信息")

    def Graph(self):
        self.ScrollBar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
        self.TopLevelDomainLabel.place(x=10, y=20)
        self.TopLevelDomainInput.place(x=130, y=20)
        self.VirusTotalTokenLabel.place(x=510, y=20)
        self.VirusTotalTokenInput.place(x=680, y=20)
        self.AllPortLabel.place(x=1065, y=20)
        self.AllPortEnable.place(x=1110, y=20)
        self.CommonPortLabel.place(x=1140, y=20)
        self.CommonPortEnable.place(x=1195, y=20)
        self.ScanButton.place(x=1245, y=18)
        self.ConsequenceBox.place(x=0, y=60)
        self.LogText.place(x=0, y=270)
        self.Banner.place(x=350, y=740)
        self.ThreadSizeLabel.place(x=10, y=740)
        self.ThreadSelector.place(x=100, y=740)
        self.ConsequenceDownloadToFileButton.place(x=1200, y=738)
        self.Windows.mainloop()

    def SetPortFlag(self):
        self.PortFlag = self.PortFlagVar.get()

    def StartScan(self):
        self.TopLevelDomain = self.TopLevelDomainInput.get()
        self.VirusTotalToken = self.VirusTotalTokenInput.get()
        self.SetPortFlag()
        self.ThreadSize = self.ThreadSizeVar.get()
        if self.ThreadSize < 10:
            self.ThreadSize = 10
        ShowMessageBox("消息提示", "开始收集信息")
        self.Scanner = Scanner(self.VirusTotalToken, self.TopLevelDomain, self.PortFlag, self.ConsequenceBox,
                               self.ThreadSize, self.LogText)
        self.BeginFlag = True
        thread = threading.Thread(target=self.Scanner.Scan)
        thread.start()


if __name__ == "__main__":
    ScannerGUI = GUIShell()
    ScannerGUI.Graph()