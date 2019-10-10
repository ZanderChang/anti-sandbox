# anti-sandbox
Windows对抗沙箱和虚拟机的方法总结

## 方法总结
|函数|功能|备注|
|-|-|-|
|checkCPUCores|检查CPU核心数||
|checkCPUTemperature|检查CPU温度|需要管理员权限|
|checkDomain|检测域名||
|checkMAC|检测MAC地址||
|checkMemory|检测内存大小||
|checkPhyDisk|检测磁盘大小|需要管理员权限|
|checkProcess|检测进程||
|checkPath|检测注册表和文件路径|可能需要管理员权限|
|checkSerivce|检测服务||
|checkUptime|检测开机时间||
|checkCPUID|使用`CPUID`指令||
|checkTempDir|检测`TEMP`目录下的文件数量||
|checkHardwareInfo|检测主板序列号、主机型号、系统盘所在磁盘名称等硬件信息||
|checkSpeed|检测代码运行时间差||
|checkNoPill|使用`sgdt`和`sldt`指令|VMware|
|checkIOPort|检测IO端口`in`|VMware|
|checkTSS|检查当前正在运行的任务的任务状态段`TSS`|VMware|
|checkUnISA|检测无效指令|VirtualPC|

## 其它方法
* 如果是DOC的攻击方式则可以检测最近打开的文件数量（正常情况下应该大于3个）
  * 判断MRU（Most Recently Used，最近使用）
  * \HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\User MRU

## 参考
* https://github.com/sharepub/CheckVM-Sandbox
* https://zhuanlan.zhihu.com/p/35423785
* https://www.anquanke.com/post/id/186218