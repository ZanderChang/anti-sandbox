// anti-sandbox.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include <sysinfoapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <ShlObj.h>
#include <LM.h>
#include <TlHelp32.h>
#include <string.h>
#include <string>
#include <atlbase.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "netapi32.lib")

using namespace std;

// 检查管理员权限
BOOL isAdmin()
{
	BOOL bElevated = FALSE;
	HANDLE hToken = NULL;

	// Get current process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;

	// Retrieve token elevation information
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
	{
		if (dwRetLen == sizeof(tokenEle))
		{
			bElevated = tokenEle.TokenIsElevated;
		}
	}

	CloseHandle(hToken);
	return bElevated;
}

// 获取当前系统的时钟间隔值（频率倒数）
DWORD getSystemClockInterval()
{
	// Sysinternal的ClockRes
	// x86上最小0.500 ms，最大15.625 ms
	DWORD adjustment, clockInterval;
	BOOL  adjustmentDisabled;
	GetSystemTimeAdjustment(&adjustment,
		&clockInterval,
		&adjustmentDisabled);
	return clockInterval / 10000;
}

// 获取CPU核心数
// SYSTEM_INFO.dwNumberOfProcessors
BOOL checkPUCores(INT cores)
{
	INT i = 0;
	_asm { // x64编译模式下不支持__asm的汇编嵌入
		mov eax, dword ptr fs : [0x18]; // TEB
		mov eax, dword ptr ds : [eax + 0x30]; // PEB
		mov eax, dword ptr ds : [eax + 0x64];
		mov i, eax;
	}
	return i < cores;
}

// 获取CPU温度（需要管理员权限）
// Get-WMIObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi"
// https://docs.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
BOOL checkCPUTemperature()
{
	HRESULT hres;
	BOOL res = FALSE;

	do 
	{
		// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

		hres = CoInitializeEx(0, COINIT_MULTITHREADED);
		if (FAILED(hres))
		{
			// cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
			break;                  // Program has failed.
		}

		// Step 2: --------------------------------------------------
		// Set general COM security levels --------------------------

		hres = CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities 
			NULL                         // Reserved
		);

		if (FAILED(hres))
		{
			// cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
			CoUninitialize();
			break;                    // Program has failed.
		}

		// Step 3: ---------------------------------------------------
		// Obtain the initial locator to WMI -------------------------

		IWbemLocator *pLoc = NULL;

		hres = CoCreateInstance(
			CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, (LPVOID *)&pLoc);

		if (FAILED(hres))
		{
			// cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
			CoUninitialize();
			break;                 // Program has failed.
		}

		// Step 4: -----------------------------------------------------
		// Connect to WMI through the IWbemLocator::ConnectServer method

		IWbemServices *pSvc = NULL;

		// Connect to the root\cimv2 namespace with
		// the current user and obtain pointer pSvc
		// to make IWbemServices calls.
		hres = pLoc->ConnectServer(
			// _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
			_bstr_t(L"ROOT\\WMI"),
			NULL,                    // User name. NULL = current user
			NULL,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			NULL,                    // Security flags.
			0,                       // Authority (for example, Kerberos)
			0,                       // Context object 
			&pSvc                    // pointer to IWbemServices proxy
		);

		if (FAILED(hres))
		{
			// cout << "Could not connect. Error code = 0x" << hex << hres << endl;
			pLoc->Release();
			CoUninitialize();
			break;                // Program has failed.
		}

		// cout << "Connected to ROOT\\WMI WMI namespace" << endl;

		// Step 5: --------------------------------------------------
		// Set security levels on the proxy -------------------------

		hres = CoSetProxyBlanket(
			pSvc,                        // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			NULL,                        // Server principal name 
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities 
		);

		if (FAILED(hres))
		{
			// cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			break;               // Program has failed.
		}

		// Step 6: --------------------------------------------------
		// Use the IWbemServices pointer to make requests of WMI ----

		// For example, get the name of the operating system
		IEnumWbemClassObject* pEnumerator = NULL;
		hres = pSvc->ExecQuery(
			bstr_t("WQL"),
			bstr_t("SELECT * FROM MSAcpi_ThermalZoneTemperature"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			NULL,
			&pEnumerator);

		if (FAILED(hres))
		{
			// cout << "Query for operating system name failed." << " Error code = 0x" << hex << hres << endl;
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			break;               // Program has failed.
		}

		// Step 7: -------------------------------------------------
		// Get the data from the query in step 6 -------------------

		IWbemClassObject *pclsObj = NULL;
		ULONG uReturn = 0;

		while (pEnumerator)
		{
			HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

			if (0 == uReturn)
			{
				break;
			}

			VARIANT vtProp;

			// Get the value of the Name property
			hr = pclsObj->Get(L"CurrentTemperature", 0, &vtProp, 0, 0);
			res = vtProp.ullVal / 10.0 - 273.15; // 开氏转摄氏
			VariantClear(&vtProp);

			pclsObj->Release();
		}

		// Cleanup
		// ========

		pSvc->Release();
		pLoc->Release();
		pEnumerator->Release();
		CoUninitialize();

	} while (false);

	return res;
}

// ??
BOOL checkDomain()
{
	BOOL ret = FALSE;
	DWORD dwLevel = 100;
	LPWKSTA_INFO_100 pBuf = NULL;
	NET_API_STATUS nStatus;
	nStatus = NetWkstaGetInfo(NULL, dwLevel, (LPBYTE *)&pBuf);
	if (nStatus == NERR_Success)
	{
		char response[512];
		wcstombs(response, pBuf->wki100_langroup, 500); // 该主机的全称域名FQDN
		char workgroup[] = "WORKGROUP";
		if (strcmp(response, workgroup)) // returns 0 if identical
		{
			ret = TRUE;
		}
		else
		{
			ret = FALSE;
		}
	}
	return ret;
}

// 检测MAC地址
// 00:05:69、00:0c:29、00:50:56开始的MAC地址与VMware相对应
// 00:03:ff开始的MAC地址与virtualpc对应
// 08:00:27开始的MAC地址与virtualbox对应
BOOL checkMAC() 
{
	BOOL bRet = FALSE;

	do 
	{
		char buffer[128];
		char result[1024 * 50] = "";
		char MAC[5][9] = { "08-00-27", "00-03-FF", "00-05-69", "00-0C-29", "00-50-56" };
		FILE *pipe = _popen("ipconfig /all", "r");
		if (!pipe)
		{
			break;
		}

		while (!feof(pipe))
		{
			if (fgets(buffer, 128, pipe))
			{
				strcat(result, buffer);
			}
		}
		_pclose(pipe);

		for (int i = 0; i < 5; ++i)
		{
			if (strstr(result, MAC[i]))
			{
				bRet = TRUE;
				break;
			}
		}
		
	} while (FALSE);

	return bRet;
}

// 检测内存大小
// SELECT * FROM Win32_ComputerSystem
// TotalPhysicalMemory
BOOL checkMemory(INT memory) 
{
	_MEMORYSTATUSEX mst;
	DWORDLONG d_size = memory * 1024 * 1024 * 1024;
	mst.dwLength = sizeof(mst);
	GlobalMemoryStatusEx(&mst);
	if (mst.ullTotalPhys < d_size) // B
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 检测磁盘大小（需要管理员权限）
// SELECT * FROM Win32_LogicalDisk
// Size
BOOL checkPhyDisk(INT disk)
{
	HANDLE hDrive;
	GET_LENGTH_INFORMATION size;
	DWORD lpBytes;
	hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDrive);
		return FALSE;
	}
	bool result = DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size, sizeof(GET_LENGTH_INFORMATION), &lpBytes, NULL);
	CloseHandle(hDrive);

	if ((size.Length.QuadPart / 1073741824) > disk)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 检测进程
int check(char* name)
{
	const char* list[3] = { "VBoxService.exe", "VBoxTray.exe", "vmware.exe"};
	for (int i = 0; i < 3; ++i)
	{
		if (strcmp(name, list[i]) == 0)
		{
			return -1;
		}
	}
	return 0;
}
BOOL checkProcess() 
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	while (bResult) 
	{
		char sz_Name[MAX_PATH] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, sz_Name, sizeof(sz_Name), NULL, NULL);
		if (check(sz_Name) == -1)
		{
			return FALSE;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	return TRUE;
}

// 检测注册表和文件路径（可能需要管理员权限）
BOOL checkPath()
{
	HKEY hkey;
	if (RegOpenKeyA(HKEY_CLASSES_ROOT, "\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS || 
		RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", &hkey) == ERROR_SUCCESS)
	{
		return TRUE;
	}

	// 文件夹路径
	if (!PathIsDirectoryA("C:\\Program Files\\VMware\\VMware Tools\\") || 
		!PathIsDirectoryA("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\"))
	{
		return TRUE;
	}

	return FALSE;
}

// 检测服务
BOOL checkSerivce()
{
	int menu = 0;
	// 打开系统服务控制器    
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (SCMan == NULL)
	{
		return FALSE;
	}
	// 保存系统服务的结构  
	LPENUM_SERVICE_STATUSA service_status;
	DWORD cbBytesNeeded = NULL;
	DWORD ServicesReturned = NULL;
	DWORD ResumeHandle = NULL;
	service_status = (LPENUM_SERVICE_STATUSA)LocalAlloc(LPTR, 1024 * 64);
	// 获取系统服务的简单信息    
	bool ESS = EnumServicesStatusA(SCMan, //系统服务句柄    
		SERVICE_WIN32, //服务的类型    
		SERVICE_STATE_ALL,  //服务的状态    
		(LPENUM_SERVICE_STATUSA)service_status,  //输出参数，系统服务的结构    
		1024 * 64,  //结构的大小    
		&cbBytesNeeded, //输出参数，接收返回所需的服务    
		&ServicesReturned, //输出参数，接收返回服务的数量    
		&ResumeHandle //输入输出参数，第一次调用必须为0，返回为0代表成功
	);
	if (ESS == NULL)
	{
		return FALSE;
	}
	for (int i = 0; i < ServicesReturned; i++)
	{
		if (strstr(service_status[i].lpDisplayName, "VMware Tools") != NULL || strstr(service_status[i].lpDisplayName, "VMware 物理磁盘助手服务") != NULL || strstr(service_status[i].lpDisplayName, "Virtual Machine") != NULL || strstr(service_status[i].lpDisplayName, "VirtualBox Guest") != NULL)
		{
			return TRUE;
		}
	}
	//关闭服务管理器的句柄   
	CloseServiceHandle(SCMan);
	return FALSE;
}

// 检测开机时间
BOOL checkUptime()
{
	DWORD UpTime = GetTickCount();
	if (UpTime < 3600000)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 使用CPUID指令
BOOL checkCPUID()
{
	DWORD dw_ecx;
	bool bFlag = true;
	_asm {
		pushad; // 将32位通用寄存器压入堆栈
		pushfd; // 将32位标志寄存器EFLAGS压入堆栈
		mov eax, 1; // Processor Info and Feature Bits
		cpuid; // 根据传递给EAX寄存器的值，将对应的信息返回给EAX、EBX、ECX、EDX
		mov dw_ecx, ecx; // Feature Information
		and ecx, 0x80000000; // Hypervisor present (always zero on physical CPUs)
		test ecx, ecx; // AND为0的话ZF=1
		setz[bFlag]; // ZF为1的话bFlag=1
		popfd;
		popad;
	}
	if (bFlag) // 真实机器
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

// 检测TEMP目录下的文件数量
BOOL checkTemp(INT aNum)
{
	int file_count = 0;
	DWORD dwRet;
	LPSTR pszOldVal;
	pszOldVal = (LPSTR)malloc(MAX_PATH * sizeof(char));
	dwRet = GetEnvironmentVariableA("TEMP", pszOldVal, MAX_PATH);

	std::string stdstr = pszOldVal;
	stdstr += "\\*";

	LPSTR s = const_cast<char *>(stdstr.c_str());

	WIN32_FIND_DATAA data;
	HANDLE hFind = FindFirstFileA(s, &data);
	if (hFind != INVALID_HANDLE_VALUE) 
	{
		do 
		{
			file_count++;
		} while (FindNextFileA(hFind, &data));
		FindClose(hFind);
	}

	if (file_count < aNum)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 检测主板序列号、主机型号、系统盘所在磁盘名称等硬件信息
// WMI ROOT\\CIMV2
BOOL ManageWMIInfo(string &result, string table, wstring wcol)
{
	char bord[1024];
	HRESULT hres = CoInitialize(0);
   
	IWbemLocator *pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc
	);

	if (FAILED(hres))
	{
		CoUninitialize();
		return FALSE;
	}
  
	IWbemServices *pSvc = NULL;
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace  
		NULL, // User name. NULL = current user  
		NULL, // User password. NULL = current  
		0, // Locale. NULL indicates current  
		NULL, // Security flags.  
		0, // Authority (e.g. Kerberos)  
		0, // Context object   
		&pSvc // pointer to IWbemServices proxy  
	);
	if (FAILED(hres))
	{
		pLoc->Release();
		CoUninitialize();
		return FALSE;
	}
   
	hres = CoSetProxyBlanket(
		pSvc, // Indicates the proxy to set  
		RPC_C_AUTHN_WINNT, // RPC_C_AUTHN_xxx  
		RPC_C_AUTHZ_NONE, // RPC_C_AUTHZ_xxx  
		NULL, // Server principal name   
		RPC_C_AUTHN_LEVEL_CALL, // RPC_C_AUTHN_LEVEL_xxx   
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx  
		NULL, // client identity  
		EOAC_NONE // proxy capabilities   
	);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	string select = "SELECT * FROM " + table;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(select.c_str()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);
	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	ULONG uReturn = 0;
	IWbemClassObject *pclsObj;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}
		VARIANT vtProp;
		VariantInit(&vtProp);
		hr = pclsObj->Get(wcol.c_str(), 0, &vtProp, 0, 0);
		if (!FAILED(hr))
		{
			CW2A tmpstr(vtProp.bstrVal);
			strcpy_s(bord, 200, tmpstr);
			result = bord;
		}
		VariantClear(&vtProp);
	}

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	pclsObj->Release();
	CoUninitialize();

	return TRUE;
}
BOOL checkHardwareInfo()
{
	BOOL bRet = TRUE;

	do 
	{
		string ret;
		ManageWMIInfo(ret, "Win32_BaseBoard", L"SerialNumber");
		if (ret == "None")
		{
			break;
		}

		ManageWMIInfo(ret, "Win32_DiskDrive", L"Caption");
		if (ret.find("VMware") != string::npos || ret.find("VBOX") != string::npos || ret.find("Virtual HD") != string::npos)
		{
			break;
		}

		ManageWMIInfo(ret, "Win32_computersystem", L"Model");
		if (ret.find("VMware") != string::npos || ret.find("VirtualBox") != string::npos || ret.find("Virtual Machine") != string::npos)
		{
			break;
		}

		bRet = FALSE;
	} while (FALSE);

	return bRet;
}

// 根据代码运行时间差来判断（需指定时间差）
BOOL checkSpeed()
{
	__asm
	{
		rdtsc
		xchg ebx, eax
		rdtsc
		sub eax, ebx
		cmp eax, 0xFF
		jg detected
	}
	return FALSE;
detected:
	return TRUE;
}

int main()
{
	// 需要管理员权限
	if (isAdmin() && IsUserAnAdmin())
	{
		printf("[+] Admin\n");
		checkCPUTemperature();
		checkPhyDisk(250);
	}
	else // 不需要管理员权限
	{
		printf("[+] Not Admin\n");
		checkPUCores(4);
		checkDomain();
		checkMemory(4);
		checkCPUID();
	}

	return 0;
}

