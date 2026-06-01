// TwsLoginHelper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <atlbase.h>
#include <atlstr.h>
#include <tchar.h>
#include <iostream>
#include <list>
#include <string>
#include <vector>
#include <functional>
#include <windows.h>
#include "AccessBridgeCalls.h"

#pragma warning(disable:6255)

using namespace std;

extern "C" AccessBridgeFPs theAccessBridge;
string bitwardenId;
static string sessionKey;

typedef struct BRIDGENODE {
    long vmId;
    AccessibleContext ctx;
    AccessibleContextInfo info;
} BridgeNode;

struct FINDTWSWINDOWPARAMS {
    LPCTSTR windowTitle;
    HWND wnd;
};

HWND FindTwsWindow(LPCTSTR windowTitle)
{
    HWND wnd = FindWindow(_T("SunAwtFrame"), _T("Login"));

    if (wnd != NULL)
    {
        FINDTWSWINDOWPARAMS args = { .windowTitle = windowTitle };
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            FINDTWSWINDOWPARAMS* args = reinterpret_cast<FINDTWSWINDOWPARAMS*>(lParam);

            if (!IsWindowVisible(hwnd)) return TRUE;

            TCHAR className[256];
            GetClassName(hwnd, className, sizeof(className) / sizeof(TCHAR));
            if (_tcscmp(className, _T("SunAwtFrame")) == 0)
            {
                TCHAR foundWindowTitle[256];
                GetWindowText(hwnd, foundWindowTitle, sizeof(foundWindowTitle) / sizeof(TCHAR));
                if (_tcscmp(foundWindowTitle, args->windowTitle) == 0)
                {
                    args->wnd = hwnd;
                    return FALSE; // Stop enumeration
                }
            }
            return TRUE; // Continue enumeration
            }, reinterpret_cast<LPARAM>(&args));

            return args.wnd;
    }

    return NULL;
}

void DoEvents()
{
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void WalkNodes(long vmId, AccessibleContext ctx, list<BridgeNode>& nodes)
{
    nodes.push_back({ vmId, ctx });
    BridgeNode& node = nodes.back();

    if (!GetAccessibleContextInfo(vmId, ctx, &node.info)) return;
    for (int i = 0; i < node.info.childrenCount; ++i)
    {
        AccessibleContext childCtx = GetAccessibleChildFromContext(vmId, ctx, i);
        if (childCtx != 0)
        {
            WalkNodes(vmId, childCtx, nodes);
        }
    }
}

bool FindNode(const list<BridgeNode>& nodes, const wchar_t* name, const wchar_t* role, const wchar_t* description, BridgeNode& result)
{
    for (const BridgeNode& node : nodes)
    {
        AccessibleContextInfo info;
        if (!GetAccessibleContextInfo(node.vmId, node.ctx, &info)) continue;
        if (wcscmp(info.name, name) == 0 && 
            wcscmp(info.role_en_US, role) == 0 &&
            (description == NULL || wcscmp(info.description, description) == 0))
        {
            result = node;
            return true;
        }
    }
    return false;
}

string RunCommandCapture(const string& cmd)
{
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return "";

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = {};

    string cmdline = "cmd.exe /C " + cmd;

    if (!CreateProcessA(
        NULL,
        cmdline.data(),
        NULL, NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si,
        &pi))
    {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "";
    }

    CloseHandle(hWrite);

    string output;
    char buffer[4096];
    DWORD bytesRead;

    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0)
        output.append(buffer, bytesRead);

    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

string ExtractSessionKey(const std::string& output)
{
    const std::string marker = "BW_SESSION=\"";
    size_t pos = output.find(marker);
    if (pos == std::string::npos)
        return "";

    pos += marker.size(); // move past BW_SESSION="

    size_t end = output.find('"', pos);
    if (end == std::string::npos)
        return "";

    return output.substr(pos, end - pos);
}

string UnlockAndGetSessionKey()
{
    if (!sessionKey.empty()) return sessionKey;

    string output = RunCommandCapture("bwbio unlock");

    sessionKey = ExtractSessionKey(output);

    return sessionKey;
}

void ClickButton(const BridgeNode& buttonNode)
{
    jint failure;
    AccessibleActionsToDo todo = { .actionsCount = 1 };
    wcsncpy_s(todo.actions[0].name, _countof(todo.actions[0].name), L"click", _TRUNCATE);
    doAccessibleActions(buttonNode.vmId, buttonNode.ctx, &todo, &failure);
}

void DumpNodes(const list<BridgeNode>& nodes)
{
    USES_CONVERSION;

    for (const BridgeNode& node : nodes)
    {
        cout << hex << node.ctx << " name: " << W2A(node.info.name) << " role: " << W2A(node.info.role_en_US) << endl;
    }
}

void WaitUntilTotpHasAtLeast(int nSeconds)
{
    while (true)
    {
        time_t now = time(nullptr);
        int remaining = 30 - (now % 30);

        cout << "TOTP has " << remaining << "s" << "remaining" << endl;

        if (remaining >= nSeconds)
            return;

        cout << "Waiting " << remaining + 1 << " for next TOTP interval";

        // Not enough time left — wait until next window
        int sleepMs = (remaining + 1) * 1000; // +1 to cross boundary safely
        Sleep(sleepMs);
    }
}

bool SubmitLogin(const list<BridgeNode>& nodes)
{
    USES_CONVERSION;

    BridgeNode loginTextNode;
    BridgeNode passwordTextNode;
    BridgeNode loginButtonNode;

    if (!FindNode(nodes, L"Username", L"text", NULL, loginTextNode) ||
        !FindNode(nodes, L"Password", L"password text", NULL, passwordTextNode) ||
        !FindNode(nodes, L"Log In", L"push button", NULL, loginButtonNode))
    {
        //DumpNodes(nodes);
        return false;
    }

    cout << "Found Login Textbox: " << hex << loginTextNode.ctx << " name: " << W2A(loginTextNode.info.name) << endl;
    cout << "Found Password Textbox: " << hex << passwordTextNode.ctx << " name: " << W2A(passwordTextNode.info.name) << endl;
    cout << "Found Login Button: " << hex << loginButtonNode.ctx << " name: " << W2A(loginButtonNode.info.name) << endl;

    string sessionKey = UnlockAndGetSessionKey();

    cout << "Retrieved session key: " << sessionKey << endl;

    auto username = RunCommandCapture("bw get username " + bitwardenId + " --session " + sessionKey);
    cout << "Retrieved username: " << username << endl;
    auto password = RunCommandCapture("bw get password " + bitwardenId + " --session " + sessionKey);
    cout << "Retrieved password: " << password << endl;

    setTextContents(loginTextNode.vmId, loginTextNode.ctx, A2W(username.c_str()));
    setTextContents(passwordTextNode.vmId, passwordTextNode.ctx, A2W(password.c_str()));

    ClickButton(loginButtonNode);

    return true;
}

bool SubmitAppCode(const list<BridgeNode>& nodes)
{
    USES_CONVERSION;

    BridgeNode appCodeLabelNode;
    BridgeNode appCodeTextNode;
    BridgeNode okButtonNode;

    if (!FindNode(nodes, L"Enter Mobile Authenticator app code", L"label", NULL, appCodeLabelNode) ||
        !FindNode(nodes, L"", L"text", L"", appCodeTextNode) ||
        !FindNode(nodes, L"OK", L"push button", NULL, okButtonNode))
    {
        DumpNodes(nodes);
        return false;
    }

    //DumpNodes(nodes);

    WaitUntilTotpHasAtLeast(5);

    cout << "Found App Code Label: " << hex << appCodeLabelNode.ctx << " name: " << W2A(appCodeLabelNode.info.name) << endl;
    cout << "Found App Code Textbox: " << hex << appCodeTextNode.ctx << " name: " << W2A(appCodeTextNode.info.name) << endl;
    cout << "Found OK Button: " << hex << okButtonNode.ctx << " name: " << W2A(okButtonNode.info.name) << endl;   

    string sessionKey = UnlockAndGetSessionKey();
    auto appCode = RunCommandCapture("bw get totp " + bitwardenId + " --session " + sessionKey);
    cout << "App Code: " << appCode << endl;
    setTextContents(appCodeTextNode.vmId, appCodeTextNode.ctx, A2W(appCode.c_str()));
    ClickButton(okButtonNode);
    auto locked = RunCommandCapture("bw lock");
    cout << "Locked Bitwarden CLI: " << locked << endl;

    sessionKey.clear();

    return true;
}

bool DoLogin(HWND wnd, LPCSTR windowName, function<bool(const std::list<BridgeNode>&)> func)
{
    while (!IsJavaWindow(wnd))
    {
        DoEvents();
        Sleep(500);
    }

    cout << "Found " << windowName << ": " << hex << wnd << endl;

    long vmId;
    AccessibleContext ctx;

    if (!GetAccessibleContextFromHWND(wnd, &vmId, &ctx)) return true;

    cout << "Got VM for TWS Login Window: " << hex << vmId << endl;

    list<BridgeNode> nodes;

    WalkNodes(vmId, ctx, nodes);

    cout << "Total nodes found: " << dec << nodes.size() << endl;

    func(nodes);

    for (const BridgeNode& node : nodes)
    {
        ReleaseJavaObject(node.vmId, node.ctx);
    }

    return true;
}

bool DoLogin()
{
    cout << "Waiting for TWS Login Window..." << endl;

    HWND twsLoginWindow = NULL;
    HWND twsAppCodeWindow = NULL;
    while ((twsLoginWindow = FindTwsWindow(_T("Login"))) == NULL &&
        (twsAppCodeWindow = FindTwsWindow(_T("Second Factor Authentication"))) == NULL)
    {
        Sleep(2000);
    }

    if (twsLoginWindow != NULL)
    {
        return DoLogin(twsLoginWindow, "TWS Login", SubmitLogin);
    }
    if (twsAppCodeWindow != NULL)
    {
        return DoLogin(twsAppCodeWindow, "App Code", SubmitAppCode);
    }

    return false;
}


int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        cerr << "Usage: TwsLoginHelper.exe <bitwarden_tws_login_name_or_id>" << endl;
        return 1;
    }

    bitwardenId = argv[1];

    if (!initializeAccessBridge()) {
        cerr << "Failed to initialize Access Bridge" << endl;
        return 1;
    }
    theAccessBridge.Windows_run();

    while (1)
    {
        if (!DoLogin()) Sleep(4000);
        Sleep(1000);
    }
}

