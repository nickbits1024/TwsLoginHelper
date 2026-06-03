// TwsLoginHelper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <tchar.h>
#include <iostream>
#include <array>
#include <functional>
#include <list>
#include <string>
#include <windows.h>
#include <vcclr.h>
#include "AccessBridgeCalls.h"

#pragma warning(disable: 6262)

using namespace std;
using namespace System;
using namespace System::Diagnostics;
using namespace System::Net;
using namespace System::Text;
using namespace Newtonsoft::Json;
using namespace Newtonsoft::Json::Linq;

extern "C" AccessBridgeFPs theAccessBridge;
wstring g_bitwardenId;
string g_sessionKey;
HANDLE g_serveProcessHandle;
int g_serverPort;

struct BridgeNode
{
    long vmId;
    AccessibleContext ctx;
    AccessibleContextInfo info;
};

struct FINDTWSWINDOWPARAMS {
    LPCTSTR windowTitle;
    HWND wnd;
};

JObject^ BwCliGetJson(const wstring& url)
{
    WebClient^ client = gcnew WebClient();

    wstring url2 = L"http://localhost:" + to_wstring(g_serverPort) + L"/" + url;
    String^ json = client->DownloadString(gcnew String(url2.c_str()));

    return JObject::Parse(json);
}

JObject^ BwCliPostJson(const wstring& url)
{
    WebClient^ client = gcnew WebClient();

    wstring url2 = L"http://localhost:" + to_wstring(g_serverPort) + L"/" + url;

    String^ json = client->UploadString(gcnew String(url2.c_str()), String::Empty);

    return JObject::Parse(json);
}

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

std::wstring ToWString(const std::string& s)
{
    return std::wstring(s.begin(), s.end());
}

HANDLE RunBwCommand(const std::string& cmd, const string& sessionKey)
{
    //pin_ptr<wchar_t> sessionKeyPtr = PtrToStringChars(sessionKey);
    //pin_ptr<wchar_t> cmdPtr = PtrToStringChars(cmd);

    wstring bwSession = L"BW_SESSION=" + ToWString(sessionKey);

    wstring env;
    LPWCH envBlock = GetEnvironmentStringsW();
    if (envBlock != NULL)
    {
        for (LPWCH p = envBlock; *p; )
        {
            size_t len = wcslen(p);
            env.append(p, len + 1); // include null terminator
            p += len + 1;
        }
    }
    //env.reserve(bwSession.size() + 2);
    env.append(bwSession);
    env.push_back('\0'); // End of BW_SESSION variable
    env.push_back('\0'); // End of the environment block

    STARTUPINFOA si{};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi{};

    LPCWSTR test = env.c_str();

    //string cmdline = "cmd.exe /C " + cmd;
    string cmdline = cmd;

    // Create process with custom environment
    BOOL ok = CreateProcessA(
        nullptr,                       // app name
        const_cast<LPSTR>(cmdline.c_str()), // command line
        nullptr,                       // process security
        nullptr,                       // thread security
        TRUE,                          // inherit handles
        CREATE_UNICODE_ENVIRONMENT, //CREATE_NO_WINDOW,              
        (LPVOID)env.c_str(),           // environment block
        nullptr,                       // current directory
        &si,
        &pi
    );

    if (!ok)
        return nullptr;

    cout << "Started process " << dec << pi.dwProcessId << " for command: " << cmd << endl;

    // We return the process handle; caller must CloseHandle() when done
    CloseHandle(pi.hThread);
    return pi.hProcess;
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

    //string cmdline = "cmd.exe /C " + cmd;
    string cmdline = cmd;

    if (!CreateProcessA(
        NULL,
        const_cast<LPSTR>(cmdline.c_str()),
        NULL, NULL,
        TRUE,
        0,
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
    const string marker = "BW_SESSION=\"";
    size_t pos = output.find(marker);
    if (pos == string::npos)
        return "";

    pos += marker.size(); // move past BW_SESSION="

    size_t end = output.find('"', pos);
    if (end == string::npos)
        return "";

    return output.substr(pos, end - pos);
}

string UnlockAndGetSessionKey(HANDLE& serveProcess)
{
    if (!g_sessionKey.empty())
    {
        serveProcess = g_serveProcessHandle;
        return g_sessionKey;
    }

    if (FindWindow(_T("Credential Dialog Xaml Host"), _T("Windows Security")) != NULL)
    {
        cerr << "Bitwarden CLI is locked and showing Windows Security prompt, cannot proceed" << endl;
        return "";
    }

    auto output = RunCommandCapture("cmd /c bwbio unlock");
    g_sessionKey = ExtractSessionKey(output);
    if (g_sessionKey.empty())
    {
        cerr << "Failed to extract session key from bwbio unlock output" << endl;
        return "";
    }

    g_serveProcessHandle = RunBwCommand("bw serve --port " + to_string(g_serverPort), g_sessionKey);

    return g_sessionKey;
}

void ClickButton(const BridgeNode& buttonNode)
{
    //return;
    jint failure;
    AccessibleActionsToDo todo = { .actionsCount = 1 };
    wcsncpy_s(todo.actions[0].name, _countof(todo.actions[0].name), L"click", _TRUNCATE);
    doAccessibleActions(buttonNode.vmId, buttonNode.ctx, &todo, &failure);
}

void DumpNodes(const list<BridgeNode>& nodes)
{
    for (const BridgeNode& node : nodes)
    {
        wcout << hex << node.ctx << " name: " << node.info.name << " role: " << node.info.role_en_US << endl;
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

static bool SubmitLogin(const list<BridgeNode>& nodes)
{
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

    wcout << L"Found Login Textbox: " << hex << loginTextNode.ctx << L" name: " << loginTextNode.info.name << endl;
    wcout << L"Found Password Textbox: " << hex << passwordTextNode.ctx << L" name: " << passwordTextNode.info.name << endl;
    wcout << L"Found Login Button: " << hex << loginButtonNode.ctx << L" name: " << loginButtonNode.info.name << endl;

    HANDLE serveProcess;

    string sessionKey = UnlockAndGetSessionKey(serveProcess);
    if (sessionKey.empty()) return true;

    cout << "Retrieved session key: " << sessionKey << endl;

    auto loginResponse = BwCliGetJson(L"object/item/" + g_bitwardenId);

    //auto username = RunCommandCapture("bw get username " + g_bitwardenId + " --session " + sessionKey);
    //auto password = RunCommandCapture("bw get password " + g_bitwardenId + " --session " + sessionKey);
    auto login = loginResponse->Value<JObject^>("data")->Value<JObject^>("login");
    auto username = login->Value<String^>("username");
    auto password = login->Value<String^>("password");

    pin_ptr<const wchar_t> usernamePtr = PtrToStringChars(username);
    pin_ptr<const wchar_t> passwordPtr = PtrToStringChars(password);
    String^ stars = gcnew String(L'*', password->Length);
    pin_ptr<const wchar_t> starsPtr = PtrToStringChars(stars);

    wcout << "Retrieved username: " << static_cast<const wchar_t*>(usernamePtr) << endl;
    wcout << "Retrieved password: " << static_cast<const wchar_t*>(starsPtr) << endl;

    setTextContents(loginTextNode.vmId, loginTextNode.ctx, usernamePtr);
    setTextContents(passwordTextNode.vmId, passwordTextNode.ctx, passwordPtr);

    ClickButton(loginButtonNode);

    return true;
}

static bool SubmitAppCode(const list<BridgeNode>& nodes)
{
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

    wcout << L"Found App Code Label: " << hex << appCodeLabelNode.ctx << L" name: " << appCodeLabelNode.info.name << endl;
    wcout << L"Found App Code Textbox: " << hex << appCodeTextNode.ctx << L" name: " << appCodeTextNode.info.name << endl;
    wcout << L"Found OK Button: " << hex << okButtonNode.ctx << L" name: " << okButtonNode.info.name << endl;

    HANDLE serveProcess;
    string sessionKey = UnlockAndGetSessionKey(serveProcess);
    if (sessionKey.empty()) return true;
    //string appCode = RunCommandCapture("bw get totp " + g_bitwardenId + " --session " + sessionKey);

    WaitUntilTotpHasAtLeast(2);

    auto totpResponse = BwCliGetJson(L"object/totp/" + g_bitwardenId);
    auto appCode = totpResponse->Value<JObject^>("data")->Value<String^>("data");

    pin_ptr<const wchar_t> appCodePtr = PtrToStringChars(appCode);
    wcout << L"App Code: " << static_cast<const wchar_t*>(appCodePtr) << endl;

    setTextContents(appCodeTextNode.vmId, appCodeTextNode.ctx, appCodePtr);
    ClickButton(okButtonNode);
    //auto locked = RunCommandCapture("bw lock");
    auto lockedReponse = BwCliPostJson(L"lock");

    pin_ptr <const wchar_t> lockedJsonPtr = PtrToStringChars(lockedReponse->ToString(Formatting::Indented));

    wcout << L"Locked Bitwarden CLI: " << static_cast<const wchar_t*>(lockedJsonPtr) << endl;

    BOOL terminated = TerminateProcess(g_serveProcessHandle, 0);
    int error = GetLastError();
    CloseHandle(g_serveProcessHandle);
    g_serveProcessHandle = NULL;
    g_sessionKey.clear();

    return true;
}

bool DoLogin(HWND wnd, LPCSTR windowName, function<bool(const std::list<BridgeNode>&)> func)
{
    ULONGLONG start = GetTickCount64();

    while (!IsJavaWindow(wnd))
    {
        DoEvents();
        Sleep(500);

        if (GetTickCount64() - start >= 10000)
        {
            cout << "Window " << windowName << " is not a Java window after 10 seconds, giving up" << endl;
            return false;
        }
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
        Sleep(1000);
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

public ref class TwsLoginHelper
{
public:
    static void Main(cli::array<String^>^ args)
    {
        if (args->Length != 1)
        {
            cerr << "Usage: TwsLoginHelper.exe <bitwarden_tws_login_name_or_id>" << endl;
            return;
        }

        pin_ptr<const wchar_t> bitwardenIdPtr = PtrToStringChars(args[0]);
        g_bitwardenId = bitwardenIdPtr;

        if (!initializeAccessBridge()) {
            cerr << "Failed to initialize Access Bridge" << endl;
            return;
        }
        theAccessBridge.Windows_run();

        Random^ rand = gcnew Random();

        g_serverPort = rand->Next(10000, 60000);
        Process::Start("taskkill.exe", "/im bw.exe /f")->WaitForExit();

        while (1)
        {
            if (!DoLogin()) Sleep(5000);
            Sleep(1000);
        }
    }
};