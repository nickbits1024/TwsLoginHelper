// TwsLoginHelper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <list>
#include <vcclr.h>
#include "AccessBridgeCalls.h"

using namespace std;
using namespace System;
using namespace System::IO;
using namespace System::Diagnostics;
using namespace System::Reflection;

extern "C" AccessBridgeFPs theAccessBridge;

public ref class LoginDetails
{
private:
    String^ username;
    String^ password;
    String^ totpSecret;

public:
    property String^ Username
    {
        String ^ get() { return this->username; }
        void set(String ^ value) { this->username = value; }
    }

        property String^ Password
    {
        String ^ get() { return this->password; }
        void set(String ^ value) { this->password = value; }
    }

        property String^ TotpSecret
    {
        String ^ get() { return this->totpSecret; }
        void set(String ^ value) { this->totpSecret = value; }
    }

};


public interface class ILoginProvider
{
    LoginDetails^ GetLogin();
    String^ GetTotp(String^ totpSecret);
};

struct BridgeNode
{
    long vmId;
    AccessibleContext ctx;
    AccessibleContextInfo info;
};

struct FINDTWSWINDOWPARAMS {
    LPCWSTR windowTitle;
    HWND wnd;
};

HWND FindTwsWindow(LPCWSTR windowTitle)
{
    HWND wnd = FindWindowW(L"SunAwtFrame", L"Login");

    if (wnd != NULL)
    {
        FINDTWSWINDOWPARAMS args = { .windowTitle = windowTitle };
        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            FINDTWSWINDOWPARAMS* args = reinterpret_cast<FINDTWSWINDOWPARAMS*>(lParam);

            if (!IsWindowVisible(hwnd)) return TRUE;

            TCHAR className[256];
            GetClassName(hwnd, className, sizeof(className) / sizeof(TCHAR));
            if (wcscmp(className, L"SunAwtFrame") == 0)
            {
                TCHAR foundWindowTitle[256];
                GetWindowText(hwnd, foundWindowTitle, sizeof(foundWindowTitle) / sizeof(TCHAR));
                if (wcscmp(foundWindowTitle, args->windowTitle) == 0)
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

        cout << "TOTP has " << remaining << "s remaining" << endl;

        if (remaining >= nSeconds)
            return;

        cout << "Waiting " << remaining + 1 << "s for next TOTP interval";

        // Not enough time left — wait until next window
        int sleepMs = (remaining + 1) * 1000; // +1 to cross boundary safely
        Sleep(sleepMs);
    }
}

static bool SubmitLogin(const list<BridgeNode>& nodes, ILoginProvider^ loginProvider, LoginDetails^% loginDetails)
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

    if (loginDetails == nullptr)
    {
        loginDetails = loginProvider->GetLogin();
    }
    if (loginDetails == nullptr) return false;

    pin_ptr<const wchar_t> usernamePtr = PtrToStringChars(loginDetails->Username);
    pin_ptr<const wchar_t> passwordPtr = PtrToStringChars(loginDetails->Password);
    String^ stars = gcnew String(L'*', loginDetails->Password->Length);
    pin_ptr<const wchar_t> starsPtr = PtrToStringChars(stars);

    wcout << "Retrieved username: " << static_cast<const wchar_t*>(usernamePtr) << endl;
    wcout << "Retrieved password: " << static_cast<const wchar_t*>(starsPtr) << endl;

    setTextContents(loginTextNode.vmId, loginTextNode.ctx, usernamePtr);
    setTextContents(passwordTextNode.vmId, passwordTextNode.ctx, passwordPtr);

    ClickButton(loginButtonNode);

    return true;
}

static bool SubmitAppCode(const list<BridgeNode>& nodes, ILoginProvider^ loginProvider, LoginDetails^& loginDetails)
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

    WaitUntilTotpHasAtLeast(1);

    if (loginDetails == nullptr)
    {
        loginDetails = loginProvider->GetLogin();
    }
    if (loginDetails == nullptr) return false;

    pin_ptr<const wchar_t> appCodePtr = PtrToStringChars(loginProvider->GetTotp(loginDetails->TotpSecret));
    wcout << L"App Code: " << static_cast<const wchar_t*>(appCodePtr) << endl;

    setTextContents(appCodeTextNode.vmId, appCodeTextNode.ctx, appCodePtr);
    ClickButton(okButtonNode);
    loginDetails = nullptr;

    return true;
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

template <typename TCallback>
bool DoLogin(HWND wnd, LPCSTR windowName, TCallback func, ILoginProvider^ loginProvider, LoginDetails^& lastLoginDetails)
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

    func(nodes, loginProvider, lastLoginDetails);

    for (const BridgeNode& node : nodes)
    {
        ReleaseJavaObject(node.vmId, node.ctx);
    }

    return true;
}

static bool DoLogin(ILoginProvider^ loginProvider, LoginDetails^& lastLoginDetails)
{
    cout << "Waiting for TWS Window..." << endl;

    HWND twsLoginWindow = NULL;
    HWND twsAppCodeWindow = NULL;
    while ((twsLoginWindow = FindTwsWindow(L"Login")) == NULL &&
        (twsAppCodeWindow = FindTwsWindow(L"Second Factor Authentication")) == NULL)
    {
        Sleep(1000);
    }

    if (twsLoginWindow != NULL)
    {
        DoLogin(twsLoginWindow, "TWS Login", SubmitLogin, loginProvider, lastLoginDetails);
        return false;
    }
    if (twsAppCodeWindow != NULL)
    {
        return DoLogin(twsAppCodeWindow, "App Code", SubmitAppCode, loginProvider, lastLoginDetails);
    }

    return false;
}

public ref class TwsLoginHelper
{
public:
    static void Login(ILoginProvider^ loginProvider)
    {
        LoginDetails^ lastLoginDetails;

        if (!initializeAccessBridge()) {
            cerr << "Failed to initialize Access Bridge" << endl;
            return;
        }

        try
        {
            while (!DoLogin(loginProvider, lastLoginDetails))
            {
                Sleep(1000);
                DoEvents();
            }
        }
        finally
        {
            shutdownAccessBridge();
        }

        cout << "Login cycle complete" << endl;
    }

    static void Run(Guid vaultId)
    {
        while (1)
        {
            cout << "Waiting for TWS Login window..." << endl;
            while (FindTwsWindow(L"Login") == NULL)
            {
                Sleep(1000);
            }

            String^ hostPath = Path::ChangeExtension(Assembly::GetEntryAssembly()->Location, ".exe");

            Process^ proc = Process::Start(hostPath, "--login --vault-id " + vaultId);

            proc->WaitForExit();

            while (Process::GetProcessesByName("tws")->Length > 0)
            {
                cout << "Waiting for TWS to exit" << endl;
                Sleep(10000);
            }
        }
    }
};