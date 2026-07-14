using System;
using System.Runtime.InteropServices;
using System.Threading;

public sealed class FakeConsoleWindow
{
    private Thread uiThread;
    private IntPtr hwnd;
    private IntPtr edit;
    private IntPtr trayMenu;
    private uint taskbarRestartMsg;
    private AutoResetEvent readyEvent = new(initialState: false);

    private const int WM_USER = 0x0400;
    private const int WM_TRAYICON = WM_USER + 1;
    private const int WM_APPENDTEXT = WM_USER + 2;
    private const int WM_SMOOTHSCROLL = WM_USER + 3;
    private const int NIF_MESSAGE = 0x00000001;
    private const int NIF_ICON = 0x00000002;
    private const int NIF_TIP = 0x00000004;


    private const int ID_SHOW = 1001;
    private const int ID_HIDE = 1002;
    private const int ID_EXIT = 1003;

    private const int TIMER_SCROLL = 1;

    private string name;
    private WNDPROC wndProc;

    public FakeConsoleWindow(string name)
    {
        this.name = name;
        this.wndProc = new WNDPROC(WndProc);

        this.uiThread = new Thread(this.UIThread);
        this.uiThread.SetApartmentState(ApartmentState.STA);
        this.uiThread.IsBackground = true;
        this.uiThread.Start();
        this.readyEvent.WaitOne();
    }

    public void Write(string text)
    {
        if (this.hwnd == IntPtr.Zero)
            return;

        IntPtr str = Marshal.StringToHGlobalUni(text);
        SendMessage(this.hwnd, WM_APPENDTEXT, IntPtr.Zero, str);
        Marshal.FreeHGlobal(str);
    }

    public void WriteLine(string text)
    {
        if (this.hwnd == IntPtr.Zero)
            return;

        IntPtr str = Marshal.StringToHGlobalUni(text + "\r\n");
        PostMessage(this.hwnd, WM_APPENDTEXT, IntPtr.Zero, str);
    }

    // ---------------- UI THREAD ----------------

    private void UIThread()
    {
        string className = "FakeConsoleWindowClass";

        WNDCLASSEX wc = new WNDCLASSEX();
        wc.cbSize = (uint)Marshal.SizeOf(typeof(WNDCLASSEX));
        wc.style = 0x0003; // CS_HREDRAW | CS_VREDRAW
        wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(this.wndProc);
        wc.hInstance = GetModuleHandle(null);
        wc.hCursor = LoadCursor(IntPtr.Zero, (IntPtr)32512); // IDC_ARROW
        wc.hbrBackground = (IntPtr)(1 + 1); // COLOR_WINDOW
        wc.lpszClassName = className;

        RegisterClassEx(ref wc);

        this.hwnd = CreateWindowEx(
            0,
            className,
            name,
            0xCF0000, // WS_OVERLAPPEDWINDOW
            int.MinValue, int.MinValue, 1920, 1080,
            IntPtr.Zero,
            IntPtr.Zero,
            wc.hInstance,
            IntPtr.Zero);

        this.taskbarRestartMsg = RegisterWindowMessage("TaskbarCreated");

        this.CreateEditControl();
        this.CreateTrayIcon();
        this.CreateTrayMenu();

        ShowWindow(this.hwnd, 0); // hidden initially

        var writer = new FakeConsoleWriter(this);

        Console.SetOut(writer);
        Console.SetError(writer);

        this.readyEvent.Set();

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    // ---------------- WINDOW PROCEDURE ----------------

    private IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == WM_TRAYICON)
        {
            if ((int)lParam == 0x205) // WM_RBUTTONUP
                this.ShowTrayMenu();
            else if ((int)lParam == 0x201) // WM_LBUTTONDOWN
                this.ToggleWindowVisibility();
        }
        else if (msg == this.taskbarRestartMsg)
        {
            this.CreateTrayIcon();
        }
        else if (msg == WM_APPENDTEXT)
        {
            string s = Marshal.PtrToStringUni(lParam);
            this.AppendText(s);
            Marshal.FreeHGlobal(lParam);
        }
        else if (msg == 0x0111) // WM_COMMAND
        {
            int cmd = (int)wParam;

            if (cmd == ID_SHOW)
                ShowWindow(this.hwnd, 5);
            else if (cmd == ID_HIDE)
                ShowWindow(this.hwnd, 0);
            else if (cmd == ID_EXIT)
            {
                PostQuitMessage(0);
                Environment.Exit(0);
            }
        }
        else if (msg == 0x0005) // WM_SIZE
        {
            this.ResizeEditControl();
        }
        else if (msg == 0x0138) // WM_CTLCOLORSTATIC
        {
            IntPtr hdc = wParam;
            SetTextColor(hdc, 0x00FFFFFF); // white
            SetBkColor(hdc, 0x00000000);   // black
            return GetStockObject(0x0004); // BLACK_BRUSH
        }
        else if (msg == 0x0113) // WM_TIMER
        {
            if ((int)wParam == TIMER_SCROLL)
                this.SmoothScrollTick();
        }
        else if (msg == 0x0010) // WM_CLOSE
        {
            ShowWindow(this.hwnd, 0);
            return IntPtr.Zero;
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    // ---------------- EDIT CONTROL ----------------

    private void CreateEditControl()
    {

        this.edit = CreateWindowEx(
            0,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 0, 1920, 1080,
            this.hwnd,
            IntPtr.Zero,
            GetModuleHandle(null),
            IntPtr.Zero);
        // Font: Consolas
        IntPtr hFont = CreateFont(
            -16, 0, 0, 0, 400, 0, 0, 0,
            0, 0, 0, 0, 0,
            "Consolas");

        SendMessage(this.edit, 0x0030, hFont, 0); // WM_SETFONT
    }

    private void ResizeEditControl()
    {
        RECT r;
        GetClientRect(this.hwnd, out r);
        MoveWindow(this.edit, 0, 0, r.right - r.left, r.bottom - r.top, true);
    }

    private void AppendText(string text)
    {
        SendMessage(this.edit, 0x00B1, (IntPtr)int.MaxValue, (IntPtr)int.MaxValue); // EM_SETSEL
        SendMessage(this.edit, 0x00C2, IntPtr.Zero, text); // EM_REPLACESEL

        this.StartSmoothScroll();
    }

    // ---------------- SMOOTH SCROLLING ----------------

    private void StartSmoothScroll()
    {
        SetTimer(this.hwnd, TIMER_SCROLL, 16, IntPtr.Zero); // ~60 FPS
    }

    private void SmoothScrollTick()
    {
        int maxLines = (int)SendMessage(this.edit, 0x00CE, IntPtr.Zero, IntPtr.Zero); // EM_GETLINECOUNT
        int firstVisible = (int)SendMessage(this.edit, 0x00CE - 1, IntPtr.Zero, IntPtr.Zero); // EM_GETFIRSTVISIBLELINE

        if (firstVisible >= maxLines - 1)
        {
            KillTimer(this.hwnd, TIMER_SCROLL);
            return;
        }

        SendMessage(this.edit, 0x00B6, IntPtr.Zero, (IntPtr)1); // EM_LINESCROLL
    }

    // ---------------- TRAY ICON ----------------

    private void CreateTrayIcon()
    {
        NOTIFYICONDATA data = new NOTIFYICONDATA();
        data.cbSize = Marshal.SizeOf(typeof(NOTIFYICONDATA));
        data.hWnd = this.hwnd;
        data.uID = 1;
        data.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
        data.uCallbackMessage = WM_TRAYICON;
        data.hIcon = LoadIcon(IntPtr.Zero, (IntPtr)0x7F00); // IDI_APPLICATION
        data.szTip = this.name;

        Shell_NotifyIcon(0x0, ref data); // NIM_ADD
    }

    private void ToggleWindowVisibility()
    {
        int style = GetWindowLong(this.hwnd, -16);
        bool visible = (style & 0x10000000) != 0; // WS_VISIBLE

        if (visible)
            ShowWindow(this.hwnd, 0);
        else
            ShowWindow(this.hwnd, 5);
    }

    // ---------------- TRAY MENU ----------------

    private void CreateTrayMenu()
    {
        this.trayMenu = CreatePopupMenu();
        AppendMenu(this.trayMenu, 0x0000, ID_SHOW, "Show");
        AppendMenu(this.trayMenu, 0x0000, ID_HIDE, "Hide");
        AppendMenu(this.trayMenu, 0x0000, ID_EXIT, "Exit");
    }

    private void ShowTrayMenu()
    {
        POINT pt;
        GetCursorPos(out pt);

        SetForegroundWindow(this.hwnd);

        TrackPopupMenu(
            this.trayMenu,
            0,
            pt.x,
            pt.y,
            0,
            this.hwnd,
            IntPtr.Zero);
    }

    const int WS_CHILD = 0x40000000;
    const int WS_VISIBLE = 0x10000000;
    const int WS_VSCROLL = 0x00200000;
    const int ES_LEFT = 0x0000;
    const int ES_MULTILINE = 0x0004;
    const int ES_AUTOVSCROLL = 0x0040;
    const int ES_READONLY = 0x0800;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadCursor(IntPtr hInstance, IntPtr lpCursorName);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(uint dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("user32.dll")]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassEx(ref WNDCLASSEX lpwcx);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(
        uint dwExStyle, string lpClassName, string lpWindowName,
        uint dwStyle, int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DispatchMessage(ref MSG lpMsg);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern sbyte GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessage(string lpString);

    [DllImport("user32.dll")]
    private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll")]
    private static extern bool AppendMenu(IntPtr hMenu, uint uFlags, int uIDNewItem, string lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool SetTimer(IntPtr hWnd, int nIDEvent, int uElapse, IntPtr lpTimerFunc);

    [DllImport("user32.dll")]
    private static extern bool KillTimer(IntPtr hWnd, int uIDEvent);

    [DllImport("gdi32.dll")]
    private static extern uint SetTextColor(IntPtr hdc, uint color);

    [DllImport("gdi32.dll")]
    private static extern uint SetBkColor(IntPtr hdc, uint color);

    [DllImport("gdi32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFont(
        int nHeight, int nWidth, int nEscapement, int nOrientation,
        int fnWeight, uint fdwItalic, uint fdwUnderline, uint fdwStrikeOut,
        uint fdwCharSet, uint fdwOutputPrecision, uint fdwClipPrecision,
        uint fdwQuality, uint fdwPitchAndFamily, string lpFaceName);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int nExitCode);

    [DllImport("gdi32.dll")]
    private static extern IntPtr GetStockObject(int fnObject);

    // ---------------- Structs ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int pt_x;
        public int pt_y;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    private delegate IntPtr WNDPROC(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x; public int y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int left, top, right, bottom; }
}
