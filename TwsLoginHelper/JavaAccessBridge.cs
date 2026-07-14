using System.Runtime.InteropServices;
using Microsoft.Win32;

public static class JavaAccessBridge
{
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint LoadLibrary(string lpFileName);

    private static nint windowAccessBridgeDll;

    public static bool IsInitialized { get; private set; }

    public static void Initialize()
    {
        JavaAccessBridge.windowAccessBridgeDll = LoadTwsWindowsAccessBridge();

        Console.WriteLine($"TWS WindowAccessBridge-64.dll: {JavaAccessBridge.windowAccessBridgeDll:x16}");

        JavaAccessBridge.IsInitialized = true;
    }

    public static void Shutdown()
    {
        if (!JavaAccessBridge.IsInitialized) throw new InvalidOperationException();

        JavaAccessBridge.IsInitialized = false;
    }

    public static nint LoadTwsWindowsAccessBridge()
    {
        const string regPath = @"tws\shell\open\command";
        using var key = Registry.ClassesRoot.OpenSubKey(regPath);
        string command = key?.GetValue(null) as string;

        if (string.IsNullOrWhiteSpace(command)) return 0;

        string twsExe = ExtractExePath(command);
        string twsDir = Path.GetDirectoryName(twsExe);

        string cfgPath = Path.Combine(twsDir, ".install4j", "inst_jre.cfg");
        if (!File.Exists(cfgPath)) return 0;

        string jreDir = File.ReadAllText(cfgPath).Trim();
        if (!Directory.Exists(jreDir)) return 0;

        string dllPath = Path.Combine(jreDir, "bin", "windowsaccessbridge-64.dll");
        if (!File.Exists(dllPath)) return 0;

        return LoadLibrary(dllPath);
    }

    private static string ExtractExePath(string command)
    {
        // Handles:
        //   "E:\IB\Jts\1045\tws.exe" "%1"
        //   "C:\path with spaces\tws.exe" "%1"
        //   C:\NoQuotes\tws.exe "%1"
        //   etc.

        command = command.Trim();

        if (command.StartsWith("\""))
        {
            // Quoted path
            int end = command.IndexOf('"', 1);
            if (end < 0)
                throw new FormatException("Malformed quoted command string.");

            return command.Substring(1, end - 1);
        }
        else
        {
            // Unquoted path: take until first space
            int space = command.IndexOf(' ');
            return space > 0 ? command.Substring(0, space) : command;
        }
    }
}
