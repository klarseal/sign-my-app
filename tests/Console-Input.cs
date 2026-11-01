// TEST ONLY: supply harmless sample text to a real console, then detach.
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class SigningConsoleTest {
    [StructLayout(LayoutKind.Explicit, Size = 20, CharSet = CharSet.Unicode)]
    struct InputRecord {
        [FieldOffset(0)] public ushort Type;
        [FieldOffset(4)] public int Down;
        [FieldOffset(8)] public ushort Repeat;
        [FieldOffset(10)] public ushort VirtualKey;
        [FieldOffset(14)] public char Character;
    }
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WriteConsoleInputW(IntPtr handle, InputRecord[] input, uint count, out uint written);
    [DllImport("kernel32.dll")] public static extern bool FreeConsole();
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr window, StringBuilder name, int count);
    public static string Describe() {
        IntPtr window = GetConsoleWindow();
        var name = new StringBuilder(256);
        GetClassNameW(window, name, name.Capacity);
        return (window != IntPtr.Zero) + "|" + IsWindowVisible(window) + "|" + name + "|" + Console.IsInputRedirected;
    }
    public static void Show() {
        IntPtr window = GetConsoleWindow();
        ShowWindow(window, 5);
        // The console host owns this HWND on another thread/process.
        for (int i = 0; i < 100 && !IsWindowVisible(window); i++) System.Threading.Thread.Sleep(10);
        if (!IsWindowVisible(window)) throw new Exception("Could not show classic test console.");
    }
    public static void QueueSampleText() {
        QueueText("console regression answer");
    }
    public static void QueueText(string answer) {
        string text = answer + "\r";
        var records = new InputRecord[text.Length];
        for (int i = 0; i < text.Length; i++) records[i] = new InputRecord {
            Type = 1, Down = 1, Repeat = 1, Character = text[i], VirtualKey = (ushort)Char.ToUpperInvariant(text[i])
        };
        uint written;
        if (!WriteConsoleInputW(GetStdHandle(-10), records, (uint)records.Length, out written) || written != records.Length)
            throw new Exception("Could not prepare console regression input.");
    }
}
