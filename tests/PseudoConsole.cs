// TEST ONLY: host a real ConPTY and send sample input only after its prompt arrives.
// Lifecycle follows https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class SigningPseudoConsoleResult {
    public int ExitCode;
    public string Output;
    public bool PromptSeen;
}
public static class SigningPseudoConsoleTest {
    [StructLayout(LayoutKind.Sequential)] struct Coord { public short X, Y; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StartupInfo {
        public int Size;
        public string Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        public short Show, ReservedSize;
        public IntPtr ReservedData, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx { public StartupInfo Info; public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public int ProcessId, ThreadId; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, IntPtr security, int size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteFile(SafeFileHandle handle, byte[] buffer, int count, out int written, IntPtr overlapped);
    [DllImport("kernel32.dll")] static extern int CreatePseudoConsole(Coord size, SafeFileHandle input, SafeFileHandle output, uint flags, out IntPtr console);
    [DllImport("kernel32.dll")] static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }

    public static SigningPseudoConsoleResult Run(string executable, string arguments, string prompt, string answer) {
        SafeFileHandle inputRead = null, inputWrite = null, outputRead = null, outputWrite = null;
        IntPtr console = IntPtr.Zero, attributes = IntPtr.Zero;
        ProcessInfo process = new ProcessInfo();
        Thread reader = null;
        var output = new StringBuilder();
        var result = new SigningPseudoConsoleResult();
        Exception readerError = null;
        bool initialized = false;
        try {
            Check(CreatePipe(out inputRead, out inputWrite, IntPtr.Zero, 0));
            Check(CreatePipe(out outputRead, out outputWrite, IntPtr.Zero, 0));
            Marshal.ThrowExceptionForHR(CreatePseudoConsole(new Coord { X = 240, Y = 40 }, inputRead, outputWrite, 0, out console));
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attributes = Marshal.AllocHGlobal(size);
            Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref size));
            initialized = true;
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20016), console, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            var startup = new StartupInfoEx();
            startup.Info.Size = Marshal.SizeOf(typeof(StartupInfoEx));
            // Do not inherit this test runner's redirected standard handles.
            // Null STARTF_USESTDHANDLES entries get ConPTY's console devices.
            startup.Info.Flags = 0x100;
            startup.Attributes = attributes;
            // Drain output concurrently, including during ClosePseudoConsole.
            reader = new Thread(delegate() {
                try {
                    using (var stream = new FileStream(outputRead, FileAccess.Read))
                    using (var text = new StreamReader(stream, Encoding.UTF8)) {
                        var buffer = new char[4096];
                        int count;
                        while ((count = text.Read(buffer, 0, buffer.Length)) > 0) {
                            lock (output) {
                                output.Append(buffer, 0, count);
                                if (!result.PromptSeen && prompt != null && output.ToString().Contains(prompt)) {
                                    result.PromptSeen = true;
                                    byte[] bytes = Encoding.UTF8.GetBytes(answer + "\r");
                                    int written;
                                    Check(WriteFile(inputWrite, bytes, bytes.Length, out written, IntPtr.Zero));
                                    if (written != bytes.Length) throw new IOException("Incomplete test input write.");
                                }
                            }
                        }
                    }
                } catch (Exception error) { readerError = error; }
            });
            reader.IsBackground = true;
            reader.Start();
            Check(CreateProcessW(executable, new StringBuilder("\"" + executable + "\" " + arguments), IntPtr.Zero, IntPtr.Zero, false, 0x80000, IntPtr.Zero, Environment.SystemDirectory, ref startup, out process));
            inputRead.Dispose(); outputWrite.Dispose();
            uint wait = WaitForSingleObject(process.Process, 20000);
            if (wait != 0) {
                TerminateProcess(process.Process, 99);
                lock (output) { throw new Exception("ConPTY test timed out or wait failed: " + wait + "\n" + output); }
            }
            uint code;
            Check(GetExitCodeProcess(process.Process, out code));
            result.ExitCode = (int)code;
        } finally {
            if (process.Process != IntPtr.Zero) {
                if (WaitForSingleObject(process.Process, 0) != 0) TerminateProcess(process.Process, 99);
                CloseHandle(process.Process); CloseHandle(process.Thread);
            }
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (inputRead != null) inputRead.Dispose();
            if (outputWrite != null) outputWrite.Dispose();
            if (console != IntPtr.Zero) ClosePseudoConsole(console);
            if (reader != null && !reader.Join(5000)) throw new Exception("ConPTY output drain timed out.");
            if (inputWrite != null) inputWrite.Dispose();
            if (outputRead != null) outputRead.Dispose();
        }
        if (readerError != null) throw new Exception("ConPTY reader failed.", readerError);
        result.Output = output.ToString();
        return result;
    }
}
