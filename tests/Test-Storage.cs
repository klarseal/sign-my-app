// Test-only compound-storage copy. Windows Installer creates a 4096-byte-sector
// database here; Windows SIP rejects its signed metadata. Preserve all logical
// entries in a 512-byte-sector copy for the successful MSI integrity regression.
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class TestStorage {
 [ComImport, Guid("0000000b-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 interface Storage {
  void CreateStream([MarshalAs(UnmanagedType.LPWStr)] string n,uint m,uint r1,uint r2,out IStream s);
  void OpenStream([MarshalAs(UnmanagedType.LPWStr)] string n,IntPtr r1,uint m,uint r2,out IStream s);
  void CreateStorage([MarshalAs(UnmanagedType.LPWStr)] string n,uint m,uint r1,uint r2,out Storage s);
  void OpenStorage([MarshalAs(UnmanagedType.LPWStr)] string n,Storage p,uint m,IntPtr x,uint r,out Storage s);
  void CopyTo(uint c,IntPtr i,IntPtr e,Storage s);
  void MoveElementTo([MarshalAs(UnmanagedType.LPWStr)] string n,Storage s,[MarshalAs(UnmanagedType.LPWStr)] string nn,uint f);
  void Commit(uint f);
  void Revert();
  void EnumElements(uint a,IntPtr b,uint c,out IntPtr d);
  void DestroyElement([MarshalAs(UnmanagedType.LPWStr)] string n);
  void RenameElement([MarshalAs(UnmanagedType.LPWStr)] string a,[MarshalAs(UnmanagedType.LPWStr)] string b);
  void SetElementTimes([MarshalAs(UnmanagedType.LPWStr)] string n,IntPtr c,IntPtr a,IntPtr m);
  void SetClass(ref Guid c);
  void SetStateBits(uint b,uint m);
  void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG s,uint f);
 }
 [DllImport("ole32.dll",CharSet=CharSet.Unicode,PreserveSig=false)]
 static extern void StgOpenStorage(string n,Storage p,uint m,IntPtr e,uint r,out Storage s);
 [DllImport("ole32.dll",CharSet=CharSet.Unicode,PreserveSig=false)]
 static extern void StgCreateDocfile(string n,uint m,uint r,out Storage s);
 public static void Convert512(string source,string destination) {
  Storage a=null,b=null;
  try {
   StgOpenStorage(source,null,0x10,IntPtr.Zero,0,out a);
   StgCreateDocfile(destination,0x1012,0,out b);
   a.CopyTo(0,IntPtr.Zero,IntPtr.Zero,b);
   System.Runtime.InteropServices.ComTypes.STATSTG stat; a.Stat(out stat,1); b.SetClass(ref stat.clsid); b.Commit(0);
  } finally { if(b!=null)Marshal.FinalReleaseComObject(b); if(a!=null)Marshal.FinalReleaseComObject(a); }
 }
 public static void CorruptExtendedMetadata(string path) {
  Storage storage=null; IStream stream=null;
  try {
   StgOpenStorage(path,null,0x12,IntPtr.Zero,0,out storage);
   storage.OpenStream("\x05MsiDigitalSignatureEx",IntPtr.Zero,0x12,0,out stream);
   byte[] value=new byte[1]; stream.Read(value,1,IntPtr.Zero); value[0]^=1;
   stream.Seek(0,0,IntPtr.Zero); stream.Write(value,1,IntPtr.Zero); stream.Commit(0); storage.Commit(0);
  } finally { if(stream!=null)Marshal.FinalReleaseComObject(stream); if(storage!=null)Marshal.FinalReleaseComObject(storage); }
 }
}
