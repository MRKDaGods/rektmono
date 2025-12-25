using System.Runtime.InteropServices;

Console.Write("Process path: ");
string? processPath = Console.ReadLine();
if (string.IsNullOrEmpty(processPath))
    processPath = "C:\\Users\\mamar\\Desktop\\Build\\UnityAssignment.exe";

Console.WriteLine($"Using process path: {processPath}");

LoaderConfig config = new LoaderConfig(processPath);
string b64 = Convert.ToBase64String(config.ToByteArray());
Console.WriteLine("\n\nOUTPUT\n");
Console.WriteLine(b64);

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
struct LoaderConfig(string processPath)
{
    const uint CONFIG_MAGIC = 0xDEADC0DE;
    const int MAX_PATH_LENGTH = 260;

    public readonly uint Magic = CONFIG_MAGIC;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH_LENGTH)]
    public readonly string ProcessPath = processPath;

    public readonly byte[] ToByteArray()
    {
        int size = Marshal.SizeOf<LoaderConfig>();
        Console.WriteLine($"Struct size: {size} bytes");

        byte[] arr = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);
        
        try
        {
            Marshal.StructureToPtr(this, ptr, false);
            Marshal.Copy(ptr, arr, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        return arr;
    }
}