using System.Security.Cryptography.X509Certificates;
using System.IO.Packaging;
using CommandLine;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Input;
using System.Security.Cryptography;

public class Options
{
  [Option('k', "package", Required = true, HelpText = "The package to sign")]
  public string? Package { get; set; }

  [Option('c', "certificate", Required = true, HelpText = "The certificate to use for signing")]
  public string? Certificate { get; set; }

  [Option('p', "password", Required = false, HelpText = "The password for certificate to use for signing")]
  public string? Password { get; set; }
}

public static class SimulateKB
{
  [StructLayout(LayoutKind.Sequential)]
  public struct KeyboardInput
  {
    public ushort wVk;
    public ushort wScan;
    public uint dwFlags;
    public uint time;
    public IntPtr dwExtraInfo;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct MouseInput
  {
    public int dx;
    public int dy;
    public uint mouseData;
    public uint dwFlags;
    public uint time;
    public IntPtr dwExtraInfo;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct HardwareInput
  {
    public uint uMsg;
    public ushort wParamL;
    public ushort wParamH;
  }

  [StructLayout(LayoutKind.Explicit)]
  public struct InputUnion
  {
    [FieldOffset(0)] public MouseInput mi;
    [FieldOffset(0)] public KeyboardInput ki;
    [FieldOffset(0)] public HardwareInput hi;
  }

  public struct Input
  {
    public int type;
    public InputUnion u;
  }

  [Flags]
  public enum InputType
  {
    Mouse = 0,
    Keyboard = 1,
    Hardware = 2
  }

  [Flags]
  public enum KeyEventF
  {
    KeyDown = 0x0000,
    ExtendedKey = 0x0001,
    KeyUp = 0x0002,
    Unicode = 0x0004,
    Scancode = 0x0008
  }

  [Flags]
  public enum MouseEventF
  {
    Absolute = 0x8000,
    HWheel = 0x01000,
    Move = 0x0001,
    MoveNoCoalesce = 0x2000,
    LeftDown = 0x0002,
    LeftUp = 0x0004,
    RightDown = 0x0008,
    RightUp = 0x0010,
    MiddleDown = 0x0020,
    MiddleUp = 0x0040,
    VirtualDesk = 0x4000,
    Wheel = 0x0800,
    XDown = 0x0080,
    XUp = 0x0100
  }

  [DllImport("user32.dll", SetLastError = true)]
  private static extern uint SendInput(uint cInputs, ref Input pInputs, int cbSize);

  [DllImport("user32.dll")]
  private static extern short VkKeyScan(char ch);

  public static void SendUnicode(string message)
  {
    for (int i = 0; i < message.Length; i++)
    {
      Input input_down = new()
      {
        type = (int)InputType.Keyboard,
        u = new()
        {
          ki = new()
          {
            dwFlags = (int)KeyEventF.Unicode,
            wScan = (ushort)message[i],
            wVk = 0
          }
        }
      };
      SendInput(1, ref input_down, Marshal.SizeOf(input_down));//keydown     
      Input input_up = new()
      {
        type = (int)InputType.Keyboard,
        u = new()
        {
          ki = new()
          {
            dwFlags = (int)(KeyEventF.KeyUp | KeyEventF.Unicode),
            wScan = (ushort)message[i],
            wVk = 0
          }
        }
      };
      SendInput(1, ref input_up, Marshal.SizeOf(input_up));//keyup      
    }
  }
}

public static class HCK
{
  // Import Windows API functions
  [DllImport("user32.dll", SetLastError = true)]
  static extern IntPtr FindWindow(string? lpClassName, string lpWindowName);

  [DllImport("user32.dll", SetLastError = true)]
  static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string? lpszWindow);

  [DllImport("user32.dll", SetLastError = true)]
  static extern IntPtr SetFocus(IntPtr hWnd);

  [DllImport("user32.dll", SetLastError = true)]
  static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, string? lParam);

  // Define constants for the Windows API functions
  const int WM_SETTEXT = 0x000C;
  const int BM_CLICK = 0x00F5;

  static bool running = true;

  static void InsertPassword(object parameter)
  {
    string password = parameter.ToString();
    while (running)
    {
      // Find the window with the specified title
      IntPtr windowHandle = FindWindow(null, "验证 PIN 码");

      if (windowHandle != IntPtr.Zero)
      {
        IntPtr editHandle = FindWindowEx(windowHandle, IntPtr.Zero, "Edit", null);

        if (editHandle != IntPtr.Zero)
        {
          // insert password
          SetFocus(editHandle);
          SimulateKB.SendUnicode(password);

          Thread.Sleep(1000); // wait for 1 second

          // find and click the OK button
          IntPtr buttonHandle = FindWindowEx(windowHandle, IntPtr.Zero, "Button", "登录");

          if (buttonHandle != IntPtr.Zero)
          {
            SendMessage(buttonHandle, BM_CLICK, 0, null);
          }
        }
      }
    }
  }

  static void Sign(string package, X509Certificate2 certificate)
  {
    // Open the package to sign it
    Package packageToSign = Package.Open(package);

    // Specify that the digital signature should exist 
    // embedded in the signature part
    PackageDigitalSignatureManager signatureManager = new PackageDigitalSignatureManager(packageToSign);

    signatureManager.CertificateOption = CertificateEmbeddingOption.InCertificatePart;

    // We want to sign every part in the package
    List<Uri> partsToSign = new List<Uri>();
    foreach (PackagePart part in packageToSign.GetParts())
    {
      partsToSign.Add(part.Uri);
    }

    // We will sign every relationship by type
    // This will mean the signature is invalidated if *anything* is modified in
    // the package post-signing
    List<PackageRelationshipSelector> relationshipSelectors = new List<PackageRelationshipSelector>();

    foreach (PackageRelationship relationship in packageToSign.GetRelationships())
    {
      relationshipSelectors.Add(new PackageRelationshipSelector(relationship.SourceUri, PackageRelationshipSelectorType.Type, relationship.RelationshipType));
    }

    try
    {
      signatureManager.Sign(partsToSign, certificate, relationshipSelectors);
    }
    finally
    {
      packageToSign.Close();
    }
  }

  static void Main(string[] args)
  {
    Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
    {
      if (o.Certificate != null && o.Package != null)
      {
        // Create a certificate
        X509Certificate2 certificate = new(o.Certificate);

        if (o.Password != null)
        {
          Thread thread = new(new ParameterizedThreadStart(InsertPassword));
          thread.Start(o.Password);
        }
        // Sign the package
        Sign(o.Package, certificate);
        running = false;
      }
    });
  }
}

