using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RunPE.Internals;

namespace RunPE.Patchers
{
    internal class ImportResolver
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern bool FreeLibrary(IntPtr hModule);

        private const int
            IDT_SINGLE_ENTRY_LENGTH =
                20; // Each Import Directory Table entry is 20 bytes long https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table

        private const int IDT_IAT_OFFSET = 16; // Offset in IDT to Relative Virtual Address to the Import Address Table for this DLL

        private const int IDT_DLL_NAME_OFFSET = 12; // Offset in IDT to DLL name for this DLL
        private const int ILT_HINT_LENGTH = 2; // Length of the 'hint' prefix to the function name in the ILT/IAT

        private readonly List<string> _originalModules = new List<string>();

        public void ResolveImports(PELoader pe, long currentBase)
        {
            // Save the current loaded modules so can unload new ones afterwards
            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
#if DEBUG
                Console.WriteLine($"[*] Original module: {module.ModuleName}");
#endif
                _originalModules.Add(module.ModuleName);
            }

            // Resolve Imports
            var pIDT = (IntPtr)(currentBase + pe.OptionalHeader64.ImportTable.VirtualAddress);
            var dllIterator = 0;
            while (true)
            {
                var pDLLImportTableEntry = (IntPtr)(pIDT.ToInt64() + IDT_SINGLE_ENTRY_LENGTH * dllIterator);

                var iatRVA = Marshal.ReadInt32((IntPtr)(pDLLImportTableEntry.ToInt64() + IDT_IAT_OFFSET));
                var pIAT = (IntPtr)(currentBase + iatRVA);

                var dllNameRVA = Marshal.ReadInt32((IntPtr)(pDLLImportTableEntry.ToInt64() + IDT_DLL_NAME_OFFSET));
                var pDLLName = (IntPtr)(currentBase + dllNameRVA);
                var dllName = Marshal.PtrToStringAnsi(pDLLName);

                if (string.IsNullOrEmpty(dllName))
                {
#if DEBUG
                    Console.WriteLine("[*] End of DLLs");
#endif
                    break;
                }

                var handle = NativeDeclarations.LoadLibrary(dllName);
#if DEBUG
                Console.WriteLine("[+] Loaded {0}", dllName);
#endif
                if (handle == IntPtr.Zero)
                {
                    throw new Exception($"Unable to load dependency: {dllName}, Last error: 0x{NativeDeclarations.GetLastError():X}");
                }

                var pCurrentIATEntry = pIAT;
                while (true)
                {
                    // For each DLL iterate over its functions in the IAT and patch the IAT with the real address https://tech-zealots.com/malware-analysis/journey-towards-import-address-table-of-an-executable-file/
                    var pDLLFuncName =
                        (IntPtr)(currentBase + Marshal.ReadInt32(pCurrentIATEntry) +
                                 ILT_HINT_LENGTH); // Skip two byte 'hint' http://sandsprite.com/CodeStuff/Understanding_imports.html
                    var dllFuncName = Marshal.PtrToStringAnsi(pDLLFuncName);

                    if (string.IsNullOrEmpty(dllFuncName))
                    {
#if DEBUG
                        Console.WriteLine($"[*] End of functions for {dllName}\n");
#endif
                        break;
                    }

                    var pRealFunction = NativeDeclarations.GetProcAddress(handle, dllFuncName);
                    if (pRealFunction == IntPtr.Zero)
                    {
                        throw new Exception($"Unable to find procedure {dllName}!{dllFuncName}");
                    }
#if DEBUG
                    Console.WriteLine($"[+] Patching {dllName}!{dllFuncName}, to: 0x{pRealFunction.ToInt64():X}");
#endif
                    Marshal.WriteInt64(pCurrentIATEntry, pRealFunction.ToInt64());

                    pCurrentIATEntry =
                        (IntPtr)(pCurrentIATEntry.ToInt64() +
                                 IntPtr.Size); // Shift the current entry to point to the next entry along, as each entry is just a pointer this is one IntPtr.Size
                }

                dllIterator++;
            }
#if DEBUG
            Console.WriteLine($"[+] Finished resolving imports\n");
#endif
        }

        internal void ResetImports()
        {
#if DEBUG
            Console.WriteLine("[*] Cleaning up loaded DLLs");
#endif
            var currentProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in currentProcess.Modules)
            {
                if (!_originalModules.Contains(module.ModuleName))
                {
#if DEBUG
                    Console.WriteLine($"[*] Freeing {module.ModuleName} at 0x{module.BaseAddress.ToInt64():X}");
#endif
                    if (!FreeLibrary(module.BaseAddress))
                    {
#if DEBUG
                        Console.WriteLine($"[-] Unable to free library: {module.ModuleName}");
                        var error = NativeDeclarations.GetLastError();
                        Console.WriteLine($"\t[-] GetLastError: {error}");
#endif
                    }
                }
            }
#if DEBUG
            Console.WriteLine("[+] Loaded DLLs cleaned up\n");
#endif
        }
    }
}