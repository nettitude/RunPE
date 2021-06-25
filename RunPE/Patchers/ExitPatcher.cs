using System;
using System.Collections.Generic;
using RunPE.Helpers;
using RunPE.Internals;

namespace RunPE.Patchers
{
    internal class ExitPatcher
    {
        private byte[] _terminateProcessOriginalBytes;
        private byte[] _ntTerminateProcessOriginalBytes;
        private byte[] _rtlExitUserProcessOriginalBytes;
        private byte[] _corExitProcessOriginalBytes;

        public bool PatchExit()
        {
            var hKernelbase = NativeDeclarations.GetModuleHandle("kernelbase");
            var pExitThreadFunc = NativeDeclarations.GetProcAddress(hKernelbase, "ExitThread");
#if DEBUG
            Console.WriteLine($"[*] kernelbase!ExitThread API function at: 0x{pExitThreadFunc.ToInt64():X}");
#endif
            var exitThreadPatchBytes = new List<byte>() {0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8};
            /*
                mov rcx, 0x0 #takes first arg
                mov rax, <ExitThread> # 
                push rax
                ret
             */
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

#if DEBUG
            Console.WriteLine("[*] Patching kernelbase!TerminateProcess, redirecting flow to kernelbase!ExitThread");
#endif
            _terminateProcessOriginalBytes =
                Utils.PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
            {
                return false;
            }
#if DEBUG
            Console.WriteLine("[*] Patching mscoree!CorExitProcess, redirecting flow to kernelbase!ExitThread");
#endif
            _corExitProcessOriginalBytes =
                Utils.PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
            {
                return false;
            }
            
#if DEBUG
            Console.WriteLine("[*] Patching ntdll!NtTerminateProcess, redirecting flow to kernelbase!ExitThread");
#endif
            _ntTerminateProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
            {
                return false;
            }
            
#if DEBUG
            Console.WriteLine("[*] Patching ntdll!RtlExitUserProcess, redirecting flow to kernelbase!ExitThread");
#endif
            _rtlExitUserProcessOriginalBytes =
                Utils.PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
            {
                return false;
            }
            
#if DEBUG
            Console.WriteLine("[+] Exit functions patched\n");
#endif
            return true;
        }

        internal void ResetExitFunctions()
        {
#if DEBUG
            Console.WriteLine("[*] Reverting patch to kernelbase!TerminateProcess");
#endif
            Utils.PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
#if DEBUG
            Console.WriteLine("[*] Reverting patch to mscoree!CorExitProcess");
#endif
            Utils.PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
#if DEBUG
            Console.WriteLine("[*] Reverting patch to ntdll!NtTerminateProcess");
#endif
            Utils.PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
#if DEBUG
            Console.WriteLine("[*] Reverting patch to ntdll!RtlExitUserProcess");
#endif
            Utils.PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
#if DEBUG
            Console.WriteLine("[+] Exit patches reverted\n");
#endif
        }
    }
}