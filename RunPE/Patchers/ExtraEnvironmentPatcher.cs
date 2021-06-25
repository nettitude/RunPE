using System;
using System.Runtime.InteropServices;
using RunPE.Helpers;

namespace RunPE.Patchers
{
    internal class ExtraEnvironmentPatcher
    {
        private const int PEB_BASE_ADDRESS_OFFSET = 0x10;

        private IntPtr _pOriginalPebBaseAddress;
        private IntPtr _pPEBBaseAddr;

        private IntPtr _newPEBaseAddress;

        public ExtraEnvironmentPatcher(IntPtr newPEBaseAddress)
        {
            _newPEBaseAddress = newPEBaseAddress;
        }

        internal bool PerformExtraEnvironmentPatches()
        {
#if DEBUG
            Console.WriteLine("\n[*] Performing extra environmental patches");
#endif
            return PatchPebBaseAddress();
        }

        private bool PatchPebBaseAddress()
        {
#if DEBUG
            Console.WriteLine(
                $"[*] Patching the main module base address in the PEB to 0x{_newPEBaseAddress.ToString("X")}");
#endif
            _pPEBBaseAddr = (IntPtr) (Utils.GetPointerToPeb().ToInt64() + PEB_BASE_ADDRESS_OFFSET);
#if DEBUG
            Console.WriteLine($"[*] Address of main module base address in PEB: 0x{_pPEBBaseAddr.ToString("X")}");
#endif
            _pOriginalPebBaseAddress = Marshal.ReadIntPtr(_pPEBBaseAddr);
#if DEBUG
            Console.WriteLine(
                $"[*] Main module base address read from PEB: 0x{_pOriginalPebBaseAddress.ToString("X")}");
#endif
            if (!Utils.PatchAddress(_pPEBBaseAddr, _newPEBaseAddress))
            {
#if DEBUG
                Console.WriteLine(
                    $"[-] Unable to patch main module base address in PEB at: 0x{_pPEBBaseAddr.ToString("X")}");
#endif
                return false;
            }
#if DEBUG
            var pNewPebBaseAddress = Marshal.ReadIntPtr(_pPEBBaseAddr);
            Console.WriteLine($"[*] New main module base address in PEB: 0x{pNewPebBaseAddress.ToString("X")}");
#endif
            return true;
        }

        internal bool RevertExtraPatches()
        {
#if DEBUG
            Console.WriteLine($"[*] Reverting patch to main module base address in PEB at: 0x{_pPEBBaseAddr:X}");
#endif
            if (!Utils.PatchAddress(_pPEBBaseAddr, _pOriginalPebBaseAddress))
            {
#if DEBUG
                Console.WriteLine(
                    $"[-] Unable to revert patch to main module base address in PEB at: 0x{_pPEBBaseAddr:X}");
#endif
                return false;
            }
#if DEBUG
            Console.WriteLine($"[+] All extra environmental patches reverted\n");
#endif
            return true;
        }
    }
}