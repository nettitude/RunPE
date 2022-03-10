using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using RunPE.Helpers;
using RunPE.Internals;

namespace RunPE.Patchers
{
    internal class ArgumentHandler
    {
        private const int
            PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET =
                0x20; // Offset into the PEB that the RTL_USER_PROCESS_PARAMETERS pointer sits at

        private const int
            RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET =
                0x70; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters

        private const int RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET = 2;

        private const int
            RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET =
                0x60; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters

        private const int
            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET =
                0x8; // Offset into the UNICODE_STRING struct that the string pointer sits at https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string

        private byte[] _originalCommandLineFuncBytes;
        private IntPtr _ppCommandLineString;
        private IntPtr _ppImageString;
        private IntPtr _pLength;
        private IntPtr _pMaxLength;
        private IntPtr _pOriginalCommandLineString;
        private IntPtr _pOriginalImageString;
        private IntPtr _pNewString;
        private short _originalLength;
        private short _originalMaxLength;
        private string _commandLineFunc;
        private Encoding _encoding;

        public bool UpdateArgs(string filename, string[] args)
        {
            var pPEB = Utils.GetPointerToPeb();
            if (pPEB == IntPtr.Zero)
            {
                return false;
            }

            GetPebCommandLineAndImagePointers(pPEB, out _ppCommandLineString, out _pOriginalCommandLineString,
                out _ppImageString, out _pOriginalImageString, out _pLength, out _originalLength, out _pMaxLength,
                out _originalMaxLength);


#if DEBUG
            var commandLineString = Marshal.PtrToStringUni(_pOriginalCommandLineString);
            var imageString = Marshal.PtrToStringUni(_pOriginalImageString);
            Console.WriteLine($"[*] Current args read from PEB: {commandLineString}");
            Console.WriteLine($"[*] Current image read from PEB: {imageString}");
#endif
            var newCommandLineString = $"\"{filename}\" {string.Join(" ", args)}";
            var pNewCommandLineString = Marshal.StringToHGlobalUni(newCommandLineString);
            var pNewImageString = Marshal.StringToHGlobalUni(filename);
#if DEBUG
            Console.WriteLine($"[*] Patching CommandLine string pointer...");
#endif
            if (!Utils.PatchAddress(_ppCommandLineString, pNewCommandLineString))
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to patch CommandLine string pointer");
#endif
                return false;
            }
#if DEBUG
            Console.WriteLine($"[*] Patching Image string pointer...");
#endif
            if (!Utils.PatchAddress(_ppImageString, pNewImageString))
            {
#if DEBUG
                Console.WriteLine($"[-] Unable to patch Image string pointer");
#endif
                return false;
            }
#if DEBUG
            Console.WriteLine($"[*] Patching Length...");
#endif
            Marshal.WriteInt16(_pLength, 0, (short) newCommandLineString.Length);
#if DEBUG
            Console.WriteLine($"[*] Patching MaximumLength...");
#endif
            Marshal.WriteInt16(_pMaxLength, 0, (short) newCommandLineString.Length);

#if DEBUG
            GetPebCommandLineAndImagePointers(pPEB, out _, out var pCommandLineStringCheck, out _,
                out var pImageStringCheck, out _, out var lengthCheck, out _, out var maxLengthCheck);
            var commandLineStringCheck = Marshal.PtrToStringUni(pCommandLineStringCheck);
            Console.WriteLine($"[*] New args read from PEB: {commandLineStringCheck}");
            var imageStringCheck = Marshal.PtrToStringUni(pImageStringCheck);
            Console.WriteLine($"[*] New image read from PEB: {imageStringCheck}");
            Console.WriteLine($"[*] New length read from PEB: {lengthCheck}");
            Console.WriteLine($"[*] New maxlength read from PEB: {maxLengthCheck}");
            Console.WriteLine($"[+] Finished Patching PEB\n");
            Console.WriteLine($"[+] Patching GetCommandLine API Call...");
#endif

            if (!PatchGetCommandLineFunc(newCommandLineString))
            {
                return false;
            }

#if DEBUG
            var getCommandLineAPIString = Marshal.PtrToStringUni(NativeDeclarations.GetCommandLine());
            Console.WriteLine(
                $"[*] Patched CommandLine string from GetCommandLine API call: {getCommandLineAPIString}");
            Console.WriteLine($"[+] Finished Patching API Calls\n");
#endif
            return true;
        }

        private bool PatchGetCommandLineFunc(string newCommandLineString)
        {
            var pCommandLineString = NativeDeclarations.GetCommandLine();
            var commandLineString = Marshal.PtrToStringAuto(pCommandLineString);

            _encoding = Encoding.UTF8;

            if (commandLineString != null)
            {
                var stringBytes = new byte[commandLineString.Length];

                // Copy the command line string bytes into an array and check if it contains null bytes (so if it is wide or not
                Marshal.Copy(pCommandLineString, stringBytes, 0,
                    commandLineString.Length); // Even if ASCII won't include null terminating byte

                if (!new List<byte>(stringBytes).Contains(0x00))
                {
                    _encoding = Encoding.ASCII; // At present assuming either ASCII or UTF8
                }

                Program.encoding = _encoding;

#if DEBUG
                // Print the string bytes and what the encoding was determined to be
                var stringBytesHexString = "";
                foreach (var x in stringBytes)
                {
                    stringBytesHexString += x.ToString("X") + " ";
                }

                Console.WriteLine($"[*] String bytes: {stringBytesHexString}");
                Console.WriteLine($"[*] String encoding determined to be: {_encoding}");
#endif
            }

            // Set the GetCommandLine func based on the determined encoding
            _commandLineFunc = _encoding.Equals(Encoding.ASCII) ? "GetCommandLineA" : "GetCommandLineW";

#if DEBUG
            Console.WriteLine($"[*] Old GetCommandLine return value: 0x{pCommandLineString.ToInt64():X}");
#endif
            // Write the new command line string into memory
            _pNewString = _encoding.Equals(Encoding.ASCII)
                ? Marshal.StringToHGlobalAnsi(newCommandLineString)
                : Marshal.StringToHGlobalUni(newCommandLineString);
#if DEBUG
            Console.WriteLine($"[*] New String Address: 0x{_pNewString.ToInt64():X}");
#endif
            // Create the patch bytes that provide the new string pointer
            var patchBytes = new List<byte> {0x48, 0xB8}; // TODO architecture
            var pointerBytes = BitConverter.GetBytes(_pNewString.ToInt64());

            patchBytes.AddRange(pointerBytes);

            patchBytes.Add(0xC3);

            // Patch the GetCommandLine function to return the new string
            _originalCommandLineFuncBytes = Utils.PatchFunction("kernelbase", _commandLineFunc, patchBytes.ToArray());
            if (_originalCommandLineFuncBytes == null)
            {
                return false;
            }

#if DEBUG
            var pNewCommandLineString = NativeDeclarations.GetCommandLine();
            Console.WriteLine($"[*] New GetCommandLine return value: 0x{pNewCommandLineString.ToInt64():X}");
#endif
            return true;
        }

        private static void GetPebCommandLineAndImagePointers(IntPtr pPEB, out IntPtr ppCommandLineString,
            out IntPtr pCommandLineString, out IntPtr ppImageString, out IntPtr pImageString,
            out IntPtr pCommandLineLength, out short commandLineLength, out IntPtr pCommandLineMaxLength,
            out short commandLineMaxLength)
        {
#if DEBUG
            Console.WriteLine($"[*] PEB Base Address: 0x{pPEB.ToInt64():X}");
#endif
            var ppRtlUserProcessParams = (IntPtr) (pPEB.ToInt64() + PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET);
#if DEBUG
            Console.WriteLine(
                $"[*] PEB RTL_USER_PROCESS_PARAMETERS Struct Pointer Address: 0x{ppRtlUserProcessParams.ToInt64():X}");
#endif
            var pRtlUserProcessParams = Marshal.ReadInt64(ppRtlUserProcessParams);
#if DEBUG
            Console.WriteLine($"[*] PEB RTL_USER_PROCESS_PARAMETERS Struct Pointer: 0x{pRtlUserProcessParams:X}");
#endif
            ppCommandLineString = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                  UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pCommandLineString = (IntPtr) Marshal.ReadInt64(ppCommandLineString);

            ppImageString = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET +
                            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pImageString = (IntPtr) Marshal.ReadInt64(ppImageString);

            pCommandLineLength = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET;
            commandLineLength = Marshal.ReadInt16(pCommandLineLength);

            pCommandLineMaxLength = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                    RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET;
            commandLineMaxLength = Marshal.ReadInt16(pCommandLineMaxLength);
#if DEBUG
            Console.WriteLine($"[*] CommandLine String Pointer Pointer: 0x{ppCommandLineString:X}");
            Console.WriteLine($"[*] CommandLine String Pointer: 0x{pCommandLineString:X}");
            Console.WriteLine($"[*] Image String Pointer Pointer: 0x{ppImageString:X}");
            Console.WriteLine($"[*] Image String Pointer: 0x{pImageString:X}");
            Console.WriteLine($"[*] Length Pointer: 0x{pCommandLineLength:X}");
            Console.WriteLine($"[*] Length Value: 0x{commandLineLength:X} ({commandLineLength})");
            Console.WriteLine($"[*] MaxLength Pointer: 0x{pCommandLineMaxLength:X}");
            Console.WriteLine($"[*] MaxLength Value: 0x{commandLineMaxLength:X} ({commandLineMaxLength})");
#endif
        }

        internal void ResetArgs()
        {
#if DEBUG
            Console.WriteLine($"[*] Reverting patch to kernelbase!{_commandLineFunc}");
#endif
            if (Utils.PatchFunction("kernelbase", _commandLineFunc, _originalCommandLineFuncBytes) == null)
            {
#if DEBUG
                Console.WriteLine($"[-] Failed to revert patch on kernelbase!{_commandLineFunc}");
#endif
            }
#if DEBUG
            Console.WriteLine($"[*] Reverting patch to command line string pointer");
#endif
            if (!Utils.PatchAddress(_ppCommandLineString, _pOriginalCommandLineString))
            {
#if DEBUG
                Console.WriteLine($"[-] Failed to revert patch to command line string pointer");
#endif
            }
#if DEBUG
            Console.WriteLine($"[*] Reverting patch to image string pointer");
#endif
            if (!Utils.PatchAddress(_ppImageString, _pOriginalImageString))
            {
#if DEBUG
                Console.WriteLine($"[-] Failed to revert patch to image string pointer");
#endif
            }
#if DEBUG
            Console.WriteLine($"[*] Reverting patch to command line string length");
#endif
            Marshal.WriteInt16(_pLength, 0, _originalLength);
#if DEBUG
            Console.WriteLine($"[*] Patching command line string max length");
#endif
            Marshal.WriteInt16(_pMaxLength, 0, _originalMaxLength);
#if DEBUG
            Console.WriteLine("[+] Args reverted\n");
#endif
        }
    }
}