using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using RunPE.Internals;
using RunPE.Patchers;

namespace RunPE
{
    internal static class Program
    {
        private const uint EXECUTION_TIMEOUT = 30000;

        internal static Encoding encoding;

        private static int Main(string[] args)
        {

#if BREAK
            Console.WriteLine("[*] Press Enter to continue...");
            Console.ReadLine();
            Console.WriteLine("[*] Continuing...");
#endif

            try
            {
#if LOG_TO_FILE
                var fileLogger = new FileLogger();
                fileLogger.RedirectStdOutToFile();
#endif

                if (IntPtr.Size != 8)
                {
                    Console.WriteLine("\n[-] Process is not 64-bit, this version of run-exe won't work !\n");
                    return -1;
                } else

                if (args.Length == 0)
                {
                    PrintUsage();
                    return -2;
                }

                var peRunDetails = ParseArgs(args.ToList());

                if(peRunDetails == null)
                {
                    return -10;
                }

                var peMapper = new PEMapper();
                peMapper.MapPEIntoMemory(peRunDetails.binaryBytes, out var pe, out var currentBase);

                var importResolver = new ImportResolver();
                importResolver.ResolveImports(pe, currentBase);

                peMapper.SetPagePermissions();

                var argumentHandler = new ArgumentHandler();
                if (!argumentHandler.UpdateArgs(peRunDetails.filename, peRunDetails.args))
                {
                    return -3;
                }

                var fileDescriptorRedirector = new FileDescriptorRedirector();
                if (!fileDescriptorRedirector.RedirectFileDescriptors())
                {
                    Console.WriteLine("[-] Unable to redirect file descriptors");
                    return -7;
                }

                var extraEnvironmentalPatcher = new ExtraEnvironmentPatcher((IntPtr)currentBase);
                extraEnvironmentalPatcher.PerformExtraEnvironmentPatches();

                // Patch this last as may interfere with other activity
                var extraAPIPatcher = new ExtraAPIPatcher();

                if (!extraAPIPatcher.PatchAPIs((IntPtr)currentBase))
                {
                    return -9;
                }
                
                var exitPatcher = new ExitPatcher();
                if (!exitPatcher.PatchExit())
                {
                    return -8;
                }

                fileDescriptorRedirector.StartReadFromPipe();

#if BREAK
                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
#endif
                StartExecution(peRunDetails.args, pe, currentBase);
#if BREAK
                Console.WriteLine("Done, press enter...");
                Console.ReadLine();
#endif

                // Revert changes
                exitPatcher.ResetExitFunctions();
                extraAPIPatcher.RevertAPIs();
                extraEnvironmentalPatcher.RevertExtraPatches();
                fileDescriptorRedirector.ResetFileDescriptors();
                fileDescriptorRedirector.ClosePipes();
                argumentHandler.ResetArgs();
                peMapper.ClearPE();
                importResolver.ResetImports();

                // Print the output
                var output = fileDescriptorRedirector.ReadDescriptorOutput();

#if LOG_TO_FILE
               fileLogger.ResetFileLoggingToStdOut();
#endif
#if DEBUG
                Console.WriteLine("\n------------------------ EXE OUTPUT -------------------------\n");
#endif
                Console.WriteLine(output);
#if DEBUG
                Console.WriteLine("\n--------------------- END OF EXE OUTPUT ---------------------\n");
                Console.WriteLine("[+] End of RunPE\n");
#endif
#if BREAK
                Console.WriteLine("Press Enter to quit\n");
                Console.ReadLine();
#endif
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running RunPE: {e}");
#if LOG_TO_FILE
                fileLogger.ResetFileLoggingToStdOut();
#endif
                return -6;
            }
        }

        private static void StartExecution(string[] binaryArgs, PELoader pe, long currentBase)
        {

#if DEBUG
            Console.WriteLine($"\n[*] Executing loaded PE\n");
#endif
            try
            {
                var threadStart = (IntPtr)(currentBase + (int)pe.OptionalHeader64.AddressOfEntryPoint);
                var hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);

                NativeDeclarations.WaitForSingleObject(hThread, EXECUTION_TIMEOUT);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error {e}\n");
            }

        }

        private static PeRunDetails ParseArgs(List<string> args)
        {
            string filename;
            string[] binaryArgs;
            byte[] binaryBytes;

            if(args.Contains("---f") || args.Contains("---b"))
            {
                if(!(args.Contains("---f") && args.Contains("---b")))
                {
                    PrintUsage();
                    return null;
                }

                filename = args[args.IndexOf("---f") + 1];
                if (args.Contains("---a")) {
                    binaryArgs = Encoding.UTF8.GetString(Convert.FromBase64String(args[args.IndexOf("---a") + 1])).Split();
                } else
                {
                    binaryArgs = new string[] { };
                }
                
                binaryBytes = Convert.FromBase64String(args[args.IndexOf("---b") + 1]);
#if DEBUG
                Console.WriteLine($"[*] Running base64 encoded binary as file {filename} with args: '{string.Join(" ", binaryArgs)}'");
#endif
            }
            else
            {
                filename = args[0];
                binaryBytes = File.ReadAllBytes(filename);
                if(args.Count > 1)
                {
                    binaryArgs = new string[args.Count - 1];
                    Array.Copy(args.ToArray(), 1, binaryArgs, 0, args.Count - 1);
    #if DEBUG
                    Console.WriteLine($"[*] Running: {filename} with args: '{string.Join(" ", binaryArgs)}'");
    #endif
                }
                else
                {
                    binaryArgs = new string[] { };
    #if DEBUG
                    Console.WriteLine($"[*] Running: {filename} with no args");
    #endif
                }
            }
            return new PeRunDetails { filename = filename, args = binaryArgs, binaryBytes = binaryBytes};
        }

        private static void PrintUsage()
        {
            Console.WriteLine($"Usage: RunPE.exe <file-to-run> <args-to-file-to-run>");
            Console.WriteLine($"\te.g. RunPE.exe C:\\Windows\\System32\\net.exe localgroup administrators");
            Console.WriteLine($"\nAlternative usage: RunPE.exe ---f <file-to-pretend-to-be> ---b <base64 blob of file bytes> ---a <base64 blob of args>");
            Console.WriteLine($"\te.g: RunPE.exe ---f C:\\Windows\\System32\\svchost.exe ---b <net.exe, base64 encoded> ---a <localgroup administrators, base64 encoded>");
        }

    }

    internal class PeRunDetails
    {
        internal string filename;
        internal string[] args;
        internal byte[] binaryBytes;
    }

}
