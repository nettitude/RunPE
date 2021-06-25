using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace RunPE.Helpers
{
    class FileLogger
    {
#if LOG_TO_FILE
       
        FileStream logFileOutputStream;
        StreamWriter streamWriter;
        readonly TextWriter oldConsoleOut = Console.Out;

        public void RedirectStdOutToFile()
        {
            var timestamp = DateTime.Now.Ticks;
            var logfile = $"C:\\Users\\public\\runpe-{timestamp}.log";
            try
            {
                logFileOutputStream = new FileStream(logfile, FileMode.OpenOrCreate, FileAccess.Write);
                streamWriter = new StreamWriter(logFileOutputStream)
                {
                    AutoFlush = true
                };
                Console.SetOut(streamWriter);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot open {logfile} for writing");
                Console.WriteLine(e.Message);
            }
        }

        public void ResetFileLoggingToStdOut()
        {
            if (streamWriter != null)
            {
                streamWriter.Close();
            }
            if (logFileOutputStream != null)
            {
                logFileOutputStream.Close();
            }
            Console.SetOut(oldConsoleOut);
        }
#endif

    }
}
