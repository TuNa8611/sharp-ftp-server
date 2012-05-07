using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpFtpServer
{
    class Program
    {
        static void Main(string[] args)
        {
            using (FtpServer server = new FtpServer())
            {
                server.Start();

                Console.WriteLine("Press any key to stop...");
                Console.ReadKey(true);
            }
        }
    }
}
