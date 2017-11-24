using System;
using System.IO;
using Microsoft.AspNetCore.Hosting;

namespace Accounts
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Accounts";

            var host = new WebHostBuilder()
                .UseKestrel()
                .UseUrls("http://localhost:5000")
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .UseApplicationInsights()
                .Build();

            host.Run();
        }
    }
}
