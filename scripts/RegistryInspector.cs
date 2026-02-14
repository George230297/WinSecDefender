using System;
using Microsoft.Win32;

namespace SecurityInspector
{
    class Program
    {
        static void Main(string[] args)
        {
            // Default check if no args provided (Backwards compatibility: UAC Check)
            string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            string valueName = "EnableLUA";
            string expectedValue = "1";

            if (args.Length >= 3)
            {
                keyPath = args[0];
                valueName = args[1];
                expectedValue = args[2];
            }

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        Object o = key.GetValue(valueName);
                        if (o != null)
                        {
                            string currentVal = o.ToString();
                            string status = (currentVal == expectedValue) ? "SECURE" : "VULNERABLE";
                            Console.WriteLine("{{ \"status\": \"{0}\", \"value\": \"{1}\", \"expected\": \"{2}\" }}", status, currentVal, expectedValue);
                        }
                        else { 
                            Console.WriteLine("{ \"status\": \"ERROR\", \"message\": \"Value not found\" }");
                        }
                    }
                    else { 
                        Console.WriteLine("{ \"status\": \"ERROR\", \"message\": \"Key not found\" }");
                    }
                }
            }
            catch (Exception ex) { 
                // Escape quotes for simplified JSON
                string msg = ex.Message.Replace("\"", "'");
                Console.WriteLine("{{ \"status\": \"ERROR\", \"message\": \"{0}\" }}", msg);
            }
        }
    }
}