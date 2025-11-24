using System;
using Microsoft.Win32;

namespace SecurityInspector
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Ruta para verificar UAC (User Account Control)
                string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
                
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        Object o = key.GetValue("EnableLUA");
                        if (o != null)
                        {
                            // 1 = Seguro, 0 = Vulnerable
                            int uacValue = Convert.ToInt32(o);
                            Console.WriteLine(uacValue == 1 ? "SECURE" : "VULNERABLE");
                        }
                        else { Console.WriteLine("ERROR: Value not found"); }
                    }
                    else { Console.WriteLine("ERROR: Key not found"); }
                }
            }
            catch (Exception ex) { Console.WriteLine("ERROR: " + ex.Message); }
        }
    }
}