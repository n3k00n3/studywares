// This code was based by this one: https://github.com/brandonprry/gray_hat_csharp_code/blob/master/ch2_sqli_get_fuzzer/Program.cs

using System;
using System.Net;
using System.IO;

namespace Program
{
    class MainClass
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide a URL as an argument.");
                return;
            }

            string url = args[0];
            string[] parameters = ExtractParameters(url);

            foreach (string parameter in parameters)
            {
                string xssUrl = AppendPayload(url, parameter, "fd<xss>sa");
                string sqlUrl = AppendPayload(url, parameter, "fd'sa");

                string sqlResponse = SendRequest(sqlUrl);
                string xssResponse = SendRequest(xssUrl);

                if (xssResponse.Contains("<xss>"))
                {
                    Console.WriteLine("Possible XSS point found in parameter: " + parameter);
                }

                if (sqlResponse.Contains("error in your SQL syntax"))
                {
                    Console.WriteLine("SQL injection point found in parameter: " + parameter);
                }
            }
        }

        static string[] ExtractParameters(string url)
        {
            string queryString = url.Substring(url.IndexOf('?') + 1);
            return queryString.Split('&');
        }

        static string AppendPayload(string url, string parameter, string payload)
        {
            return url.Replace(parameter, parameter + payload);
        }

        static string SendRequest(string url)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                if (ex.Response != null)
                {
                    using (StreamReader reader = new StreamReader(ex.Response.GetResponseStream()))
                    {
                        return reader.ReadToEnd();
                    }
                }
                else
                {
                    Console.WriteLine("Error sending request: " + ex.Message);
                    return string.Empty;
                }
            }
        }
    }
}
