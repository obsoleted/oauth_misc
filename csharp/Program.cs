using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace ConsoleApplication
{
    public class Program
    {
        public static int Main(string[] args)
        {
            CommandLineApplication commandLineApplication = new CommandLineApplication(throwOnUnexpectedArg: false);

            var clientKeyOption = commandLineApplication.Option("-c | --client-key <client_key>", "The client key or id for the requesting application", CommandOptionType.SingleValue);
            var clientSecretOption = commandLineApplication.Option("-s | --client-secret <client_secret>", "Client secret", CommandOptionType.SingleValue);

            var getRequestToken = commandLineApplication.Command("getrequesttoken", (target) =>
            {
                Console.WriteLine("configure getRequestToken");

                var callbackUrlOption = target.Option("-b|--callback-url <callback_url>", "callback url", CommandOptionType.SingleValue);
                target.OnExecute(() =>
                {
                    Console.WriteLine($"execute getrequesttoken '{clientSecretOption.Value() ?? String.Empty}'");
                    if (!clientKeyOption.HasValue())
                    {
                        Console.WriteLine("Error: getrequesttoken requires Client Key option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!clientSecretOption.HasValue())
                    {
                        Console.WriteLine("Error: getrequesttoken requires Client Secret option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!callbackUrlOption.HasValue())
                    {
                        Console.WriteLine("Error: getrequesttoken requires Callback Url option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    GetTwitterRequestToken(clientKeyOption.Value(), clientSecretOption.Value(), callbackUrlOption.Value()).Wait();
                    return 0;
                });
            }, false);

            var handleRedirect = commandLineApplication.Command("handleredirect", (target) =>
            {
                Console.WriteLine("configure handleredirect");
                target.OnExecute(() =>
                {
                    Console.WriteLine("execute handleredirect");
                    return 0;
                });
            });

            commandLineApplication.OnExecute(() =>
            {
                if (clientKeyOption.HasValue())
                {
                    Console.WriteLine($"ClientKey: {clientKeyOption.Value()}");
                }
                Console.WriteLine("Hello World!");
                return 0;
            });

            return commandLineApplication.Execute(args);
        }

        public static Random Random = new Random();

        public static async Task GetTwitterRequestToken(string clientKey, string clientSecret, string callbackUrl)
        {
            const string twitterRequestTokenUrl = "https://api.twitter.com/oauth/request_token";
            HttpClient client = new HttpClient();
            StringContent content = new StringContent("string", Encoding.UTF8, "application/json");
            Dictionary<string, string> authorizationParams = new Dictionary<string, string>();

            authorizationParams.AddUrlEncodedKeyValuePair("oauth_callback", callbackUrl);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_consumer_key", clientKey);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_nonce", GenerateNonce());
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature_method", "HMAC-SHA1");
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_timestamp", SecondsSinceEpoch().ToString());
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_version", "1.0");

            string orderParameterString = string.Join("&", authorizationParams.OrderBy((kv) => kv.Key).Select((h) => $"{h.Key}={h.Value}"));

            Console.WriteLine(orderParameterString);
            var signatureBaseString = GetSignatureBaseString(HttpMethod.Post, twitterRequestTokenUrl, orderParameterString);
            var signingKey = GetSigningKey(clientSecret, null);
            var signature = GetSignature(signatureBaseString, signingKey);

            Console.WriteLine($"Ordered Parameters: {orderParameterString}");
            Console.WriteLine($"SignatureBaseString: {signatureBaseString}");
            Console.WriteLine($"SigningKey: {signingKey}");
            Console.WriteLine($"Signature: {signature}");

            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature", signature);
            var oAuthHeaderValue = string.Join(", ", authorizationParams.Select((param) => $"{param.Key}=\"{param.Value}\""));
            Console.WriteLine($"oAuthHeaderValue: {oAuthHeaderValue}");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", oAuthHeaderValue);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var result = await client.PostAsync(twitterRequestTokenUrl, new StringContent(""));

            Console.WriteLine($"Result Status Code: {result.StatusCode}");

            var responseString = await result.Content.ReadAsStringAsync();

            Console.WriteLine($"Response: {responseString}");
            var responseParams = QueryHelpers.ParseQuery(responseString);

            foreach (var responseParam in responseParams)
            {
                Console.WriteLine($"{responseParam.Key} {string.Join(", ", responseParam.Value)}");
            }
        }

        public static string GetSignature(string signatureBaseString, string signingKey)
        {
            byte[] key = Encoding.ASCII.GetBytes(signingKey);
            HMACSHA1 hmachSha1 = new HMACSHA1(key);
            byte[] baseBytes = Encoding.ASCII.GetBytes(signatureBaseString);
            return Convert.ToBase64String(hmachSha1.ComputeHash(baseBytes));
        }

        public static string GetSigningKey(string clientSecret, string tokenSecret)
        {
            clientSecret = clientSecret ?? string.Empty;
            tokenSecret = tokenSecret ?? string.Empty;

            return $"{WebUtility.UrlEncode(clientSecret)}&{WebUtility.UrlEncode(tokenSecret)}";
        }

        public static string GetSignatureBaseString(HttpMethod method, string url, string parameters)
        {
            return $"{method.Method.ToString().ToUpper()}&{WebUtility.UrlEncode(url)}&{WebUtility.UrlEncode(parameters)}";
        }

        public static string GenerateNonce()
        {
            byte[] randomBytes = new byte[32];
            Random.NextBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        public static long SecondsSinceEpoch()
        {
            // I'm guessing there is a better way to do this?
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (long)t.TotalSeconds;
        }
    }

    public static class Extensions
    {
        public static void AddUrlEncodedKeyValuePair(this Dictionary<string, string> authParams, string key, string value)
        {
            authParams.Add(System.Net.WebUtility.UrlEncode(key),
                System.Net.WebUtility.UrlEncode(value));
        }
    }
}
