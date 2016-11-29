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
        private static bool TestMode = false;
        public static int Main(string[] args)
        {
            CommandLineApplication commandLineApplication = new CommandLineApplication(throwOnUnexpectedArg: false);

            var clientKeyOption = commandLineApplication.Option("-c | --client-key <client_key>", "The client key or id for the requesting application", CommandOptionType.SingleValue);
            var clientSecretOption = commandLineApplication.Option("-s | --client-secret <client_secret>", "Client secret", CommandOptionType.SingleValue);
            var testModeOption = commandLineApplication.Option("-x | --test", "test mode", CommandOptionType.NoValue);

            var getRequestToken = commandLineApplication.Command("getrequesttoken", (target) =>
            {
                Console.WriteLine("configure getRequestToken");

                var callbackUrlOption = target.Option("-b|--callback-url <callback_url>", "callback url", CommandOptionType.SingleValue);
                target.OnExecute(() =>
                {
                    TestMode = testModeOption.HasValue();

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

            var handleRedirect = commandLineApplication.Command("getaccesstoken", (target) =>
            {
                var verifierOption = target.Option("-r|--oauth-verifier <oauth_verifier>", "token verifier", CommandOptionType.SingleValue);
                var tokenOption = target.Option("-t|--oauth-token <oauth_token>", "token", CommandOptionType.SingleValue);
                var tokenSecretOption = target.Option("-k|--oauth-token-secret <oauth_token_secret>", "token secret", CommandOptionType.SingleValue);
                Console.WriteLine("configure getaccesstoken");

                target.OnExecute(() =>
                {
                    TestMode = testModeOption.HasValue();

                    if (!clientKeyOption.HasValue())
                    {
                        Console.WriteLine("Error: getaccesstoken requires Client Key option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!clientSecretOption.HasValue())
                    {
                        Console.WriteLine("Error: getaccesstoken requires Client Secret option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!verifierOption.HasValue())
                    {
                        Console.WriteLine("Error: getaccesstoken requires Verifier option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!tokenOption.HasValue())
                    {
                        Console.WriteLine("Error: getaccesstoken requires token option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!tokenSecretOption.HasValue())
                    {
                        Console.WriteLine($"Error: getaccesstoken requires token secret option to be specified");
                        target.ShowHelp();
                        return 2;
                    }
                    GetTwitterAccessToken(verifierOption.Value(), clientKeyOption.Value(), clientSecretOption.Value(), tokenOption.Value(), tokenSecretOption.Value()).Wait();
                    Console.WriteLine("execute getaccesstoken");
                    return 0;
                });
            });

            commandLineApplication.Command("verifyaccesstoken", (target) =>
            {
                var accessTokenOption = target.Option("-t|--access-token <access_token>", "access token", CommandOptionType.SingleValue);
                var accessTokenSecretOption = target.Option("-k|--access-token-secret <access_token_secret> ", "access token secret", CommandOptionType.SingleValue);

                target.OnExecute(() =>
                {

                    if (!clientKeyOption.HasValue())
                    {
                        Console.WriteLine("Error: verifyaccesstoken requires Client Key option to be specified");
                        target.ShowHelp();
                        return 2;
                    }

                    if (!clientSecretOption.HasValue())
                    {
                        Console.WriteLine("Error: verifyaccesstoken requires Client Secret option to be specified");
                        target.ShowHelp();
                        return 2;
                    }
                    if (!accessTokenOption.HasValue())
                    {
                        Console.WriteLine("Error: access token option must be specified for this command.");
                        return 2;
                    }

                    if (!accessTokenSecretOption.HasValue())
                    {
                        Console.WriteLine("Error: access token secret must be specified for this command.");
                        return 2;
                    }

                    VerifyTwitterCredentials(clientKeyOption.Value(), clientSecretOption.Value(), accessTokenOption.Value(), accessTokenSecretOption.Value()).Wait();

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

        public static Dictionary<string, string> GetDefaultOAuthAuthorizationParams(string clientKey)
        {
            Dictionary<string, string> authorizationParams = new Dictionary<string, string>();

            authorizationParams.AddUrlEncodedKeyValuePair("oauth_consumer_key", clientKey);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_nonce", GenerateNonce());
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature_method", "HMAC-SHA1");
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_timestamp", SecondsSinceEpoch().ToString());
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_version", "1.0");
            return authorizationParams;
        }

        public static AuthenticationHeaderValue GetHeaderFromParams(Dictionary<string, string> authorizationParams)
        {
            var oAuthHeaderValue = string.Join(", ", authorizationParams.OrderBy((kv) => kv.Key).Select((param) => $"{param.Key}=\"{param.Value}\""));
            return new AuthenticationHeaderValue("OAuth", oAuthHeaderValue);
        }

        public static async Task GetTwitterAccessToken(string verifier, string clientKey, string clientSecret, string token, string tokenSecret)
        {

            const string twitterAccessTokenUrl = "https://api.twitter.com/oauth/access_token";
            if (TestMode)
            {
                clientKey = "cChZNFj6T5R0TigYB9yd1w";
                clientSecret = "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg";
                verifier = "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY";
                token = "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0";
                tokenSecret = "veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI";
            }
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            var authorizationParams = GetDefaultOAuthAuthorizationParams(clientKey);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_token", token);

            Dictionary<string, string> bodyParams = new Dictionary<string, string>();
            bodyParams.Add("oauth_verifier", verifier);

            if (TestMode)
            {
                authorizationParams["oauth_nonce"] = "a9900fe68e2573b27a37f10fbad6a755";
                authorizationParams["oauth_timestamp"] = "1318467427";
            }

            var signature = GetSignatureForRequest(HttpMethod.Post, twitterAccessTokenUrl, authorizationParams.Concat(bodyParams), clientSecret, tokenSecret);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature", signature);
            client.DefaultRequestHeaders.Authorization = GetHeaderFromParams(authorizationParams);
            Console.WriteLine($"Signature: {signature}");

            if (TestMode)
            {
                return;
            }

            FormUrlEncodedContent content = new FormUrlEncodedContent(bodyParams);
            var response = await client.PostAsync(twitterAccessTokenUrl, content);
            Console.WriteLine($"Response StatusCode: {response.StatusCode}");
            var responseString = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Response: {responseString}");
            var responseParams = QueryHelpers.ParseQuery(responseString);
            foreach (var responseParam in responseParams)
            {
                Console.WriteLine($"{responseParam.Key} {string.Join(", ", responseParam.Value)}");
            }
        }

        public static async Task VerifyTwitterCredentials(string clientKey, string clientSecret, string token, string tokenSecret)
        {
            Console.WriteLine("Verifying token...");
            const string twitterVerifyCredentialsUrl = "https://api.twitter.com/1.1/account/verify_credentials.json";
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var authorizationParams = GetDefaultOAuthAuthorizationParams(clientKey);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_token", token);

            var signature = GetSignatureForRequest(HttpMethod.Get, twitterVerifyCredentialsUrl, authorizationParams, clientSecret, tokenSecret);
            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature", signature);

            client.DefaultRequestHeaders.Authorization = GetHeaderFromParams(authorizationParams);

            var response = await client.GetAsync(twitterVerifyCredentialsUrl);

            Console.WriteLine($"Response Code: {response.StatusCode}");

            var responseTxt = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"Response: {responseTxt}");
        }

        public static string GetSignatureForRequest(HttpMethod method, string requestUrl, IEnumerable<KeyValuePair<string, string>> requestParams, string clientSecret, string tokenSecret)
        {
            string orderParameterString = string.Join("&", requestParams.OrderBy((kv) => kv.Key).Select((h) => $"{h.Key}={h.Value}"));
            var signatureBaseString = GetSignatureBaseString(method, requestUrl, orderParameterString);
            var signingKey = GetSigningKey(clientSecret, tokenSecret);
            return GetSignature(signatureBaseString, signingKey);
        }

        public static async Task GetTwitterRequestToken(string clientKey, string clientSecret, string callbackUrl)
        {
            if (TestMode)
            {
                clientKey = "cChZNFj6T5R0TigYB9yd1w";
                clientSecret = "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg";
                callbackUrl = "http://localhost/sign-in-with-twitter/";
            }
            const string twitterRequestTokenUrl = "https://api.twitter.com/oauth/request_token";
            HttpClient client = new HttpClient();
            Dictionary<string, string> authorizationParams = GetDefaultOAuthAuthorizationParams(clientKey);

            if (TestMode)
            {
                authorizationParams["oauth_nonce"] = "ea9ec8429b68d6b77cd5600adbbb0456";
                authorizationParams["oauth_timestamp"] = "1318467427";
            }

            authorizationParams.AddUrlEncodedKeyValuePair("oauth_callback", callbackUrl);


            var signature = GetSignatureForRequest(HttpMethod.Post, twitterRequestTokenUrl, authorizationParams, clientSecret, null);

            Console.WriteLine($"Signature: {signature}");
            if (TestMode)
            {
                return;
            }

            authorizationParams.AddUrlEncodedKeyValuePair("oauth_signature", signature);
            client.DefaultRequestHeaders.Authorization = GetHeaderFromParams(authorizationParams);
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
