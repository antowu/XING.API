using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Xing
{
    /// <summary>
    /// Handles OAuth authorizations.
    /// </summary>
    internal class OAuth
    {
        private const string UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0);

        private Random random = new Random();
        private Dictionary<string, string> parameterValues = new Dictionary<string, string>();

        public OAuth()
        {
            parameterValues["version"] = "1.0";
            parameterValues["timestamp"] = GenerateTimeStamp();
            parameterValues["nonce"] = GenerateNonce();
            parameterValues["signature_method"] = "HMAC-SHA1";
            parameterValues["signature"] = "";
            parameterValues["callback"] = "oob";
            parameterValues["consumer_key"] = "";
            parameterValues["consumer_secret"] = "";
            parameterValues["token"] = "";
            parameterValues["token_secret"] = "";
        }

        /// <summary>
        /// Gets or sets OAuth parameter values.
        /// </summary>
        /// <remarks>Use the parameter name without the oauth_ prefix.</remarks>
        public string this[string parameter]
        {
            get
            {
                if (parameterValues.ContainsKey(parameter))
                    return parameterValues[parameter];
                else
                    throw new ArgumentException("Invalid parameter.");
            }
            set
            {
                if (parameterValues.ContainsKey(parameter))
                    parameterValues[parameter] = value;
                else
                    throw new ArgumentException("Invalid parameter.");
            }
        }

        /// <summary>
        /// Acquires a request token, from the given URI, using the given HTTP method.
        /// </summary>
        /// <remarks>
        /// To use this method, first instantiate a new <see cref="OAuth"/> instance, then set the
        /// callback param (oauth["callback"]='oob'). After the call returns, you should direct the
        /// user to open a browser window to the authorization page for the OAuth-enabled service.
        /// Or, you can automatically open that page yourself. Do this with
        /// <c>System.Diagnostics.Process.Start()</c>, passing the URL of the page. There should be
        /// one query param: oauth_token with the value obtained from oauth["token"].
        /// </remarks>
        public OAuthResponse AcquireRequestToken(string uri, string method)
        {
            NewRequest();
            var authorizationHeader = GetAuthorizationHeader(uri, method);

            // Prepare the token request
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add("Authorization", authorizationHeader);
            request.Method = method;

            using (var webResponse = (HttpWebResponse)request.GetResponse())
            {
                using (var reader = new StreamReader(webResponse.GetResponseStream()))
                {
                    var oauthResponse = new OAuthResponse(reader.ReadToEnd());
                    this["token"] = oauthResponse["oauth_token"];

                    // Sometimes the request_token URL gives us an access token, with no user
                    // interaction required; e.g., when prior approval has already been granted.
                    try
                    {
                        if (oauthResponse["oauth_token_secret"] != null)
                            this["token_secret"] = oauthResponse["oauth_token_secret"];
                    }
                    catch { }

                    return oauthResponse;
                }
            }
        }

        /// <summary>
        /// Acquires an access token from the given URI, using the given HTTP method.
        /// </summary>
        /// <remarks>
        /// To use this method, you must first set the oauth_token to the value of the request
        /// token; e.g., oauth["token"] = "whatever".
        /// </remarks>
        public OAuthResponse AcquireAccessToken(string uri, string method, string pin)
        {
            NewRequest();
            parameterValues["verifier"] = pin;
            var authorizationHeader = GetAuthorizationHeader(uri, method);

            // Prepare the token request
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add("Authorization", authorizationHeader);
            request.Method = method;

            using (var webResponse = (HttpWebResponse)request.GetResponse())
            {
                using (var reader = new StreamReader(webResponse.GetResponseStream()))
                {
                    var oauthResponse = new OAuthResponse(reader.ReadToEnd());
                    this["token"] = oauthResponse["oauth_token"];
                    this["token_secret"] = oauthResponse["oauth_token_secret"];
                    return oauthResponse;
                }
            }
        }

        /// <summary>
        /// Generates a string to be used in an Authorization header in an HTTP request.
        /// </summary>
        public string GenerateAuthorizationHeader(string uri, string method)
        {
            NewRequest();
            parameterValues["callback"] = null;
            parameterValues["verifier"] = null;

            return GetAuthorizationHeader(uri, method, null);
        }

        /// <summary>
        /// Generates the timestamp for the signature.
        /// </summary>
        private static string GenerateTimeStamp()
        {
            return DateTime.UtcNow.Subtract(Epoch).TotalSeconds.ToString("F0");
        }

        /// <summary>
        /// Encodes an URL OAuth-compliant.
        /// </summary>
        private static string UrlEncode(string value)
        {
            var result = new StringBuilder();
            foreach (char ch in value)
            {
                if (UnreservedChars.IndexOf(ch) != -1)
                    result.Append(ch);
                else
                    result.Append('%' + String.Format("{0:X2}", (int)ch));
            }
            return result.ToString();
        }

        /// <summary>
        /// Formats the list of request parameters into a string according to the requirements of OAuth;
        /// the resulting string can be used in the Authorization header of the request.
        /// </summary>
        private static string EncodeRequestParameters(ICollection<KeyValuePair<string, string>> p)
        {
            var sb = new StringBuilder();
            foreach (var item in p.OrderBy(x => x.Key))
            {
                if (!string.IsNullOrEmpty(item.Value) && !item.Key.EndsWith("secret"))
                    sb.AppendFormat("oauth_{0}=\"{1}\", ", item.Key, UrlEncode(item.Value));
            }
            return sb.ToString().TrimEnd(new[] { ' ', ',' });
        }

        /// <summary>
        /// Renews the nonce and timestamp on the OAuth parameters.
        /// </summary>
        /// <remarks>Each new request should get a new, current timestamp, and a nonce.</remarks>
        private void NewRequest()
        {
            parameterValues["nonce"] = GenerateNonce();
            parameterValues["timestamp"] = GenerateTimeStamp();
        }

        /// <summary>
        /// Generates an OAuth nonce.
        /// </summary>
        private string GenerateNonce()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                switch (random.Next(3))
                {
                    case 0: // Lowercase alpha
                        sb.Append((char)(random.Next(26) + 97), 1);
                        break;
                    default: // Numeric digit
                        sb.Append((char)(random.Next(10) + 48), 1);
                        break;
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Extracts all query string parameters from a URL that are not related to OAuth.
        /// </summary>
        private Dictionary<string, string> ExtractQueryParameters(string queryString)
        {
            if (queryString.StartsWith("?"))
                queryString = queryString.Remove(0, 1);

            var result = new Dictionary<string, string>();

            if (string.IsNullOrEmpty(queryString))
                return result;

            foreach (var field in queryString.Split('&'))
            {
                if (!string.IsNullOrEmpty(field) && !field.StartsWith("oauth_"))
                {
                    if (field.IndexOf('=') > -1)
                    {
                        var temp = field.Split(new[] { '=' }, 2);
                        result.Add(temp[0], temp[1]);
                    }
                    else
                        result.Add(field, string.Empty);
                }
            }

            return result;
        }
        
        private string GetAuthorizationHeader(string uri, string method)
        {
            return GetAuthorizationHeader(uri, method, null);
        }

        private string GetAuthorizationHeader(string uri, string method, string realm)
        {
            if (string.IsNullOrEmpty(parameterValues["consumer_key"]))
                throw new ArgumentNullException("consumer_key");

            if (string.IsNullOrEmpty(parameterValues["signature_method"]))
                throw new ArgumentNullException("signature_method");

            Sign(uri, method);

            var encodedRequestParams = EncodeRequestParameters(this.parameterValues);
            return (string.IsNullOrEmpty(realm)) ?
                "OAuth " + encodedRequestParams :
                string.Format("OAuth realm=\"{0}\", ", realm) + encodedRequestParams;
        }

        private void Sign(string uri, string method)
        {
            var signatureBase = GetSignatureBase(uri, method);
            var hash = GetHash();

            var dataBuffer = Encoding.ASCII.GetBytes(signatureBase);
            var hashBytes = hash.ComputeHash(dataBuffer);

            this["signature"] = Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Formats the list of request parameters into a "signature base" string as defined
        /// by RFC 5849; this will then be MAC'd with a suitable hash.
        /// </summary>
        private string GetSignatureBase(string url, string method)
        {
            // Normalize the URI
            var uri = new Uri(url);
            var normUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);
            if (!((uri.Scheme == "http" && uri.Port == 80) ||
                  (uri.Scheme == "https" && uri.Port == 443)))
                normUrl += ":" + uri.Port;

            normUrl += uri.AbsolutePath;

            // The sigbase starts with the method and the encoded URI
            var sb = new System.Text.StringBuilder();
            sb.Append(method)
                .Append('&')
                .Append(UrlEncode(normUrl))
                .Append('&');

            // The parameters follow: all OAuth params plus any params on the URI
            var p = ExtractQueryParameters(uri.Query);

            // Add all non-empty params to the "current" params
            foreach (var paramValue in this.parameterValues)
            {
                // Exclude all OAuth params that are secret or signatures; any secrets should
                // be kept to ourselves, and any existing signature will be invalid.
                if (!string.IsNullOrEmpty(this.parameterValues[paramValue.Key]) &&
                    !paramValue.Key.EndsWith("_secret") &&
                    !paramValue.Key.EndsWith("signature"))
                    p.Add("oauth_" + paramValue.Key, paramValue.Value);
            }

            // Concat and format all those parameters
            var sb2 = new StringBuilder();
            foreach (var item in p.OrderBy(x => x.Key))
            {
                // Even "empty" parameters need to be encoded this way
                sb2.AppendFormat("{0}={1}&", item.Key, item.Value);
            }

            // Append the URL-encoded version of that string to the sigbase
            sb.Append(UrlEncode(sb2.ToString().TrimEnd('&')));

            return sb.ToString();
        }

        private HashAlgorithm GetHash()
        {
            if (this["signature_method"] != "HMAC-SHA1")
                throw new NotImplementedException();

            var keystring = string.Format("{0}&{1}",
                UrlEncode(this["consumer_secret"]),
                UrlEncode(this["token_secret"]));
            var hmacsha1 = new HMACSHA1
            {
                Key = Encoding.ASCII.GetBytes(keystring)
            };
            return hmacsha1;
        }

        /// <summary>
        /// Holds an OAuth response message.
        /// </summary>
        public class OAuthResponse
        {
            private Dictionary<string, string> parameterValues = new Dictionary<string, string>();

            /// <summary>
            /// Gets all of the text in the response; this is useful if the app wants to do its own parsing.
            /// </summary>
            public string AllText { get; protected set; }

            /// <summary>
            /// Gets an OAuth response parameter value.
            /// </summary>
            public string this[string parameter]
            {
                get { return parameterValues[parameter]; }
            }

            public OAuthResponse(string allText)
            {
                AllText = allText;
                var keyValuePairs = allText.Split('&');
                foreach (var pair in keyValuePairs)
                {
                    var keyValue = pair.Split(new[] { '=' }, 2);
                    parameterValues.Add(keyValue[0], keyValue[1]);
                }
            }
        }
    }
}