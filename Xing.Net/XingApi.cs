using System.IO;
using System.Net;
using System.Text;

namespace Xing
{
    /// <summary>
    /// Provides access to the XING API.
    /// </summary>
    public class XingApi
    {
        /// <summary>
        /// The base URL for all XING API calls.
        /// </summary>
        private const string BaseUrl = "https://api.xing.com/v1/";

        /// <summary>
        /// The manager for handling the OAuth autorization.
        /// </summary>
        private OAuth oauth = new OAuth();

        public XingApi(string consumerKey, string consumerSecret)
            : this()
        {
            ConsumerKey = consumerKey;
            ConsumerSecret = consumerSecret;
        }

        public XingApi(string token)
            : this()
        {
            Token = token;
        }

        public XingApi()
        {
        }

        /// <summary>
        /// Gets or sets the consumer key assigned to the application.
        /// </summary>
        public string ConsumerKey
        {
            get { return oauth["consumer_key"]; }
            set { oauth["consumer_key"] = value; }
        }

        /// <summary>
        /// Gets or sets the consumer secret assigned to the application.
        /// </summary>
        public string ConsumerSecret
        {
            get { return oauth["consumer_secret"]; }
            set { oauth["consumer_secret"] = value; }
        }

        /// <summary>
        /// Gets or sets the OAuth token for accessing the API.
        /// </summary>
        public string Token
        {
            get { return oauth["token"]; }
            set { oauth["token"] = value; }
        }

        /// <summary>
        /// Obtains a request token and returns the URL where the user needs to authenticate
        /// and authorize the application.
        /// </summary>
        public string GetAuthorizationUrl()
        {
            // Obtain a temporary token for initiating the authentication and authorization process
            var requestTokenUrl = string.Format("{0}request_token", BaseUrl);
            oauth.AcquireRequestToken(requestTokenUrl, "POST");

            // Generate the URL where the user needs to authenticate and authorize the application
            var autorizationUrl = string.Format("{0}authorize?oauth_token={1}", BaseUrl, Token);
            return autorizationUrl;
        }

        /// <summary>
        /// Exchanges the request token obtained by <see cref="GetAuthorizationUrl"/> for an
        /// access token.
        /// </summary>
        /// <param name="pin">The PIN/verifier from the authentication and authorization web page.</param>
        public void AcquireAccessToken(string pin)
        {
            // Exchange the request token/pin for an access token
            var accessTokenUrl = string.Format("{0}access_token", BaseUrl);
            oauth.AcquireAccessToken(accessTokenUrl, "POST", pin);
        }

        /// <summary>
        /// Gets the app user's details.
        /// </summary>
        public string GetCurrentUser()
        {
            var url = string.Format("{0}users/me", BaseUrl);
            return MakeGetRequest(url);
        }

        /// <summary>
        /// Sends a GET request to the specified URL and returns the plain-text response 
        /// </summary>
        private string MakeGetRequest(string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.PreAuthenticate = true;
            request.AllowWriteStreamBuffering = true;
            request.Headers.Add("Authorization", oauth.GenerateAuthorizationHeader(url, "GET"));

            using (var webResponse = (HttpWebResponse)request.GetResponse())
            {
                if (webResponse.StatusCode != HttpStatusCode.OK)
                {
                    throw new HttpStatusCodeException(webResponse.StatusCode);
                }
                else
                {
                    using (var responseStream = webResponse.GetResponseStream())
                    using (var responseStreamReader = new StreamReader(responseStream, Encoding.UTF8))
                    {
                        return responseStreamReader.ReadToEnd();
                    }
                }
            }
        }
    }
}