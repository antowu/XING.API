using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Xing.Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // The consumer key and consumer secret from https://dev.xing.com/
            var consumerKey = "***YOUR_CONSUMER_KEY***";
            var consumerSecret = "***YOUR_CONSUMER_SECRET***";

            // Initialize a new XingApi instance
            var api = new XingApi(consumerKey, consumerSecret);
            
            // Open the authorization web page
            var authorizationUrl = api.GetAuthorizationUrl();
            Console.WriteLine("Press Enter to open the authentication and authorization web page in your default browser ({0}).", authorizationUrl);
            Console.ReadKey();
            Process.Start(authorizationUrl);
            
            // Acquire an access token
            Console.Write("Please enter the PIN from the authorization page and confirm the input with Enter: ");
            var pin = Console.ReadLine();
            api.AcquireAccessToken(pin);

            // Output the user's profile in JSON format
            var userProfile = api.GetCurrentUser();
            Console.WriteLine("Profile data:");
            Console.WriteLine(userProfile);

            Console.WriteLine();
            Console.WriteLine("Press Enter to close.");
            Console.ReadKey();
        }
    }
}
