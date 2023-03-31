using System;
using System.ComponentModel;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Client;






namespace ClientApp
{
    internal class Program
    {
        static ServiceCollection Services
        { get; set; }

        static void Main ( string [] args )
        {
            var services = new ServiceCollection ();


            Services = services;

            services.AddOpenIddict ()

                // Register the OpenIddict client components.
                .AddClient ( options =>
                {
                    // Allow grant_type=client_credentials to be negotiated.
                    options.AllowClientCredentialsFlow ();

                    // Disable token storage, which is not necessary for non-interactive flows like
                    // grant_type=password, grant_type=client_credentials or grant_type=refresh_token.
                    options.DisableTokenStorage ();

                    // Register the System.Net.Http integration and use the identity of the current
                    // assembly as a more specific user agent, which can be useful when dealing with
                    // providers that use the user agent as a way to throttle requests (e.g Reddit).
                    options.UseSystemNetHttp ()
                           .SetProductInformation ( typeof ( Program ).Assembly );

                    // Add a client registration matching the client application definition in the server project.
                    options.AddRegistration ( new OpenIddictClientRegistration
                    {
                        Issuer = new Uri ( "https://localhost:7296/", UriKind.Absolute ),

                        ClientId = "core_api_console",
                        ClientSecret = "E2B00F84-82D2-4D43-B081-B4B88283175A",
                    } );

                } );

            Run ();
        }

        

        static async void Run ()
        {
            try
            {
                await using var provider = Services.BuildServiceProvider ();

                var token = GetTokenAsync ( provider );


                Console.WriteLine ( "Access token: {0}", token );
                Console.WriteLine ();

                var resource = await GetResourceAsync ( provider, token );
                Console.WriteLine ( "API response: {0}", resource );
                Console.ReadLine ();
            }
            catch ( Exception ex ) 
            {
                Console.WriteLine ( ex.Message );
            }
        }

        //The redirection endpoint must be enabled to use the authorization code and implicit flows

        static string GetTokenAsync ( IServiceProvider provider )
        {
            var service = provider.GetRequiredService<OpenIddictClientService> ();

            var (response, _) = 
                service.AuthenticateWithClientCredentialsAsync ( new Uri ( "https://localhost:7296/", UriKind.Absolute ) ).GetAwaiter ().GetResult ();


            return response.AccessToken;
        }

        static async Task<string> GetResourceAsync ( IServiceProvider provider, string token )
        {
            using var client = provider.GetRequiredService<HttpClient> ();
            using var request = new HttpRequestMessage ( HttpMethod.Get, "https://localhost:7296/api/message" );
            request.Headers.Authorization = new AuthenticationHeaderValue ( "Bearer", token );

            using var response = await client.SendAsync ( request );
            response.EnsureSuccessStatusCode ();

            return await response.Content.ReadAsStringAsync ();
        }
    }
}