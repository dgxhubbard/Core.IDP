using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;


using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ClientApp
{
    internal class Program
    {
        static async Task Main ( string [] args )
        {
            try
            {
                var dbPath = Path.GetDirectoryName ( Assembly.GetExecutingAssembly ().Location );



                var host = new HostBuilder ()

                    //.ConfigureLogging(options => options.AddDebug())
                    .ConfigureServices ( services =>
                    {
                        services.AddDbContext<DbContext> ( options =>
                        {
                            options.UseSqlite ( $"Filename={Path.Combine ( dbPath, "clientapp.db3" )}" );
                            options.UseOpenIddict ();
                        } );


                        services.AddOpenIddict ()

                            // Register the OpenIddict Core. components.
                            .AddCore ( options =>
                            {
                                // Configure OpenIddict to use the Entity Framework Core. stores and models.
                                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                                options.UseEntityFrameworkCore ()
                                       .UseDbContext<DbContext> ();
                            } )

                            // Register the OpenIddict client components.
                            .AddClient ( options =>
                            {
                                // Note: this sample uses the authorization code flow,
                                // but you can enable the other flows if necessary.
                                options.AllowAuthorizationCodeFlow ()
                                       .AllowRefreshTokenFlow ();

                                // Register the signing and encryption credentials used to protect
                                // sensitive data like the state tokens produced by OpenIddict.
                                options.AddDevelopmentEncryptionCertificate ()
                                       .AddDevelopmentSigningCertificate ();

                                // Add the operating system integration.
                                options.UseSystemIntegration ()
                                       .SetAllowedEmbeddedWebServerPorts ( 7000 );

                                // Register the System.Net.Http integration and use the identity of the current
                                // assembly as a more specific user agent, which can be useful when dealing with
                                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                                options.UseSystemNetHttp ()
                                       .SetProductInformation ( typeof ( Program ).Assembly );

                                // Add a client registration matching the client application definition in the server project.
                                options.AddRegistration ( new OpenIddictClientRegistration
                                {
                                    Issuer = new Uri ( "https://localhost:7296/", UriKind.Absolute ),
                                    ProviderName = "Local",

                                    ClientId = "core_api_client",

                                    RedirectUri = new Uri ( "http://localhost:7000/", UriKind.Absolute ),
                                    //Scopes = { Scopes.OpenId, "gtapi" }
                                } );
                            } );

                        //services.AddHttpClient ();

                        //services.AddControllersWithViews ();

                        // Register the worker responsible for creating the database used to store tokens
                        // and adding the registry entries required to register the custom URI scheme.
                        //
                        // Note: in a real world application, this step should be part of a setup script.
                        services.AddHostedService<Worker> ();

                        // Register the background service responsible for handling the console interactions.
                        services.AddHostedService<InteractiveService> ();

                    } )
                    .UseConsoleLifetime ()
                    .Build ();

                await host.RunAsync ();
            }
            catch ( Exception ex ) 
            { 
            
                var msg = ex.Message;
            }
            
        }
    }
}