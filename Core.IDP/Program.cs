using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Reflection;
using System.Security.Claims;


using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyModel;
using Microsoft.Extensions.Hosting;





using OpenIddict.EntityFrameworkCore;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;




using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Routing;
using System.Diagnostics;
using System.Net.Http.Headers;

namespace Core.IDP
{
    public class Program
    {
        public static void Main ( string [] args )
        {
            var dbPath = Path.GetDirectoryName( Assembly.GetExecutingAssembly ().Location );
            var dbName = "authorize.db";

            var connectionString = @"Data Source=" + dbPath + @"\" + dbName + ";";

            var builder = WebApplication.CreateBuilder ( args );

            // Add services to the container
            builder.Services.AddControllersWithViews ();



            builder.Services.AddDbContext<AppDbContext> ( options =>
            {

                options.UseSqlite ( connectionString );

                // Register the entity sets needed by OpenIddict.
                options.UseOpenIddict ();
            } );



            builder.Services.AddOpenIddict ()

                // Register the OpenIddict Core. components
                .AddCore ( options =>
                {
                    // Configure OpenIddict to use the EF Core. stores/models
                    options.UseEntityFrameworkCore ()
                        .UseDbContext<AppDbContext> ();
                } )

                // Register the OpenIddict server components
                .AddServer ( options =>
                {
                    options
                        .AllowAuthorizationCodeFlow ()
                        //.RequireProofKeyForCodeExchange ()
                        .AllowPasswordFlow ()
                        .AllowRefreshTokenFlow ()
                        .AllowClientCredentialsFlow ();

                    options
                        .SetAuthorizationEndpointUris ( "/connect/authorize" )
                        .SetTokenEndpointUris ( "/connect/token" )
                        .SetUserinfoEndpointUris ( "/connect/userinfo" );

                    // Encryption and signing of tokens
                    options
                        .AddEphemeralEncryptionKey ()
                        .AddEphemeralSigningKey ()
                        .DisableAccessTokenEncryption ();

                    // Register scopes (permissions)
                    options.RegisterScopes ( "gtapi" );

                    // Register the ASP.NET Core. host and configure the ASP.NET Core.-specific options
                    options
                        .UseAspNetCore ()
                        .EnableTokenEndpointPassthrough ()
                        .EnableAuthorizationEndpointPassthrough ()
                        .EnableUserinfoEndpointPassthrough ();
                } )

            // Register the OpenIddict validation components
            .AddValidation ( options =>
            {
                // Import the configuration from the local OpenIddict server instance
                options.UseLocalServer ();

                // Register the ASP.NET Core. host
                options.UseAspNetCore ();
            } );
            builder.Services.AddAuthorization ();

            
            builder.Services.AddAuthentication ( CookieAuthenticationDefaults.AuthenticationScheme )
                .AddCookie ( CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/login";
                    options.LogoutPath = "/logout";
                } );

            builder.Services.AddScoped<UserManager, UserManager> ();
            /*
            .AddAuthentication ( options =>
            {
                options.DefaultAuthenticateScheme = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCore.Defaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

            } )
                .AddCookie ();
            */
            ;


			var baseAddress = "https://localhost:7296/";
			builder.Services.AddScoped ( sp =>
			{
				var client = new HttpClient ();
				client.BaseAddress = new Uri ( baseAddress );
				return client;
			} );





			builder.Services.AddRazorPages ();

            var app = builder.Build ();

            // Configure the HTTP request pipeline.
            if ( !app.Environment.IsDevelopment () )
            {
                app.UseExceptionHandler ( "/Error" );
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts ();
            }



            app.UseHttpsRedirection ();

            app.UseStaticFiles ();

            app.UseRouting ();

            app.UseHttpsRedirection ();
            app.UseStaticFiles ();

            app.UseAuthentication ();
            app.UseAuthorization ();

            // Create new application registrations matching the values configured in Zirku.Client and Zirku.Api1.
            // Note: in a real world application, this step should be part of a setup script.
            using ( var scope = app.Services.CreateAsyncScope () )
            {
                var context = scope.ServiceProvider.GetRequiredService<AppDbContext> ();
                context.Database.Migrate ();

                CreateApplicationsAsync ().GetAwaiter ().GetResult ();
                CreateScopesAsync ().GetAwaiter ().GetResult ();

                async Task CreateApplicationsAsync ()
                {

                    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager> ();

                    if ( await manager.FindByClientIdAsync ( "core_api_client" ) is null )
                    {
                        await manager.CreateAsync ( new OpenIddictApplicationDescriptor
                        {
                            ClientId = "core_api_client",
                            ConsentType = ConsentTypes.Implicit,

                            RedirectUris =
                            {
                                new Uri("http://localhost:7000/")
                            },
                            Permissions =
                            {
                                Permissions.Endpoints.Authorization,
                                Permissions.Endpoints.Token,
                                Permissions.GrantTypes.AuthorizationCode,
                                Permissions.ResponseTypes.Code,
                                Permissions.Prefixes.Scope + "gtapi"
                            }


                            /*
                            Requirements =
                            {
                                Requirements.Features.ProofKeyForCodeExchange
                            }
                            */
                        } );
                    }


                    if ( await manager.FindByClientIdAsync ( "core_api_console" ) is null )
                    {
                        await manager.CreateAsync ( new OpenIddictApplicationDescriptor
                        {
                            ClientId = "core_api_console",
                            ClientSecret = "E2B00F84-82D2-4D43-B081-B4B88283175A",
                            DisplayName = "My client application",
                            Permissions =
                            {
                                Permissions.Endpoints.Token,
                                Permissions.GrantTypes.ClientCredentials
                            }
                        } );
                    }
                }

                async Task CreateScopesAsync ()
                {
                    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager> ();

                    if ( await manager.FindByNameAsync ( "gtapi" ) is null )
                    {
                        await manager.CreateAsync ( new OpenIddictScopeDescriptor
                        {
                            Name = "gtapi",
                            Resources =
                            {
                            "resource_server_1"
                        }
                        } );
                    }

                }


            }


            app.MapRazorPages ();
			app.MapControllers ();


			// Refer to:
			// https://www.meziantou.net/list-all-routes-in-an-asp-net-core-application.htm
			if ( app.Environment.IsDevelopment () )
			{
				app.MapGet ( "/debug/routes", ( IEnumerable<EndpointDataSource> endpointSources ) =>
					string.Join ( "\n", endpointSources.SelectMany ( source => source.Endpoints ) ) );
			}


			app.Run ();
        }
    }
}