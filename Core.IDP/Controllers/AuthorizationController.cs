using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;


using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;



using static OpenIddict.Abstractions.OpenIddictConstants;

using Microsoft.AspNetCore.Components;

using Core.IDP.Extensions;
using Microsoft.AspNetCore.Identity;

namespace Core.IDP.Controllers
{
    public class AuthorizationController : Controller 
    {
        #region Constructors

        public AuthorizationController ( IOpenIddictApplicationManager applicationManager, IOpenIddictAuthorizationManager authorizationManager, IOpenIddictScopeManager scopeManager ) 
        {

            ApplicationManager = applicationManager;
            AuthorizationManager = authorizationManager;
            ScopeManager = scopeManager;

            UserManager = new UserManager ();
            if ( UserManager == null )
                throw new NullReferenceException ();
        
        }


        #endregion


        #region Properties

        [Inject]
        private UserManager UserManager
        { get; set; }

        [Inject]
        private IOpenIddictApplicationManager ApplicationManager
        { get; set; }

        [Inject]
        private IOpenIddictAuthorizationManager AuthorizationManager
        { get; set; }

        [Inject]
        private IOpenIddictScopeManager ScopeManager
        { get; set; }


        #endregion





        [HttpGet ( "~/connect/authorize" )]
        [HttpPost ( "~/connect/authorize" )]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize ( string returnUrl = null )
        {
            //ClaimsPrincipal claimsPrincipal = null;

            try
            {

                var request = HttpContext.GetOpenIddictServerRequest () ??
                    throw new InvalidOperationException ( "The OpenID Connect request cannot be retrieved." );

                // Try to retrieve the user principal stored in the authentication cookie and redirect
                // the user agent to the login page (or to an external provider) in the following cases:
                //
                //  - If the user principal can't be extracted or the cookie is too old.
                //  - If prompt=login was specified by the client application.
                //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
                var result = await HttpContext.AuthenticateAsync ( CookieAuthenticationDefaults.AuthenticationScheme );

                if ( result == null || !result.Succeeded || request.HasPrompt ( Prompts.Login ) ||
                   ( request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                    DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds ( request.MaxAge.Value ) ) )
                {
                    // If the client application requested promptless authentication,
                    // return an error indicating that the user is not logged in.
                    if ( request.HasPrompt ( Prompts.None ) )
                    {
                        return Forbid (
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties ( new Dictionary<string, string>
                            {
                                [ OpenIddictServerAspNetCoreConstants.Properties.Error ] = Errors.LoginRequired,
                                [ OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription ] = "The user is not logged in."
                            } ) );
                    }

                    // To avoid endless login -> authorization redirects, the prompt=login flag
                    // is removed from the authorization request payload before redirecting the user.
                    var prompt = string.Join ( " ", request.GetPrompts ().Remove ( Prompts.Login ) );

                    var parameters = Request.HasFormContentType ?
                        Request.Form.Where ( parameter => parameter.Key != Parameters.Prompt ).ToList () :
                        Request.Query.Where ( parameter => parameter.Key != Parameters.Prompt ).ToList ();

                    parameters.Add ( KeyValuePair.Create ( Parameters.Prompt, new StringValues ( prompt ) ) );

                    var redirectUri = Request.PathBase + Request.Path + QueryString.Create ( parameters );

                    return Challenge (
                        authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties
                        {
                            RedirectUri = redirectUri
                        } );
                }

                // Retrieve the profile of the logged in user.
                var principal = result.Principal;

                // Retrieve the application details from the database.
                var application = await ApplicationManager.FindByClientIdAsync ( request.ClientId ) ??
                    throw new InvalidOperationException ( "Details concerning the calling client application cannot be found." );

                // Retrieve the permanent authorizations associated with the user and the calling client application.
                var authorizations = await AuthorizationManager.FindAsync (
                    subject: UserManager.GetUserId ( principal ),
                    client:  await ApplicationManager.GetIdAsync ( application ),
                    status:  Statuses.Valid,
                    type:    AuthorizationTypes.Permanent,

                    scopes: request.GetScopes () ).ToListAsync ();


                var consentType = await ApplicationManager.GetConsentTypeAsync ( application );
                switch ( consentType )
                {
                    // If the consent is external (e.g when authorizations are granted by a sysadmin),
                    // immediately return an error if no authorization can be found in the database.
                    case ConsentTypes.External when !authorizations.Any ():
                        return Forbid (
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties ( new Dictionary<string, string>
                            {
                                [ OpenIddictServerAspNetCoreConstants.Properties.Error ] = Errors.ConsentRequired,
                                [ OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription ] =
                                    "The logged in user is not allowed to access this client application."
                            } ) );

                    // If the consent is implicit or if an authorization was found,
                    // return an authorization response without displaying the consent form.
                    case ConsentTypes.Implicit:
                    case ConsentTypes.External when authorizations.Any ():
                    case ConsentTypes.Explicit when authorizations.Any () && !request.HasPrompt ( Prompts.Consent ):
                        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                        var claimsIdentity = new ClaimsIdentity (
							authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );
						/*
                            nameType: Claims.Name,
                            roleType: Claims.Role );
                        */

						// Add the claims that will be persisted in the tokens.
						claimsIdentity.SetClaim ( Claims.Subject, UserManager.GetUserId ( principal ) )
                                      //.SetClaim ( Claims.Email, UserManager.GetEmail ( principal ) )
                                      .SetClaim ( Claims.Username, UserManager.GetUsername ( principal ) );
                                //.SetClaims ( Claims.Role, ( await UserManager.GetRolesAsync ( user ) ).ToImmutableArray () );

                        // Note: in this sample, the granted scopes match the requested scope
                        // but you may want to allow the user to uncheck specific scopes.
                        // For that, simply restrict the list of scopes before calling SetScopes.
                        claimsIdentity.SetScopes ( request.GetScopes () );
                        claimsIdentity.SetResources ( await ScopeManager.ListResourcesAsync ( claimsIdentity.GetScopes () ).ToListAsync () );

                        // Automatically create a permanent authorization to avoid requiring explicit consent
                        // for future authorization or token requests containing the same scopes.
                        var authorization = authorizations.LastOrDefault ();
                        authorization ??= await AuthorizationManager.CreateAsync (
                            identity: claimsIdentity,
                            subject: UserManager.GetUserId ( principal ),
                            client: await ApplicationManager.GetIdAsync ( application ),
                            type: AuthorizationTypes.Permanent,
                            scopes: claimsIdentity.GetScopes () );

                        claimsIdentity.SetAuthorizationId ( await AuthorizationManager.GetIdAsync ( authorization ) );
                        claimsIdentity.SetDestinations ( GetDestinations );

                        return SignIn ( new ClaimsPrincipal ( claimsIdentity ), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );

                        //break;

                    // At this point, no authorization was found in the database and an error must be returned
                    // if the client application specified prompt=none in the authorization request.
                    case ConsentTypes.Explicit when request.HasPrompt ( Prompts.None ):
                    case ConsentTypes.Systematic when request.HasPrompt ( Prompts.None ):
                        return Forbid (
                            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                            properties: new AuthenticationProperties ( new Dictionary<string, string>
                            {
                                [ OpenIddictServerAspNetCoreConstants.Properties.Error ] = Errors.ConsentRequired,
                                [ OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription ] =
                                    "Interactive user consent is required."
                            } ) );

                }

            }
            catch ( Exception ex ) 
            {
                throw;
            }

            /*

            try
            {
                // Retrieve the OpenIddict server request from the HTTP context.
                var request = HttpContext.GetOpenIddictServerRequest ();


                // Retrieve the user principal stored in the authentication cookie.
                var result = await HttpContext.AuthenticateAsync ( OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );

                // If the user principal can't be extracted, redirect the user to the login page.
                if ( !result.Succeeded )
                {
                    var redirectUri = Request.PathBase + Request.Path + QueryString.Create ( Request.HasFormContentType ? Request.Form.ToList () : Request.Query.ToList () );

                    var res =
                    Challenge (
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties
                        {
                            RedirectUri = redirectUri
                        } );

                    return res;
                }


                // Create a new claims principal
                var claims = new List<Claim>
                {
                    // 'subject' claim which is required
                    new Claim(OpenIddictConstants.Claims.Subject, result.Principal.Identity.Name),
                    new Claim("some claim", "some value").SetDestinations(OpenIddictConstants.Destinations.AccessToken),
                    new Claim(OpenIddictConstants.Claims.Email, "some@email").SetDestinations(OpenIddictConstants.Destinations.IdentityToken)
                };

                var claimsIdentity = new ClaimsIdentity ( claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );

                claimsPrincipal = new ClaimsPrincipal ( claimsIdentity );

                // Set requested scopes (this is not done automatically)
                claimsPrincipal.SetScopes ( request.GetScopes () );

                // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
                return SignIn ( claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );
            }
            catch ( Exception ex ) 
            {
                var msg = ex.Message;
                throw;
            }
            */


            return Ok ();
           
        }

        [HttpPost ( "~/connect/token" )]
        public async Task<IActionResult> Exchange ()
        {
            var request = HttpContext.GetOpenIddictServerRequest () ??
                          throw new InvalidOperationException ( "The OpenID Connect request cannot be retrieved." );

            ClaimsPrincipal claimsPrincipal;

            if ( request.IsClientCredentialsGrantType () )
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var identity = new ClaimsIdentity ( OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );

                // Subject (sub) is a required field, we use the client id as the subject identifier here.
                identity.AddClaim ( OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException () );

                // Add some claim, don't forget to add destination otherwise it won't be added to the access token.
                //identity.AddClaim ( "some-claim", "some-value", OpenIddictConstants.Destinations.AccessToken );

                claimsPrincipal = new ClaimsPrincipal ( identity );

                claimsPrincipal.SetScopes ( request.GetScopes () );
            }

            else if ( request.IsAuthorizationCodeGrantType () )
            {
                // Retrieve the claims principal stored in the authorization code
                claimsPrincipal = ( await HttpContext.AuthenticateAsync ( OpenIddictServerAspNetCoreDefaults.AuthenticationScheme ) ).Principal;
            }

            else if ( request.IsRefreshTokenGrantType () )
            {
                // Retrieve the claims principal stored in the refresh token.
                claimsPrincipal = ( await HttpContext.AuthenticateAsync ( OpenIddictServerAspNetCoreDefaults.AuthenticationScheme ) ).Principal;
            }

            else
            {
                throw new InvalidOperationException ( "The specified grant type is not supported." );
            }

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            var result = SignIn ( claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme );



            return result;
        }

        [Authorize ( AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme )]
        [HttpGet ( "~/connect/userinfo" )]
        public async Task<IActionResult> Userinfo ()
        {
            var id = User.GetClaim ( Claims.Subject );

            var user = UserManager.FindById ( id );
            if ( user == null )
            {
                return Challenge (
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties ( new Dictionary<string, string>
                    {
                        [ OpenIddictServerAspNetCoreConstants.Properties.Error ] = Errors.InvalidToken,
                        [ OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription ] =
                            "The specified access token is bound to an account that no longer exists."
                    } ) );
            }

            var claims = new Dictionary<string, object> ( StringComparer.Ordinal )
            {
                // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
                [ Claims.Subject ] = UserManager.GetUserId ( user )
            };

            if ( User.HasScope ( Scopes.Email ) )
            {
                claims [ Claims.Email ] = UserManager.GetEmail ( user );
                claims [ Claims.EmailVerified ] = UserManager.IsEmailConfirmedAsync ( user );
            }

            /*
            if ( User.HasScope ( Scopes.Phone ) )
            {
                claims [ Claims.PhoneNumber ] = await UserManager.GetPhoneNumberAsync ( user );
                claims [ Claims.PhoneNumberVerified ] = await UserManager.IsPhoneNumberConfirmedAsync ( user );
            }

            if ( User.HasScope ( Scopes.Roles ) )
            {
                claims [ Claims.Role ] = await UserManager.GetRolesAsync ( user );
            }
            */

            // Note: the complete list of standard claims supported by the OpenID Connect specification
            // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

            return Ok ( claims );
        }

        private static IEnumerable<string> GetDestinations ( Claim claim )
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch ( claim.Type )
            {
                case Claims.Name:
                    yield return Destinations.AccessToken;

                    if ( claim.Subject.HasScope ( Scopes.Profile ) )
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if ( claim.Subject.HasScope ( Scopes.Email ) )
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if ( claim.Subject.HasScope ( Scopes.Roles ) )
                        yield return Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }

    }
}