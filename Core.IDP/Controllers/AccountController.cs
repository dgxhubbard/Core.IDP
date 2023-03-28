using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Net.Http.Json;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;


using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;




using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants;

using Core.IDP.Models;
using Core.IDP.Pages;


namespace Core.IDP.Controllers
{
    [Microsoft.AspNetCore.Mvc.Route ( "[controller]/[action]" )]
    public class AccountController : Controller
    {
        #region Constructors

        public AccountController ()
        {
        }

        #endregion

        #region Properties

        
        #endregion


        #region Methods

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login ( string returnUrl = null )
        {
            //ViewData [ "ReturnUrl" ] = returnUrl;





            return Ok ( returnUrl );
        }

        [HttpPost]
        

        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Login ( [FromBody] LoginModel model )
        {
            var claims = new List<Claim>
            {
                new Claim ( Claims.Username, model.Username ),
                new Claim ( Claims.Subject, 1.ToString () )
            };

            var claimsIdentity =
                new ClaimsIdentity ( claims, CookieAuthenticationDefaults.AuthenticationScheme );

            var claimsPrincipal = 
                new ClaimsPrincipal ( claimsIdentity );

            // Ask the cookie authentication handler to return a new cookie and redirect
            // the user agent to the return URL stored in the authentication properties.
            return SignIn ( 
                principal: new ClaimsPrincipal ( claimsIdentity ),
                properties: new AuthenticationProperties
                {
                    RedirectUri = model.ReturnUrl
                },

                authenticationScheme: CookieAuthenticationDefaults.AuthenticationScheme );
        }

        public async Task<IActionResult> Logout ()
        {
            await HttpContext.SignOutAsync ();

            return Ok ();
        }


        #endregion
    }
}