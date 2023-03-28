using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;


using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace Core.IDP.Pages
{
    public partial class LogoutModel : PageModel
    {

        #region Constructors

        public LogoutModel () 
        { }


        #endregion




        #region Properties



        public string PostLogoutRedirectUri 
        { get; set; }

        public string ClientName 
        { get; set; }

        public string SignOutIframeUrl 
        { get; set; }

        public bool AutomaticRedirectAfterSignOut 
        { get; set; }

        public static bool ShowLogoutPrompt = true;

        public string LogoutId { get; set; }

        #endregion


        #region Overrides


        #endregion

        #region Methods

        public IActionResult OnPost ( string returnUrl = "/" )
        {
            /*
            return 
                SignOut (
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = "/"
                    } );
            */

            return SignOut (
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                } );
        }


        #endregion







    }
    }
