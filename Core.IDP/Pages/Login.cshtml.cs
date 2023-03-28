using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Json;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;



using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;




using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants;




namespace Core.IDP.Pages
{
    public partial class LoginModel : PageModel
    {

        #region Constructors

        public LoginModel ( HttpClient client )
        {

            Console.WriteLine ( "Signin" );

            HttpClient = client;

        }


		#endregion



		#region Properties

		
		private HttpClient HttpClient
		{ get; set; }



		[Required]
		[BindProperty]
		public string Username
        { get; set; }

        [Required]
		[BindProperty]

		public string Password
        { get; set; }

		[BindProperty]

		public bool RememberLogin
        { get; set; }

		[BindProperty]

		public string ReturnUrl
        { get; set; }



        public bool AllowRememberLogin
        { get; set; } = false;

        
        /*
        public bool EnableLocalLogin 
        { get; set; } = true;

        public IEnumerable<ExternalProvider> ExternalProviders 
        { get; set; } = Enumerable.Empty<ExternalProvider> ();


        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where ( x => !String.IsNullOrWhiteSpace ( x.DisplayName ) );

        public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count () == 1;

        public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault ()?.AuthenticationScheme : null;

        public class ExternalProvider
        {
            public string DisplayName { get; set; }
            public string AuthenticationScheme { get; set; }
        }
        */

		#endregion


		#region Methods


		public void OnGet ()
		{

            ViewData [ "Username" ] = Username;
			ViewData [ "Password" ] = Password;
			ViewData [ "RememberLogin" ] = RememberLogin;
			ViewData [ "ReturnUrl" ] = ReturnUrl;
    	}

        
        public IActionResult OnPost ( string returnUrl = null )
		{
			/*
            var signinModel = new Core.IDP.Models.SigninModel ();

            signinModel.Username = Username;
            signinModel.Password = Password;
            signinModel.RememberLogin = RememberLogin;
            signinModel.ReturnUrl = ReturnUrl;


			await HttpClient.PostAsJsonAsync<LoginModel> ( "Account/Login", this );

			Redirect ( "/" );
            */

			var claims = new List<Claim>
			{
				new Claim ( Claims.Username, Username ),
				new Claim ( Claims.Subject, 1.ToString () )
			};

			var claimsIdentity = 
				new ClaimsIdentity ( claims, CookieAuthenticationDefaults.AuthenticationScheme );

			var claimsPrincipal =
				new ClaimsPrincipal ( claimsIdentity );


            var redirectUrl = Url.IsLocalUrl ( returnUrl ) ? returnUrl : "/connect/signin";
			var properties = new AuthenticationProperties
			{
				RedirectUri = redirectUrl
			};



			return SignIn ( claimsPrincipal, properties, CookieAuthenticationDefaults.AuthenticationScheme );




		}


		#endregion


	}
}
