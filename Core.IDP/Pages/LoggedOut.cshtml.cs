using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Core.IDP.Pages
{
    public partial class LoggedOutMdoel : PageModel
    {
		[BindProperty]
		public string PostLogoutRedirectUri 
		{ get; set; }
        
        [BindProperty]
		public string ClientName 
		{ get; set; }

        [BindProperty]
		public string SignOutIframeUrl 
		{ get; set; }


		[BindProperty]
		public bool AutomaticRedirectAfterSignOut 
		{ get; set; }

    }
}
