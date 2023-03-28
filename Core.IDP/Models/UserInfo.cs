using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.IDP.Models
{
    public class UserInfo
    {

        public UserInfo () 
        { 
            IsAuthenticated = false;
        }

        public string UserName
        { get; set; }

        public string FirstName 
        { get; set; }

        public string LastName
        { get; set; }


        public string Email 
        { get; set; }

        public bool IsAuthenticated
        { get; set; }

        public string AccessToken
        { get; set; }

        public string Token
        { get; set; }


        public string Id 
        { get; set; }

        public string RedirectUri
        { get; set; }

    }
}
