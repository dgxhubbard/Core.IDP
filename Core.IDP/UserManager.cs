using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Core.IDP.Models;
using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;



namespace Core.IDP
{
    public class UserManager
    {





        public UserManager() 
        { }



        public string GetUsername ( ClaimsPrincipal principal )
        {
            var claims = principal.Claims.ToList ();


            var userName = claims.Find ( c => c.Type == Claims.Username );


            return userName.Value;
        }

        public string GetUserId ( ClaimsPrincipal principal )
        {
            var claims = principal.Claims.ToList ();


            var userId = claims.Find ( c => c.Type == Claims.Subject );


            return userId.Value;
        }


        public string GetUserId ( UserInfo userInfo )
        {
            if ( userInfo == null )
                return null;

            else
                return userInfo.Id;
        }


        public string GetEmail ( ClaimsPrincipal principal )
        {
            var claims = principal.Claims.ToList ();


            var email = claims.Find ( c => c.Type == Claims.Email );


            return email.Value;
        }

        public string GetEmail ( UserInfo userInfo )
        {
            if ( userInfo == null )
                return null;

            else
                return userInfo.Email;
        }

        public UserInfo FindById ( string id )
        {
            var userId = 0;

            if ( int.TryParse ( id, out userId ) ) 
            {
                return FindById ( userId );
            }
            else
            {
                return null;
            }

        }
        public UserInfo FindById ( int id )
        {
            if ( id <= 0 )
                return null;

            if ( id == 1 )
            {
                return
                    new UserInfo ()
                    {
                        UserName = "d",
                        FirstName = "Dan",
                        LastName = "Rodgers",
                        Email = "drodgers@yahoo.com",
                        Id = 1.ToString(),



                    };

            }
            else
            {
                return null;
            }
        }


        public bool IsEmailConfirmedAsync ( UserInfo user )
        {
            if ( user == null ) 
                return false;

            if ( user.Email != null )
                return true;

            return false;
        }


    }
}
