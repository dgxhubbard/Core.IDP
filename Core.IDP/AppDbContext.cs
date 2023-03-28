



using Microsoft.EntityFrameworkCore;



namespace Core.IDP
{


    public class AppDbContext : DbContext
    {
        public AppDbContext ( DbContextOptions options )
            : base ( options )
        {
        }

        protected override void OnModelCreating ( ModelBuilder builder )
        {
            base.OnModelCreating ( builder );

            builder.UseOpenIddict ();

            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
    }
}

