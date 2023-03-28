using Microsoft.AspNetCore.Mvc;

namespace Core.IDP.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}