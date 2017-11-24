using Accounts.Controllers;
using Accounts.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Accounts.Api.Controllers
{
    [Authorize(Policy = "Passwordless")]
    [Produces("application/json")]
    [Route("api/tokens/passwordlessurl")]
    public class PasswordlessController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public PasswordlessController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }


        [HttpGet]
        public async Task<string> RequestPasswordlessUrl(string returnUrl)
        {
            ClaimsPrincipal principal = HttpContext.User;
            var userId = principal.FindFirst("sub")?.Value;
            var user = await _userManager.FindByIdAsync(userId);
            var token = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, "passwordless");
            return Url.Action(nameof(AccountController.LoginWithToken), "Account", new { userId = userId, token = token }, Request.Scheme);
        }
    }
}
