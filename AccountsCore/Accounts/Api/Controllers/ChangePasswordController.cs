using Accounts.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Accounts.Api.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/management/users/changepassword")]
    public class ChangePasswordController : Controller
    {
        private readonly UserService _userService;

        public ChangePasswordController(UserService userService)
        {
            _userService = userService;
        }

        [HttpPut("")]
        public async Task ChangePassword([FromBody]ChangePasswordDto changePasswordDto)
        {
            var idClaim = User.Claims.FirstOrDefault(c => c.Type == "sub");
            if (idClaim == null) throw new InvalidOperationException("Current user not found");

            await _userService.ChangePassword(idClaim.Value, changePasswordDto);
        }

    }
}
