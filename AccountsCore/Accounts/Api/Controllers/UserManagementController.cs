using Accounts.Models;
using Accounts.Models.Api;
using Accounts.Service.Services;
using Accounts.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Accounts.Api.Controllers
{
	[Produces("application/json")]
	[Route("api/management/users")]
	[Authorize(Policy = "UserManagement")]
	public class UserManagementController : Controller
	{
		private readonly UserService _userService;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly IEmailSender _emailSender;

		public UserManagementController(
			UserManager<ApplicationUser> userManager,
			IEmailSender emailSender,
			UserService userService)
		{
			_userService = userService;
			_userManager = userManager;
			_emailSender = emailSender;
		}

		[HttpPost]
		public async Task<IActionResult> CreateUser([FromBody]UserDto user)
		{
			if(!ModelState.IsValid) return BadRequest(ModelState);
			try
			{
				var newUser = await _userService.CreateUser(user);
                if (user.IsSendConfirmationEmail)
                {
                    await SendEmailConfirmation(newUser.Id, user.ReturnUrl, user.ClientId);
                }
				return Ok(newUser);
			}
			catch (Exception ex) { return BadRequest(ex.Message); }
		}

		[HttpPut("{userId}")]
		public async Task EditUser(string userId, [FromBody]UserDto userRequest)
		{
			await _userService.EditUser(userId, userRequest);
		}

		[HttpGet]
		public List<UserDto> GetUsers()
		{
			return _userService.GetUsers();
		}

		[HttpPost("delete")]
		public async Task DeleteUsers([FromBody]IList<string> userIds)
		{
			await _userService.DeleteUsers(userIds);
		}

		[HttpPost("activate")]
		public async Task ActivateUsers([FromBody]IList<string> userIds)
		{
			await _userService.ActivateUsers(userIds);
		}

		[HttpPost("getUserInfo")]
		public async Task<UserDto> GetUserInfo([FromBody]string userName)
		{
			return await _userService.GetUserInfo(userName);
		}
		[HttpPost("getUserInfoByEmail")]
		public async Task<UserDto> GetUserInfoByEmail([FromBody]string email)
		{
			return await _userService.GetUserInfoByEmail(email);
		}

		private async Task SendEmailConfirmation(string userId, string returnUrl, string clientId)
		{
			var user = await _userManager.Users.FirstOrDefaultAsync(p => p.Id == userId);
			var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
			var urlParams = new
			{
				userId = user.Id,
			    code,
			    returnUrl,
			    clientId
			};
			var callbackUrl = Url.Action("ConfirmEmail", "Account", urlParams, HttpContext.Request.Scheme);

			await _emailSender.SendEmailAsync(
				user.Email,
				EmailTemplateService.AccountConfirmationSubject,
				EmailTemplateService.AccountConfirmationBody(callbackUrl), clientId);
		}

	}
}