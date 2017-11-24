using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Accounts.Models;
using Accounts.Models.AccountViewModels;
using Accounts.Service.Services;
using Accounts.Services;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace Accounts.Controllers
{
	[Authorize]
	public class AccountController : Controller
	{
		private const string PasswordLessUrlCookieName = "passwordlessReturnUrl";
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly SignInServiceWithActiveDirectorySupport _signInService;

		private readonly IEmailSender _emailSender;
		private readonly ISmsSender _smsSender;
		private readonly IIdentityServerInteractionService _interaction;
		private readonly ILogger _logger;

		public AccountController(
			UserManager<ApplicationUser> userManager,
			SignInManager<ApplicationUser> signInManager,
			SignInServiceWithActiveDirectorySupport signInService,
			IOptions<IdentityCookieOptions> identityCookieOptions,
			IEmailSender emailSender,
			ISmsSender smsSender,
			ILoggerFactory loggerFactory,
			IIdentityServerInteractionService interaction,
			IHttpContextAccessor httpContext,
			IClientStore clientStore)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_signInService = signInService;
			_emailSender = emailSender;
			_smsSender = smsSender;
			_interaction = interaction;
			_logger = loggerFactory.CreateLogger<AccountController>();
		}

		//
		// GET: /Account/Login
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> Login(string returnUrl = null)
		{
			string passwordlessLogoutUrl = Request.Cookies[PasswordLessUrlCookieName];
			if (passwordlessLogoutUrl != null)
			{
				Response.Cookies.Delete(PasswordLessUrlCookieName);
				return Redirect(passwordlessLogoutUrl);
			}
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);
			return View(new LoginViewModel
			{
				ReturnUrl = returnUrl,
				Email = context?.LoginHint,
				ClientId = context?.ClientId
			});
		}


		//
		// POST: /Account/Login
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Login(LoginViewModel model)
		{
			var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
			SetViewData(context?.ClientId, model.ReturnUrl);
			var vm = new LoginViewModel
			{
				ReturnUrl = model.ReturnUrl,
				Email = model.Email,
				RememberMe = model.RememberMe
			};

			if (ModelState.IsValid)
			{
				// This doesn't count login failures towards account lockout
				// To enable password failures to trigger account lockout, set lockoutOnFailure: true
				var result = await _signInService.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
				if (result.Succeeded)
				{
					_logger.LogInformation(1, "User logged in.");
					return RedirectIfAllowed(model.ReturnUrl);
				}
				if (result.RequiresTwoFactor)
				{
					return RedirectToAction(nameof(SendCode), new { ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
				}
				if (result.IsLockedOut)
				{
					_logger.LogWarning(2, "User account locked out.");
					return View("Lockout");
				}
				ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                if (context != null)
                {
                    vm.ClientId = context.ClientId;
                }

				return View(vm);
			}

			// If we got this far, something failed, redisplay form
			return View(vm);
		}


		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> LoginWithToken(string userId, string token, string returnUrl = null, string logoutUrl = null)
		{
			var user = await _userManager.FindByIdAsync(userId);

			var success = await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, "passwordless", token);
			if (!success)
			{
				return View("Error");
			}
			// Update security token in order to invalidate current login link (for further use)
			await _userManager.UpdateSecurityStampAsync(user);
			await _signInManager.SignInAsync(user, isPersistent: false);
			_logger.LogInformation(1, "User logged in (passwordless).");
			if (logoutUrl != null)
			{
				var isPenetraceUser = await _userManager.IsInRoleAsync(user, "PenetraceUsers");
				if (isPenetraceUser)
				{
					Response.Cookies.Append(PasswordLessUrlCookieName, logoutUrl);
				}
			}
			// We trust the user with a token. Hence we will allow any redirect.
			return Redirect(returnUrl);
		}


		//
		// GET: /Account/Register
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> Register(string returnUrl = null)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);

			return View(new RegisterViewModel { ReturnUrl = returnUrl });
		}

		//
		// POST: /Account/Register
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Register(RegisterViewModel model)
		{
			var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
			SetViewData(context?.ClientId, model.ReturnUrl);

			if (ModelState.IsValid)
			{
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, CreatedDate = DateTime.Now };
				var result = await _userManager.CreateAsync(user, model.Password);
				if (result.Succeeded)
				{
					await _userManager.AddToRoleAsync(user, "User");

					await SendConfirmationEmail(user, context?.RedirectUri, context?.ClientId);

					_logger.LogInformation(3, "User created a new account with password.");
					return RedirectToAction(nameof(RegisterConfirmation), new { returnUrl = model.ReturnUrl });
				}
				AddErrors(result);
			}

			// If we got this far, something failed, redisplay form
			return View(model);
		}

		// POST: /Account/Register
		// TODO: to be removed after user managment for HR Tools is done
		[Obsolete]
		[HttpPost]
		[AllowAnonymous]
		public async Task<IActionResult> RegisterAccount(RegisterViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, CreatedDate = DateTime.Now };
				var result = await _userManager.CreateAsync(user, model.Password);
				if (result.Succeeded)
				{
					await _userManager.AddToRoleAsync(user, "User");

					_logger.LogInformation(3, "User created a new account with password.");
					return Content("Successfully!");
				}
				AddErrors(result);
			}

			// If we got this far, something failed
			Response.StatusCode = 500;
			return Content("Error!");
		}

		[HttpPost]
		[AllowAnonymous]
		public async Task<IActionResult> ResendConfirmationEmail(string userId, string returnUrl, string clientId)
		{
			var user = await _userManager.FindByIdAsync(userId);

			if (user == null)
			{
				var errorViewModel = new ErrorViewModel();

				errorViewModel.ActionUrl = returnUrl;
				errorViewModel.ActionLabel = "Back";

				return View("Error", errorViewModel);
			}

			await SendConfirmationEmail(user, returnUrl, clientId);
			SetViewData(clientId, returnUrl);
			return View("ResendConfirmationEmail", new RegisterConfirmationViewModel { ReturnUrl = returnUrl });
		}

		private async Task SendConfirmationEmail(ApplicationUser user, string returnUrl, string clientId)
		{
			var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
			var urlParams = new
			{
				userId = user.Id,
				code = code,
				returnUrl = returnUrl,
				clientId = clientId
			};
			var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", urlParams, HttpContext.Request.Scheme);

			await _emailSender.SendEmailAsync(
				user.Email,
				EmailTemplateService.AccountConfirmationSubject,
				EmailTemplateService.AccountConfirmationBody(callbackUrl), clientId);
		}

		[AllowAnonymous]
		public async Task<IActionResult> RegisterConfirmation(string returnUrl)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);

			return View(new RegisterConfirmationViewModel { ReturnUrl = returnUrl });
		}

		//
		// GET: /Account/Logout
		[AllowAnonymous]
		[HttpGet]
		public async Task<IActionResult> Logout(string logoutId)
		{
			var context = await _interaction.GetLogoutContextAsync(logoutId);
			SetViewData(context?.ClientId, "");

			return await Logout(new LogoutViewModel { LogoutId = logoutId });
		}

		//
		// POST: /Account/Logout
		[HttpPost]
		[ValidateAntiForgeryToken]
		[AllowAnonymous]
		public async Task<IActionResult> Logout(LogoutViewModel model)
		{
			var context = await _interaction.GetLogoutContextAsync(model.LogoutId);
			var vm = new LoggedOutViewModel
			{
				AutomaticRedirectAfterSignOut = true,
				PostLogoutRedirectUri = context?.PostLogoutRedirectUri,
				ClientName = context?.ClientId,
				SignOutIframeUrl = context?.SignOutIFrameUrl,
				LogoutId = model.LogoutId
			};

			if (vm.TriggerExternalSignout)
			{
				string url = Url.Action("Logout", new { logoutId = vm.LogoutId });
				try
				{
					// hack: try/catch to handle social providers that throw
					await HttpContext.Authentication.SignOutAsync(vm.ExternalAuthenticationScheme,
						new AuthenticationProperties { RedirectUri = url });
				}
				catch (NotSupportedException) // this is for the external providers that don't have signout
				{
				}
				catch (InvalidOperationException) // this is for Windows/Negotiate
				{
				}
			}

			// delete authentication cookie
			await _signInManager.SignOutAsync();

			if (vm.PostLogoutRedirectUri != null)
			{
				return Redirect(vm.PostLogoutRedirectUri);
			}
			return View("LoggedOut", vm);
		}

		//
		// POST: /Account/ExternalLogin
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public IActionResult ExternalLogin(string provider, string returnUrl = null)
		{
			// Request a redirect to the external login provider.
			var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { ReturnUrl = returnUrl });
			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
			return Challenge(properties, provider);
		}

		//
		// GET: /Account/ExternalLoginCallback
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
		{
			if (remoteError != null)
			{
				ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
				return View(nameof(Login));
			}
			var info = await _signInManager.GetExternalLoginInfoAsync();
			if (info == null)
			{
				return RedirectToAction(nameof(Login));
			}

			// Sign in the user with this external login provider if the user already has a login.
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
			if (result.Succeeded)
			{
				_logger.LogInformation(5, "User logged in with {Name} provider.", info.LoginProvider);
				return RedirectIfAllowed(returnUrl);
			}
			if (result.RequiresTwoFactor)
			{
				return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl });
			}
			if (result.IsLockedOut)
			{
				return View("Lockout");
			}
			// If the user does not have an account, then ask the user to create an account.
			var email = info.Principal.FindFirstValue(ClaimTypes.Email);
			return View(nameof(ExternalLoginConfirmation), new ExternalLoginConfirmationViewModel { Email = email, ReturnUrl = returnUrl, LoginProvider = info.LoginProvider });
		}

		//
		// POST: /Account/ExternalLoginConfirmation
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model)
		{
			if (ModelState.IsValid)
			{
				// Get the information about the user from the external login provider
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if (info == null)
				{
					return View("ExternalLoginFailure");
				}
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email, CreatedDate = DateTime.Now };
				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					result = await _userManager.AddLoginAsync(user, info);
					if (result.Succeeded)
					{
						await _signInManager.SignInAsync(user, isPersistent: false);
						_logger.LogInformation(6, "User created an account using {Name} provider.", info.LoginProvider);
						return RedirectIfAllowed(model.ReturnUrl);
					}
				}
				AddErrors(result);
			}

			return View(model);
		}

		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ConfirmEmail(string userId, string code, string returnUrl, string clientId)
		{
			var errorViewModel = new ErrorViewModel();

			SetViewData(clientId, returnUrl);
			if (userId == null || code == null)
			{
				errorViewModel.ErrorTitle = "Invalid confirmation link!";
				errorViewModel.Error.Error = "This confirmation link is invalid! Please contact support for help.";
				errorViewModel.ActionUrl = returnUrl;
				errorViewModel.ActionLabel = "Back";

				return View("Error", errorViewModel);
			}

			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				errorViewModel.ErrorTitle = "Invalid confirmation link!";
				errorViewModel.Error.Error = "This confirmation link is invalid! Please contact support for help.";
				errorViewModel.ActionUrl = returnUrl;
				errorViewModel.ActionLabel = "Back";

				return View("Error", errorViewModel);
			}
			var result = await _userManager.ConfirmEmailAsync(user, code);
			if (!result.Succeeded)
			{
				errorViewModel.ErrorTitle = "Confirmation link expired!";
				errorViewModel.Error.Error = "This confirmation link expired! Please click below link to get a new one and confirm again.";
				errorViewModel.ActionUrl = Url.Action("ResendConfirmationEmail", "Account", new { userId, returnUrl, clientId });
				errorViewModel.ActionLabel = "Resend confirmation email";

				return View("Error", errorViewModel);
			}

			user.IsActive = true;
			await _userManager.UpdateAsync(user);
			return View(new ConfirmEmailViewModel { ReturnUrl = returnUrl });
		}

		//
		// GET: /Account/ForgotPassword
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ForgotPassword(string returnUrl = null)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);
			return View(new ForgotPasswordViewModel { ReturnUrl = returnUrl });
		}

		//
		// POST: /Account/ForgotPassword
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
		{
			var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
			SetViewData(context?.ClientId, model.ReturnUrl);

			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);



				// Require the user to have a confirmed email before they can log on.
				//if (user != null)
				//{
				//    if (!await _userManager.IsEmailConfirmedAsync(user))
				//    {
				//        ModelState.AddModelError(string.Empty, $"You must have a confirmed email to log in. The confirmation email has been re-sent to {model.Email}");
				//        //await SendEmailConfirmation(model.Email, user);
				//        return View(model);
				//    }
				//    return View("ForgotPasswordConfirmation");
				//}



				if (user == null)
				{
					// Don't reveal that the user does not exist or is not confirmed
					return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ReturnUrl = model.ReturnUrl });
				}

				if (!await _userManager.IsEmailConfirmedAsync(user))
				{
					await SendConfirmationEmail(user, model.ReturnUrl, context.ClientId);
					return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ReturnUrl = model.ReturnUrl });
				}


				// For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=532713
				// Send an email with this link
				var code = await _userManager.GeneratePasswordResetTokenAsync(user);
				var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { email = user.Email, code = code, returnUrl = model.ReturnUrl }, protocol: HttpContext.Request.Scheme);
				await _emailSender.SendEmailAsync(model.Email, EmailTemplateService.ResetPasswordSubject, EmailTemplateService.ResetPasswordBody(callbackUrl), context?.ClientId);
				return RedirectToAction(nameof(ForgotPasswordConfirmation), new { ReturnUrl = model.ReturnUrl });
			}

			// If we got this far, something failed, redisplay form
			return View(model);
		}

		private void SetViewData(string clientId, string returnUrl)
		{
			ViewData["returnUrl"] = returnUrl;
			if (clientId == "ResponsiveHR")
			{
				ViewData["logo"] = "/images/logo_hr.png";
				ViewData["footerText"] = "ResponsiveHR.com";
				ViewData["footerUrl"] = "//www.responsivehr.com/";
			}
			else if (clientId == "HiredNow")
			{
				ViewData["logo"] = "/images/logo_hirednow.png";
				ViewData["footerText"] = "HiredNow.com.my";
				ViewData["footerUrl"] = "//www.hirednow.com.my/";
			}
			else
			{
				ViewData["logo"] = "/images/logo.png";
				ViewData["footerText"] = "ResponsiveInsight.com";
				ViewData["footerUrl"] = "//www.responsiveinsight.com/";
			}
		}


		//
		// GET: /Account/ForgotPasswordConfirmation
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ForgotPasswordConfirmation(string returnUrl = null)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);

			return View(new ForgotPasswordConfirmationViewModel { ReturnUrl = returnUrl });
		}

		//
		// GET: /Account/ResetPassword
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ResetPassword(string email = null, string code = null, string returnUrl = null)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);
			if (email == null || code == null)
			{
				return View("Error");
			}
			return View();
		}

		//
		// POST: /Account/ResetPassword
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}
			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user == null)
			{
				// Don't reveal that the user does not exist
				return RedirectToAction(nameof(ResetPasswordConfirmation));
			}
			var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
			if (result.Succeeded)
			{
				return RedirectToAction(nameof(ResetPasswordConfirmation), new { ReturnUrl = model.ReturnUrl });
			}
			AddErrors(result);
			return View();
		}

		//
		// GET: /Account/ResetPasswordConfirmation
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> ResetPasswordConfirmation(string returnUrl = null)
		{
			var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
			SetViewData(context?.ClientId, returnUrl);
			return View(new ResetPasswordConfirmtationViewModel { ReturnUrl = returnUrl });
		}

		//
		// GET: /Account/SendCode
		[HttpGet]
		[AllowAnonymous]
		public async Task<ActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
		{
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}
			var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
			var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
			return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
		}

		//
		// POST: /Account/SendCode
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> SendCode(SendCodeViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View();
			}

			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}

			// Generate the token and send it
			var code = await _userManager.GenerateTwoFactorTokenAsync(user, model.SelectedProvider);
			if (string.IsNullOrWhiteSpace(code))
			{
				return View("Error");
			}

			var message = "Your security code is: " + code;
			if (model.SelectedProvider == "Email")
			{
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                SetViewData(context?.ClientId, model.ReturnUrl);
                await _emailSender.SendEmailAsync(await _userManager.GetEmailAsync(user), "Security Code", message, context?.ClientId);
			}
			else if (model.SelectedProvider == "Phone")
			{
				await _smsSender.SendSmsAsync(await _userManager.GetPhoneNumberAsync(user), message);
			}

			return RedirectToAction(nameof(VerifyCode), new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
		}

		//
		// GET: /Account/VerifyCode
		[HttpGet]
		[AllowAnonymous]
		public async Task<IActionResult> VerifyCode(string provider, bool rememberMe, string returnUrl = null)
		{
			// Require that the user has already logged in via username/password or external login
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}
			return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
		}

		//
		// POST: /Account/VerifyCode
		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> VerifyCode(VerifyCodeViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return View(model);
			}

			// The following code protects for brute force attacks against the two factor codes.
			// If a user enters incorrect codes for a specified amount of time then the user account
			// will be locked out for a specified amount of time.
			var result = await _signInManager.TwoFactorSignInAsync(model.Provider, model.Code, model.RememberMe, model.RememberBrowser);
			if (result.Succeeded)
			{
				return RedirectIfAllowed(model.ReturnUrl);
			}
			if (result.IsLockedOut)
			{
				_logger.LogWarning(7, "User account locked out.");
				return View("Lockout");
			}
			ModelState.AddModelError(string.Empty, "Invalid code.");
			return View(model);
		}

		//
		// GET /Account/AccessDenied
		[HttpGet]
		public IActionResult AccessDenied()
		{
			return View();
		}

		#region Helpers

		private void AddErrors(IdentityResult result)
		{
			foreach (var error in result.Errors)
			{
				ModelState.AddModelError(string.Empty, error.Description);
			}
		}

		private IActionResult RedirectIfAllowed(string returnUrl)
		{
			if (Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}

			if (!returnUrl.EndsWith("/"))
			{
				returnUrl = $"{returnUrl}/";
			}

			if (ClientsConfig.GetHrToolClientUrls().Contains(returnUrl)
				|| ClientsConfig.GetSurveyToolClientUrls().Contains(returnUrl))
			{
				return Redirect(returnUrl);
			}
			return View("Home");
		}

		#endregion

	}
}
