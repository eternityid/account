using System;
using System.Threading.Tasks;
using Accounts.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Accounts.Services
{
    public class SignInServiceWithActiveDirectorySupport 
    {
        private readonly ActiveDirectoryUserService _activeDirectoryUserService;
        private readonly bool _loginActiveDirectoryModeEnabled = true; //bool.Parse(ConfigurationManager.AppSettings["LoginActiveDirectoryModeEnabled"]);

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<SignInManager<ApplicationUser>> _logger;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public SignInServiceWithActiveDirectorySupport(
            SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ActiveDirectoryUserService activeDirectoryUserService, ILogger<SignInManager<ApplicationUser>> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _activeDirectoryUserService = activeDirectoryUserService;
            _logger = logger;
        }

        public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            if (!_loginActiveDirectoryModeEnabled)
            {
                return await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
            }

            return await PasswordSignInActiveDirectoryAsync(userName, password, isPersistent, lockoutOnFailure);
        }

        private async Task<SignInResult> PasswordSignInActiveDirectoryAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user != null && !user.IsAccountInActiveDirectory)
            {
                return await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
            }

            if (_activeDirectoryUserService.ValidateCredential(userName, password))
            {
                _logger.LogInformation("Active Directory - Credentials validated for username: {username}", userName);

                if (user == null)
                {
                    user = await InsertUserToLocalDatabase(userName);
                }
                await _signInManager.SignInAsync(user, isPersistent);
                return SignInResult.Success;
            }

            if (user != null)
            {
                await _userManager.AccessFailedAsync(user);
            }
            _logger.LogInformation(
                "Active Directory - Authentication failed for username: {username}, reason: invalid credentials", userName);
            return SignInResult.Failed;
        }


        private async Task<ApplicationUser> InsertUserToLocalDatabase(string username)
        {
            var firstName = ""; //getValueFromPropertyDirectiveEntry(userInfoInActiveDirectory, "givenName");
            var lastName = ""; //getValueFromPropertyDirectiveEntry(userInfoInActiveDirectory, "sn");
            var email = "";//getValueFromPropertyDirectiveEntry(userInfoInActiveDirectory, "mail");

            var applicationUser = new ApplicationUser
            {
                UserName = username,
                FirstName = firstName,
                LastName = lastName,
                Email = email,
                IsAccountInActiveDirectory = true,
                IsActive = true,
                CreatedDate = DateTime.Now
            };

            await _userManager.CreateAsync(applicationUser);
            await _userManager.AddToRoleAsync(applicationUser, "User");
            return applicationUser;
        }

    }
}