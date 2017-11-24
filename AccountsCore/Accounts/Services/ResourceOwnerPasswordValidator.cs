using System;
using System.Threading.Tasks;
using IdentityServer4.Validation;
using static IdentityModel.OidcConstants;
using Accounts.Models;
using Microsoft.AspNetCore.Identity;
using System.Linq;

namespace Accounts.Services
{
    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ResourceOwnerPasswordValidator(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {
            var user = await _userManager.FindByIdAsync(context.UserName);

            var isPenetraceUser = await _userManager.IsInRoleAsync(user, "PenetraceUsers");

            if (isPenetraceUser && user != null)
            {
                context.Result = new GrantValidationResult(context.UserName, AuthenticationMethods.KnowledgeBasedAuthentication);
                return;
            }
            context.Result = new GrantValidationResult(TokenErrors.InvalidGrant, "Wrong username or password");
        }
    }
}