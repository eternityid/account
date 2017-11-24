using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Accounts.Data.Exceptions;
using Accounts.Models;
using Accounts.Models.Api;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Accounts.Services
{
    public class UserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserService(UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<ApplicationUser> CreateUser(UserDto userDto)
        {
            ValidateNewUser(userDto);

            var applicationUser = new ApplicationUser
            {
                UserName = userDto.Username,
                FirstName = userDto.FirstName,
                LastName = userDto.LastName,
                Email = userDto.EmailAddress,
                CreatedDate = DateTime.Now,
                IsActive = true,
                EmailConfirmed = !userDto.IsSendConfirmationEmail
            };

            var result = await _userManager.CreateAsync(applicationUser, userDto.Password);
            if (!result.Succeeded)
            {
                if (result.Errors.Any())
                {
                    throw new Exception(string.Join(", ", result.Errors.Select(a => a.Description)));
                }
                throw new EntityNotFoundException("Creating user was not successful.");
            }
            var user = _userManager.Users.FirstOrDefault(p => p.Id == applicationUser.Id);
            await _userManager.AddToRoleAsync(user, "User");
            return user;
        }

        public async Task EditUser(string userId, UserDto userRequest)
        {
            var user = await _userManager.FindByIdAsync(userId);
            ValidateEditUser(user, userRequest);

            if (!IsAdminUser(user.UserName))
            {
                user.UserName = userRequest.Username;
            }
            user.FirstName = userRequest.FirstName;
            user.LastName = userRequest.LastName;
            user.Email = userRequest.EmailAddress;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new EntityNotFoundException("Editing user was not successful.");
            }
        }

        public async Task<UserDto> GetUserInfo(string userName)
        {
            var user = (await _userManager.FindByNameAsync(userName));
            if (user?.UserName != null)
            {
                return new UserDto
                {
                    Username = user.UserName,
                    EmailAddress = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    IsActive = user.IsActive
                };
            }
            return null;
        }
        public async Task<UserDto> GetUserInfoByEmail(string email)
        {
            var user = (await _userManager.FindByEmailAsync(email));
            if (user?.UserName != null)
            {
                return new UserDto
                {
                    Username = user.UserName,
                    EmailAddress = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    IsActive = user.IsActive
                };
            }
            return null;
        }

        private void ValidateNewUser(UserDto user)
        {
            if (string.IsNullOrWhiteSpace(user.Username))
            {
                throw new EntityNotFoundException("Username cannot be empty");
            }
            if (_userManager.FindByNameAsync(user.Username.Trim()).Result != null)
            {
                throw new DuplicateDataException("Duplicated username");
            }
            if (_userManager.FindByEmailAsync(user.EmailAddress).Result != null)
            {
                throw new DuplicateDataException("Duplicated email address");
            }
        }

        private void ValidateEditUser(ApplicationUser user, UserDto userRequest)
        {
            if (user == null)
            {
                throw new UserNotFoundException("This user is not found.");
            }
            if (user.UserName != userRequest.Username && _userManager.FindByNameAsync(userRequest.Username.Trim()).Result != null)
            {
                throw new DuplicateDataException("Duplicated username");
            }
            if (user.Email != userRequest.EmailAddress && _userManager.FindByEmailAsync(userRequest.EmailAddress).Result != null)
            {
                throw new DuplicateDataException("Duplicated email address");
            }
        }

        private bool IsAdminUser(string userName)
        {
            return userName == "Admin";
        }

        public List<UserDto> GetUsers()
        {
            var roles = _roleManager.Roles.ToList();
            var roleMap = new Dictionary<string, string>();
            foreach (var role in roles)
            {
                roleMap[role.Id] = role.Name;
            }

            var userDtos = new List<UserDto>();
            var users = _userManager.Users
                .Include(user => user.Roles)
                .OrderByDescending(user=>user.CreatedDate)
                .ToList();
            foreach (var user in users)
            {
                var userDto = new UserDto
                {
                    Id = user.Id,
                    Username = user.UserName,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    EmailAddress = user.Email,
                    IsActive = user.IsActive,
                    CreatedDate = user.CreatedDate
                };
                var defaultUserRole = user.Roles.FirstOrDefault();
                if (defaultUserRole != null) userDto.Role = roleMap[defaultUserRole.RoleId];
                userDtos.Add(userDto);
            }
            return userDtos;
        }

        public async Task DeleteUsers(IList<string> userIds)
        {
            foreach (var userId in userIds)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || IsAdminUser(user.UserName))
                {
                    throw new UserNotFoundException("This user is Admin or not found.");
                }

                var result = await _userManager.DeleteAsync(user);
                if (!result.Succeeded)
                {
                    throw new EntityNotFoundException("Deleting user was not successful.");
                }
            }
        }

        public async Task ActivateUsers(IList<string> userIds)
        {
            foreach (var userId in userIds)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null || IsAdminUser(user.UserName))
                {
                    throw new UserNotFoundException("This user is Admin or not found.");
                }

                user.IsActive = !user.IsActive;
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    throw new EntityNotFoundException("Activating/Deactivating user was not successful.");
                }
            }
        }

        public async Task ChangePassword(string userId, ChangePasswordDto changePasswordDto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new EntityNotFoundException("User not found.");
            }

            if (user.IsAccountInActiveDirectory)
            {
                throw new Exception("Cannot change password for Active Directory account");
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);
            if (!result.Succeeded)
            {
                var message = result.Errors.FirstOrDefault();
                if (message != null) throw new Exception(message.ToString());
            }

        }
    }
}
