using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Accounts.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Accounts.Data
{
    public class DataSeeder
    {

        internal static void Initialize(IServiceProvider serviceProvider)
        {
            InitializeAsync(serviceProvider).Wait();
        }

        private static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            var context = serviceProvider.GetService<ApplicationDbContext>();

            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();


            string[] roles = {"Admin", "User"};

            foreach (string role in roles)
            {
                if (!context.Roles.Any(r => r.Name == role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            var user = new ApplicationUser
            {
                Id = "f6e021af-a6a0-4039-83f4-152595b4671a",
                FirstName = "Survey Tool",
                LastName = "Admin",
                UserName = "Admin",
                Email = "surveytool123456@gmail.com",
                IsActive = true,
                EmailConfirmed = true,
                CreatedDate = DateTime.Now,
                SecurityStamp = Guid.NewGuid().ToString("D")
            };

            if (!context.Users.Any(u => u.UserName == user.UserName))
            {
                user.PasswordHash = new PasswordHasher<ApplicationUser>().HashPassword(user, "123456");
                var userStore = new UserStore<ApplicationUser>(context);
                await userStore.CreateAsync(user);
                var userFromDb = await userManager.FindByIdAsync(user.Id);
                await userManager.AddToRolesAsync(userFromDb, roles);
            }

        }

    }

}
