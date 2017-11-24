using System;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Accounts.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsActive { get; set; }
        public DateTime? CreatedDate { get; set; }
        public bool IsAccountInActiveDirectory { get; set; }
    }
}
