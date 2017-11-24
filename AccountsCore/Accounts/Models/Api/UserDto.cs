using System;
using System.ComponentModel.DataAnnotations;

namespace Accounts.Models.Api
{
    public class UserDto
	{
		public string Id { get; set; }
		[Required]
		public string Username { get; set; }
		[Required]
		public string Password { get; set; }
        public string OldPassword { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime? CreatedDate { get; set; }
		[Required]
		[EmailAddress]
		public string EmailAddress { get; set; }
        public bool IsActive { get; set; }
        public string Role { get; set; }
		[Required]
        public string ClientId { get; set; }
		[Required]
		public string ReturnUrl { get; set; }
        public bool IsSendConfirmationEmail { get; set; }

        public string CreatedDateString
            => CreatedDate != null ? Convert.ToDateTime(CreatedDate).ToString("MMM dd, yyyy hh:mm tt") : "N/A";
    }
}
