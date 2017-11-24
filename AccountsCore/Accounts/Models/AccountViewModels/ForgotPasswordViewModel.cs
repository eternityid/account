using System.ComponentModel.DataAnnotations;

namespace Accounts.Models.AccountViewModels
{
    public class ForgotPasswordViewModel

    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public string ReturnUrl { get; set; }
    }
}
