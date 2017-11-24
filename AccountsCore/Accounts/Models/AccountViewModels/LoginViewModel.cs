using System.ComponentModel.DataAnnotations;

namespace Accounts.Models.AccountViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage ="Please enter your email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Please enter your password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }
        public string ClientId { get; set; }
    }
}