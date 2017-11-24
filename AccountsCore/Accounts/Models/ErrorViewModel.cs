using IdentityServer4.Models;

namespace Accounts.Models
{
    public class ErrorViewModel
    {
        public ErrorViewModel()
        {
            Error = new ErrorMessage();
        }

        public ErrorMessage Error { get; set; }
        public string ErrorTitle { get; set; }
        public string ActionUrl { get; set; }
        public string ActionLabel { get; set; }

    }
}