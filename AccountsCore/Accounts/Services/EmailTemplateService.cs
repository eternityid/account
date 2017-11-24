using System.Text;

namespace Accounts.Service.Services
{
    public static class EmailTemplateService
    {
        //private static readonly string CompanyWebLink = ConfigurationManager.AppSettings["CompanyWebLink"];

        public static string AccountConfirmationSubject = "Registration - Confirm your new account";

        public static string AccountConfirmationBody(string callbackUrl)
        {
            var strBuilder = new StringBuilder();

            strBuilder.AppendLine("<p style=\"margin:20px 0\">Thanks for your registration! You must follow this link to activate your account:</p>");
            strBuilder.AppendLine(string.Format("<p style=\"margin: 20px 0\"><a style=\"font-size: 15px; margin: 6px auto; display: block;\" href=\"{0}\" target=\"_blank\">Click here</a></p>", callbackUrl));
            //TODO: !!!
            //strBuilder.AppendLine(string.Format("<p style=\"margin:20px 0\">Have fun, and don't hesitate to contact us with your feedback via: <a href=\"{0}\" target=\"_blank\">{0}</a></p>", "CompanyWebLink"));
            return strBuilder.ToString();
        }

        public static string ResetPasswordSubject = "Reset your account password";

        public static string ResetPasswordBody(string callbackUrl)
        {
            var strBuilder = new StringBuilder();

            strBuilder.AppendLine("Hi there,");
            strBuilder.AppendLine("<p>Someone recently requested a password change for your account. If this was you, you can set a new password here:</p>");
            strBuilder.AppendLine(string.Format("<p><a style=\"font-size: 15px; margin: 6px auto; display: block;\" href=\"{0}\" target=\"_blank\">Reset password</a></p>", callbackUrl));
            strBuilder.AppendLine("If you don't want to change your password or didn't request this, just ignore and delete this message.<br/><br/>");
            strBuilder.AppendLine("To keep your account secure, please don't forward this email to anyone.<br/>");
            strBuilder.AppendLine("Thanks!");

            return strBuilder.ToString();
        }
    }
}
