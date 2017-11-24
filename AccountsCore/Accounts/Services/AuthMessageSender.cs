using System.Threading.Tasks;
using Accounts.Configurations;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using System.Linq;

namespace Accounts.Services
{
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        private readonly SmtpConfiguration _smtpConfiguration;

        public AuthMessageSender(IOptions<SmtpConfiguration> smtpConfiguration)
        {
            _smtpConfiguration = smtpConfiguration.Value;
        }

        public Task SendEmailAsync(string email, string subject, string message, string clientId)
        {
            var emailSenderConfig = _smtpConfiguration.Items.FirstOrDefault(item => item.ClientId == clientId);

            if (emailSenderConfig == null)
            {
                emailSenderConfig = _smtpConfiguration.Items.First();
            }

            var mimeMessage = new MimeMessage();
            mimeMessage.From.Add(new MailboxAddress(emailSenderConfig.DisplayName, emailSenderConfig.UserName));
            mimeMessage.To.Add(new MailboxAddress(email));
            mimeMessage.Subject = subject;
            mimeMessage.Body = new BodyBuilder {HtmlBody = message}.ToMessageBody();
            using (var client = new SmtpClient())
            {
                client.Connect(emailSenderConfig.Host, emailSenderConfig.Port, emailSenderConfig.EnableSsl);
                // Note: since we don't have an OAuth2 token, disable 	
                // the XOAUTH2 authentication mechanism.
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(emailSenderConfig.UserName, emailSenderConfig.Password);
                client.Send(mimeMessage);
                client.Disconnect(true);
            }
            return Task.CompletedTask;
        }

        public Task SendSmsAsync(string number, string message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }
}
