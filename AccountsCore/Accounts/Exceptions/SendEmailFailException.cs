using System;

namespace Accounts.Data.Exceptions
{
    public class SendEmailFailException : Exception
    {
        public SendEmailFailException(string message) : base(message)
        {
        }
    }
}
