using Microsoft.AspNetCore.Identity;

namespace TwoFactorAuth.Models
{
    public class ApplicationUser:IdentityUser
    {
        public bool IsAuthenticatorEnabled { get; set; }
    }
}
