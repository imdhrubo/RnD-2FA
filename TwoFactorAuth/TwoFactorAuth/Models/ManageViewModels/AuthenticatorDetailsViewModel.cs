using System.ComponentModel.DataAnnotations;
namespace TwoFactorAuth.Models.ManageViewModels
{
    public class AuthenticatorDetailsViewModel
    {
        public string SharedKey { get; set; }

        public string AuthenticatorUri { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
