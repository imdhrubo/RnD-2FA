//using Microsoft.AspNetCore.Identity;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Threading.Tasks;
//using TwoFactorAuth.Models;

//namespace TwoFactorAuth.Services
//{
//	public class CustomPasswordValidator : PasswordValidator<ApplicationUser>
//	{
//		public int MaxLength { get; set; }

//		public async Task<IdentityResult> ValidateAsync(string password)
//		{
//			IdentityResult result = await base.ValidateAsync(password);
//			//if (String.IsNullOrEmpty(password) || password.Length > MaxLength)
//			//{
//			//	return Task.FromResult(IdentityResult.Failed(
//			//			String.Format("Password should be at least {0} characters", MaxLength)));
//			//}
//			IdentityResult result;

//			if (string.IsNullOrEmpty(password) || password.Length > MaxLength)
//			{
//				//errors.Add(string.Format("Password length can't exceed {0}", MaxLength));
//				return Task.FromResult(IdentityResult.Failed(String.Format("Password should be max {0} characters", MaxLength)));
//			}

//			//return await Task.FromResult(!errors.Any()
//			// ? IdentityResult.Success
//			// : IdentityResult.Failed(errors.ToArray()));
//		}
//	}
//}
