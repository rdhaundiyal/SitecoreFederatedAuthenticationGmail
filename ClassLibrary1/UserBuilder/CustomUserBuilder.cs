using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SitecoreGmailAuth.UserBuilder
{
    public class CustomUserBuilder : ExternalUserBuilder
    {
        [Obsolete("Use DefaultExternalUserBuilder(bool isPersistentUser) instead.")]
        public CustomUserBuilder()
          : this(true)
        {
        }

        public CustomUserBuilder(bool isPersistentUser)
        {
            this.IsPersistentUser = isPersistentUser;
        }

        public CustomUserBuilder(string isPersistentUser)
          : this(bool.Parse(isPersistentUser))
        {
        }

        public bool IsPersistentUser { get; set; }

        public override ApplicationUser BuildUser(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            return new ApplicationUser(this.CreateUniqueUserName(userManager, externalLoginInfo))
            {
                IsVirtual = !this.IsPersistentUser,

            };
        }

        [SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Login")]
        protected virtual string CreateUniqueUserName(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull((object)userManager, nameof(userManager));
            Assert.ArgumentNotNull((object)externalLoginInfo, nameof(externalLoginInfo));
            IdentityProvider identityProvider = this.FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);
            if (identityProvider == null)
                throw new InvalidOperationException("Unable to retrieve identity provider for given identity");
            string domain = identityProvider.Domain;
            return domain + "\\" + externalLoginInfo.Email;

        }
    }
}
