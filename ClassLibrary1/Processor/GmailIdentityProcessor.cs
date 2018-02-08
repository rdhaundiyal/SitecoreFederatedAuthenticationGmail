using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;


namespace SitecoreGmailAuth.Processor
{
   public class GmailIdentityProcessor:IdentityProvidersProcessor
    {
        public GmailIdentityProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) :
            base(federatedAuthenticationConfiguration)
        {
        }

        /// <summary>
        /// Identityprovider name. Has to match the configuration
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Google"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
          
            var clientId = Sitecore.Configuration.Settings.GetSetting("FedAuth.Google.ClientId");
            var clientSecret = Sitecore.Configuration.Settings.GetSetting("FedAuth.Google.ClientSecret");
            var domain = Sitecore.Configuration.Settings.GetSetting("FedAuth.Google.Domain");

            var provider = new GoogleOAuth2AuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    // transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                },

                OnReturnEndpoint = (context) =>
                {
                    // xsrf validation
                    if (context.Request.Query["state"] != null && context.Request.Query["state"].Contains("xsrf="))
                    {
                        var state = HttpUtility.ParseQueryString(context.Request.Query["state"]);
                        //todo: do something with it.
                        //change response status to 401 in case of forgery
                    }

                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            args.App.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = clientId,
                ClientSecret =clientSecret,
                Provider = provider

            });


        }
    }
}
