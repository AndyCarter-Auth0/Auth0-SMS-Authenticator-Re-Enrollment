using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Net_Core.Models;
using Newtonsoft.Json;
using RestSharp;
using Serilog;

namespace NetCore.Controllers
{
    public class HomeController : Controller
    {
        /// <summary>
        /// Configuration
        /// </summary>
        private readonly string _tokenValidationIssuer;
        private readonly string _tokenValidationAudience;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _domain;
        private readonly string _audience;
        private readonly string _scopes;
        private readonly string _redirectUri;
        private readonly string _customClaimNamespace;
        private readonly string _tokenValidationSigningKey;

        private static IConfiguration _configuration;

        public HomeController(IConfiguration config)
        {
            _configuration = config;
            _tokenValidationIssuer = _configuration["Auth0:TokenValidation:Issuer"];
            _tokenValidationAudience = _configuration["auth0:TokenValidation:Audience"];
            _clientId = _configuration["auth0:ClientId"];
            _clientSecret = _configuration["auth0:ClientSecret"];
            _domain = _configuration["auth0:Domain"];
            _audience = _configuration["auth0:Audience"];
            _scopes = _configuration["auth0:ClientScopes"];
            _redirectUri = _configuration["auth0:RedirectUri"];
            _customClaimNamespace = _configuration["auth0:CustomClaimNamespace"];
            _tokenValidationSigningKey = _configuration["auth0:TokenValidation:SigningKey"];
        }
        public IActionResult Index(string token, string state)
        {
            // If the token or state is not present, return an error
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(state))
            {
                return RedirectToAction("Error");
            }

            // Validate the token sent from the Auth0 redirect rule
            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = _tokenValidationIssuer,
                    ValidAudiences = new[] { _tokenValidationAudience },
                    IssuerSigningKeys = new List<SecurityKey> { new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_tokenValidationSigningKey)) }
                };

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            try
            {
                handler.ValidateToken(token, validationParameters, out validatedToken);
            }
            catch (Exception)
            {
                // The token could not be validated, return an error
                return RedirectToAction("Error");
            }

            if (validatedToken == null)
            {
                // The token could not be validated, return an error
                return RedirectToAction("Error");
            }

            // Create the redirect URL to request an MFA access token for the user, using the credentials of the MFA application
            var nonce = new Guid().ToString();
            var redirect = $"https://{_domain}/authorize?grant_type=authorization_code&response_mode=form_post&response_type=code token id_token&client_id={_clientId}&client_secret={_clientSecret}&audience={_audience}&scope={_scopes}&redirect_uri={_redirectUri}&nonce={nonce}&state={state}";

            // Redirect the user
            return Redirect(redirect);
        }


        [HttpPost]
        [Route("processenrollment")]
        public IActionResult ProcessEnrollment(IFormCollection collection)
        {
            var mfaToken = collection["access_token"].ToString();
            var idToken = collection["id_token"].ToString();
            var state = collection["state"].ToString();

            if (mfaToken == null || state == null || idToken == null)
            {
                Log.Error("An mfa token, id token or the state was not returned from the authorize endpoint");
                return View("Error");
            }
            // Read the ID token sent and extract the SMS number from the token
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token;
            try
            {
                token = handler.ReadJwtToken(idToken);
            }
            catch (Exception)
            {
                // The token could not be read, return an error
                Log.Error("Could not read id token {0}", idToken);
                return RedirectToAction("Error");
            }

            if (token.Claims.All(c => c.Type.ToLower() != $"{_customClaimNamespace}smsnumber"))
            {
                // The phone number claim is not present
                Log.Error("A claim of smsnumber is not present in the user's id token {0}", idToken);
                return RedirectToAction("Error");
            }

            var smsNumber = token.Claims.FirstOrDefault(c => c.Type.ToLower() == $"{_customClaimNamespace}smsnumber")?.Value;

            // Store the state and mfa token
            HttpContext.Session.SetString("mfaToken", mfaToken);
            HttpContext.Session.SetString("state", state);

            // Create the enrollment request
            var client = new RestClient($"{_audience}associate");
            var request = new RestRequest(Method.POST);
            request.AddHeader("authorization", $"Bearer {mfaToken}");
            request.AddHeader("content-type", "application/json");
            request.AddParameter("application/json", "{ \"authenticator_types\": [\"oob\"], \"oob_channels\": [\"sms\"], \"phone_number\": \"" + smsNumber + "\" }", ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            if (response.ResponseStatus == ResponseStatus.Error)
            {
                Log.Error("The phone number of {0} could not be associated to the user with mfa token {1}", smsNumber, mfaToken);
                return RedirectToAction("Error");
            }

            var enrollResponse = JsonConvert.DeserializeObject<EnrollResponse>(response.Content);//serializer.Deserialize<EnrollResponse>(response.Content);
            var oobCode = enrollResponse.OobCode;

            // Store the oob_code returned
            HttpContext.Session.SetString("oobCode", oobCode);

            return View();
        }

        [HttpPost]
        public IActionResult UpdateEnrollment(string smsCode)
        {
            if (string.IsNullOrEmpty(smsCode))
            {
                Log.Error("The user hasn't entered the sms code they received");
                return View("ProcessEnrollment");
            }
            var mfaToken = HttpContext.Session.GetString("mfaToken");
            var oobCode = HttpContext.Session.GetString("oobCode");
            if (mfaToken == null || oobCode == null)
            {
                Log.Error("The mfa token and oob code are not in session for the user");
                return View("Error");
            }
            var clientId = _clientId;
            var clientSecret = _clientSecret;
            var client = new RestClient($"https://{_domain}/oauth/token");
            var request = new RestRequest(Method.POST);
            request.AddHeader("authorization", $"Bearer {mfaToken}");
            request.AddHeader("content-type", "application/x-www-form-urlencoded");
            request.AddParameter("application/x-www-form-urlencoded", $"grant_type=http%3A%2F%2Fauth0.com%2Foauth%2Fgrant-type%2Fmfa-oob&client_id={clientId}&client_secret={clientSecret}&mfa_token={mfaToken}&oob_code={oobCode}&binding_code={smsCode}", ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            if (response.ResponseStatus == ResponseStatus.Error)
            {
                return RedirectToAction("ProcessEnrollment");
            }

            // Get the state from session
            var state = HttpContext.Session.GetString("state");

            if (state == null)
            {
                Log.Error("Could not retrieve state from session to redirect the user back to Auth0");
                return RedirectToAction("Error");
            }

            return Redirect($"https://{_domain}/continue?state={state}");
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
