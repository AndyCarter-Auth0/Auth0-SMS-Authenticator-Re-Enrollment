using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
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
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _domain;
        private readonly string _audience;
        private readonly string _scopes;
        private readonly string _redirectUri;
        private readonly string _customClaimNamespace;
        private readonly string _managementApiAudience;
        private readonly string _managementApiDomain;

        public HomeController(IConfiguration config)
        {
            var configuration = config;
            _clientId = configuration["auth0:ClientId"];
            _clientSecret = configuration["auth0:ClientSecret"];
            _domain = configuration["auth0:Domain"];
            _audience = configuration["auth0:Audience"];
            _scopes = configuration["auth0:ClientScopes"];
            _redirectUri = configuration["auth0:RedirectUri"];
            _customClaimNamespace = configuration["auth0:CustomClaimNamespace"];
            _managementApiAudience = configuration["auth0:ManagementApiAudience"];
            _managementApiDomain = configuration["auth0:ManagementApiDomain"];
        }


        public IActionResult Index(string state)
        {
            // If the state parameter from the Auth0 redirect is not present, return an error
            if (string.IsNullOrEmpty(state))
            {
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
            var smsNumber = GetClaimValueFromToken(idToken, $"{_customClaimNamespace}smsnumber");

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

            var enrollResponse = JsonConvert.DeserializeObject<EnrollResponse>(response.Content);
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

            // Update the user in Auth0 to say the process is complete
            // Request a token to use with the Auth0 management API
            var managementApiTokenResponse = GetManagementApiToken();
            if (managementApiTokenResponse == null)
            {
                return RedirectToAction("Error");
            }
            // Get the subject claim from the MFA token so we have the user id
            var userId = GetClaimValueFromToken(mfaToken, "sub");

            var apiClient = new RestClient($"{_managementApiAudience}users/{userId}");
            var apiRequest = new RestRequest(Method.PATCH);
            apiRequest.AddHeader("authorization", $"Bearer {managementApiTokenResponse.AccessToken}");
            apiRequest.AddHeader("content-type", "application/json");
            apiRequest.AddParameter("application/json", "{\"app_metadata\": {\"mfa_enrollment_complete\": \"true\"}}", ParameterType.RequestBody);
            IRestResponse apiResponse = apiClient.Execute(apiRequest);

            if (apiResponse.ResponseStatus == ResponseStatus.Error)
            {
                Log.Error("Could not update user's app_metadata in Auth0");
                return RedirectToAction("Error");
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

        /// <summary>
        /// Requests an access token for use with the Auth0 Management API
        /// </summary>
        /// <returns>A ManagementApiTokenResponse object containing the access token</returns>
        private ManagementApiTokenResponse GetManagementApiToken()
        {
            var managementTokenClient = new RestClient($"https://{_managementApiDomain}/oauth/token");
            var managementTokenRequest = new RestRequest(Method.POST);
            managementTokenRequest.AddHeader("content-type", "application/x-www-form-urlencoded");
            managementTokenRequest.AddParameter("application/x-www-form-urlencoded", $"grant_type=client_credentials&client_id={_clientId}&client_secret={_clientSecret}&audience={_managementApiAudience}&scope=update:users_app_metadata", ParameterType.RequestBody);
            IRestResponse managementTokenResponse = managementTokenClient.Execute(managementTokenRequest);
            if (managementTokenResponse.StatusCode != HttpStatusCode.OK)
            {
                // The token was not issued, return an error
                Log.Error("Could not get a management API token {0}", managementTokenResponse.ErrorMessage);
                return null;
            }

            ManagementApiTokenResponse managementApiTokenResponse =
                JsonConvert.DeserializeObject<ManagementApiTokenResponse>(managementTokenResponse.Content);
            return managementApiTokenResponse;
        }

        private string GetClaimValueFromToken(string token, string claim)
        {
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken;
            try
            {
                jwtToken = handler.ReadJwtToken(token);
            }
            catch (Exception)
            {
                // The token could not be read, return an error
                Log.Error("Could not read token {0}", token);
                return null;
            }

            if (jwtToken.Claims.All(c => c.Type.ToLower() != "sub"))
            {
                // The phone number claim is not present
                Log.Error($"A claim of {claim} is not present in the token {0}", token);
                return null;
            }

            var value = jwtToken.Claims.FirstOrDefault(c => c.Type.ToLower() == claim)?.Value;

            return value;
        }

    }

}
