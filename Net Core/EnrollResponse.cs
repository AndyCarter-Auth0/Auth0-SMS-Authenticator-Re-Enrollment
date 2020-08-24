using Newtonsoft.Json;

namespace NetCore
{
    public class EnrollResponse
    {
        [JsonProperty("authenticator_type")]
        public string AuthenticatorType { get; set; }

        [JsonProperty("binding_method")]
        public string BindingMethod { get; set; }

        [JsonProperty("recovery_codes")]
        public string[] RecoveryCodes { get; set; }

        [JsonProperty("oob_channel")]
        public string OobChannel { get; set; }

        [JsonProperty("oob_code")]
        public string OobCode { get; set; }
    }
}
