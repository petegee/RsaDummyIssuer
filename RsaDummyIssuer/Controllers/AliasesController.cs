using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using RsaThreeDeeSecure.Jwe;
using RsaThreeDeeSecure.Messages.Requests;
using RsaThreeDeeSecure.Messages.Responses;
using RsaThreeDeeSecure.Messages.Shared;

namespace RsaDummyIssuer.Controllers
{
    [ApiController]
    public class AliasesController : ControllerBase
    {
        [Route("3.1/fetchAvailableAliases")]
        [HttpPost]
        //[Produces("application/jose")]
        public async Task<ActionResult> Post()
        {
            string jweMessage;
            using (var reader = new StreamReader(Request.Body, Encoding.UTF8))
            {  
                jweMessage = await reader.ReadToEndAsync();
            }
           
            var raw = JweMessage.FromEncryptedString(
                jweMessage, 
                IssuerEncryptionCert,
                new DevJweCryptoPolicy()
            );
            
            Console.WriteLine($"Received POST request: Decrypted Payload:\n{raw.GetClearTextMessage()}");
            Console.WriteLine("=======================================================================");

            var request = raw.GetDecryptedJsonObjectAs<FetchAvailableAliasesRequest>();
            
            var response = Success.WrapResponse(
                new FetchAvailableAliasesResponse
                { 
                    RsaSessionId = request.RsaSessionId,
                    IssuerSessionId = request.IssuerSessionId,
                    Version = "3.1",
                    TimeStamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss"),
                    AvailableAliases = new[]
                    {
                        new AvailableAliases
                        {
                            Alias = "0800838383", 
                            AliasType = AvailableAliases.AliasTypes.SMS.ToString(), 
                            DisplayAlias = "Mobile",
                            AliasId = "123", 
                            DisplayAliasType = "SMS"
                        }
                    }
                });

            
            Console.WriteLine($"Returning response:\n{JsonConvert.SerializeObject(response)}");
            Console.WriteLine("=======================================================================");

            var encrypted = JweMessage.CreateFrom(
                response,
                ClientEncryptionCert,
                new List<X509Certificate2> {IssuerSigningCert});
            
            
            return new ObjectResult(encrypted);
        }


        private X509Certificate2 ClientEncryptionCert => new X509Certificate2("./certs/clientEncryption.p12");
        private X509Certificate2 ClientSigninCert => new X509Certificate2("./certs/clientSigning.p12");
        private X509Certificate2 IssuerEncryptionCert => new X509Certificate2("./certs/issuerEncryption.p12");
        private X509Certificate2 IssuerSigningCert => new X509Certificate2("./certs/issuerSigning.p12");


        private string CannedResponse =
            "{ " +
            "    \"success\":{ " +
            "    \"rsaSessionId\":\"6100110510100344\"," +
            "    \"issuerSessionId\":\"d04c3a7e-a0f8-4d70-bae0-449c36557847\"," +
            "    \"timeStamp\":\"20191009002447\"," +
            "    \"version\":\"3.1\"," +
            "    \"service\":\"RSA_CLIENT\"," +
            "    \"availableAliases\":[ " +
            "    { " +
            "    \"alias\":\"442072343456\"," +
            "    \"displayAlias\":\"44207****456\"," +
            "    \"aliasType\":\"SMS\"," +
            "    \"displayAliasType\":\"mobile\"," +
            "    \"aliasId\":\"001\"" +
            "    }" +
            "    ]" +
            "    }" +
            "}    ";


    }
    
    public class DevJweCryptoPolicy : IJweCryptoPolicy
    {
        public X509Chain GetX509TrustChain()
            => new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority |
                                        X509VerificationFlags.IgnoreInvalidBasicConstraints
                }
            };

        public bool IgnoreMessageExpiry => true;
    }
}
