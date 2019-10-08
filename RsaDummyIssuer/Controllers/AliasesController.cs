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
using RsaDummyIssuer.Data;
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
        public async Task<ActionResult> Post()
        {
            string jweMessage;
            using (var reader = new StreamReader(Request.Body, Encoding.UTF8))
            {  
                jweMessage = await reader.ReadToEndAsync();
            }
           
            var raw = JweMessage.FromEncryptedString(
                jweMessage, 
                IssuerEncryptionCert.GetP12Cert(),
                new DevJweCryptoPolicy()
            );
            
            Console.WriteLine($"Received POST request: Decrypted Payload:\n{raw.GetClearTextMessage()}");
            Console.WriteLine("=======================================================================");
            
            var request = JweMessage.FromEncryptedString<FetchAvailableAliasesRequests>(
                jweMessage, 
                IssuerEncryptionCert.GetP12Cert(),
                new DevJweCryptoPolicy()
            );
            
            var response = new FetchAvailableAliasesResponse
            { 
                RsaSessionId = request.RsaSessionId,
                IssuerSessionId = request.IssuerSessionId,
                Version = "3.1",
                TimeStamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                AvailableAliases = new AvailableAliases[]
                {
                    new AvailableAliases
                    {
                        Alias = "0800-83-83-83", 
                        AliasType = AvailableAliases.AliasTypes.SMS, 
                        DisplayAlias = "Mobile",
                        AliasId = "1234", 
                        DisplayAliasType = "SMS"
                    }
                }
            };

            
            Console.WriteLine($"Returning response:\n{JsonConvert.SerializeObject(response)}");
            Console.WriteLine("=======================================================================");
            
            return new ObjectResult(
                JweMessage.CreateFrom(
                    response, 
                    IssuerEncryptionCert.GetP12Cert(),
                    new List<X509Certificate2> { IssuerEncryptionCert.GetP12Cert() }));
        }
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
