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
        [Produces("application/jose")]
        public Success Post(FetchAvailableAliasesRequest request)
        {
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
            
            return response;
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

        public bool IgnoreMessageExpiry => false;
    }
}
