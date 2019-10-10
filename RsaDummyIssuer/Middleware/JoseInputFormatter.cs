using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using RsaDummyIssuer.Controllers;
using RsaThreeDeeSecure.Jwe;
using RsaThreeDeeSecure.Messages.Requests;

namespace RsaDummyIssuer.Middleware
{
    #region classdef
    public class JoseInputFormatter : TextInputFormatter
    #endregion
    {
        public JoseInputFormatter()
        {
            SupportedMediaTypes.Add(MediaTypeHeaderValue.Parse("application/jose"));

            SupportedEncodings.Add(Encoding.UTF8);
            SupportedEncodings.Add(Encoding.Unicode);
        }

        protected override bool CanReadType(Type type)
        {
            return type == typeof(FetchAvailableAliasesRequest) && base.CanReadType(type);
        }

        public override async Task<InputFormatterResult> ReadRequestBodyAsync(InputFormatterContext context, Encoding effectiveEncoding)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            if (effectiveEncoding == null)
                throw new ArgumentNullException(nameof(effectiveEncoding));

            var request = context.HttpContext.Request;

            using (var reader = new StreamReader(request.Body, effectiveEncoding))
            {
                try
                {
                    var message = await reader.ReadToEndAsync();
                    
                    Console.WriteLine("=======================================================================");
                    Console.WriteLine($"Received POST request: Encrypted Payload:\n{message}");
                    
                    var rsaRequest = JweMessage.FromEncryptedString(
                        message, 
                        new List<X509Certificate2>{IssuerEncryptionCert},
                        new DevJweCryptoPolicy()
                    ).GetDecryptedJsonObjectAs<FetchAvailableAliasesRequest>();

                    Console.WriteLine("=======================================================================");
                    Console.WriteLine($"Received POST request: Decrypted Payload:\n{JsonConvert.SerializeObject(rsaRequest)}");

                    return await InputFormatterResult.SuccessAsync(rsaRequest);
                }
                catch
                {
                    return await InputFormatterResult.FailureAsync();
                }
            }
        }
        
        
        private static X509Certificate2 ClientSigninCert => new X509Certificate2("./certs/clientSigning.p12");
        private static X509Certificate2 IssuerEncryptionCert => new X509Certificate2("./certs/issuerEncryption.p12");
        
    }
}