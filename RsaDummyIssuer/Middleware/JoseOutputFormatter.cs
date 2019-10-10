using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using RsaThreeDeeSecure.Jwe;
using RsaThreeDeeSecure.Messages.Responses;
using RsaThreeDeeSecure.Messages.Shared;

namespace RsaDummyIssuer.Middleware
{
    public class JoseOutputFormatter : TextOutputFormatter
    {
        public JoseOutputFormatter()
        {
            SupportedMediaTypes.Add(MediaTypeHeaderValue.Parse("application/jose"));
            SupportedEncodings.Add(Encoding.UTF8);
        }

        protected override bool CanWriteType(Type type)
        {
            if (typeof(Success).IsAssignableFrom(type) 
                || typeof(IEnumerable<Success>).IsAssignableFrom(type))
            {
                return base.CanWriteType(type);
            }
            
            return false;
        }

        public override async Task WriteResponseBodyAsync(OutputFormatterWriteContext context, Encoding selectedEncoding)
        {
            var response = context.HttpContext.Response;

            var buffer = new StringBuilder();
            if (context.Object is IEnumerable<Success> responses)
            {
                foreach (var success in responses)
                {
                    EncryptResponse(buffer, success);
                }
            }
            else
            {
                var success = context.Object as Success;
                EncryptResponse(buffer, success);
            }
            
            await response.WriteAsync(buffer.ToString());
        }
        
        private static void EncryptResponse(StringBuilder buffer, Success successResponse)
        {
            Console.WriteLine("=======================================================================");
            Console.WriteLine($"Responding with:\n{JsonConvert.SerializeObject(successResponse)}");
            
            var encrypted = JweMessage.CreateFrom(
                successResponse,
                ClientEncryptionCert,
                new List<X509Certificate2> {IssuerSigningCert});
            
                                
            Console.WriteLine("=======================================================================");
            Console.WriteLine($"Responding with encrypted Payload:\n{encrypted}");
            
            buffer.AppendLine(encrypted);
        }
        
        private static X509Certificate2 ClientEncryptionCert => new X509Certificate2("./certs/clientEncryption.p12");
        private static X509Certificate2 IssuerSigningCert => new X509Certificate2("./certs/issuerSigning.p12");
    }
}
