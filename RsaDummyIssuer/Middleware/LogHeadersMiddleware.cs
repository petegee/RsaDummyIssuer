using System;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetcore.Builder
{
    public static class IApplicationBuilderExtensions
    {
        public static void LogRequestHeaders(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                Console.WriteLine("Request Headers:");
                
                var builder = new StringBuilder(Environment.NewLine);
                foreach (var header in context.Request.Headers)
                {
                    builder.AppendLine($"{header.Key}:{header.Value}");
                }
                Console.WriteLine(builder.ToString());
                
                await next.Invoke();
                
                Console.WriteLine("Response Headers:");
                
                builder = new StringBuilder(Environment.NewLine);
                foreach (var header in context.Response.Headers)
                {
                    builder.AppendLine($"{header.Key}:{header.Value}");
                }
                Console.WriteLine(builder.ToString());
            });
        }

    }
}