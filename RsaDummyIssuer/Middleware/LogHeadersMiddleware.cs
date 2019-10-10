using System;
using System.Text;
using Microsoft.AspNetCore.Builder;

namespace RsaDummyIssuer.Middleware
{
    public static class ApplicationBuilderExtensions
    {
        public static void LogRequestHeaders(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                Console.WriteLine("Request Headers:");
                
                var builder = new StringBuilder(Environment.NewLine);
                foreach (var (key, value) in context.Request.Headers)
                {
                    builder.AppendLine($"{key}:{value}");
                }
                Console.WriteLine(builder.ToString());
                
                await next.Invoke();
                
                Console.WriteLine("Response Headers:");
                
                builder = new StringBuilder(Environment.NewLine);
                foreach (var (key, value) in context.Response.Headers)
                {
                    builder.AppendLine($"{key}:{value}");
                }
                Console.WriteLine(builder.ToString());
            });
        }

    }
}