// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.BearerToken.DTO;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Authentication.BearerToken;

internal sealed class BearerTokenHandler(
    IOptionsMonitor<BearerTokenOptions> optionsMonitor,
    ILoggerFactory loggerFactory,
    UrlEncoder urlEncoder,
    ISystemClock clock,
#pragma warning disable IDE0060 // Remove unused parameter. False positive fixed by https://github.com/dotnet/roslyn/pull/67167
    IDataProtectionProvider dataProtectionProvider)
#pragma warning restore IDE0060 // Remove unused parameter
    : SignInAuthenticationHandler<BearerTokenOptions>(optionsMonitor, loggerFactory, urlEncoder, clock)
{
    private const string BearerTokenPurpose = $"Microsoft.AspNetCore.Authentication.BearerToken:v1:BearerToken";

    private static readonly AuthenticateResult FailedUnprotectingToken = AuthenticateResult.Fail("Unprotected token failed");
    private static readonly AuthenticateResult TokenExpired = AuthenticateResult.Fail("Token expired");

    private ISecureDataFormat<AuthenticationTicket> BearerTokenProtector
        => Options.BearerTokenProtector ?? new TicketDataFormat(dataProtectionProvider.CreateProtector(BearerTokenPurpose));

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // If there's no bearer token, forward to cookie auth.
        if (await GetBearerTokenOrNullAsync() is not string token)
        {
            return AuthenticateResult.NoResult();
        }

        var ticket = BearerTokenProtector.Unprotect(token);

        if (ticket?.Properties?.ExpiresUtc is null)
        {
            return FailedUnprotectingToken;
        }

        if (Clock.UtcNow >= ticket.Properties.ExpiresUtc)
        {
            return TokenExpired;
        }

        return AuthenticateResult.Success(ticket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.Append(HeaderNames.WWWAuthenticate, "Bearer");
        await base.HandleChallengeAsync(properties);
    }

    protected override Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        properties ??= new();
        properties.ExpiresUtc ??= Clock.UtcNow + Options.BearerTokenExpiration;

        var ticket = new AuthenticationTicket(user, properties, Scheme.Name);
        var accessTokenResponse = new AccessTokenResponse
        {
            AccessToken = BearerTokenProtector.Protect(ticket),
            ExpiresInTotalSeconds = Options.BearerTokenExpiration.TotalSeconds,
        };

        return Context.Response.WriteAsJsonAsync(accessTokenResponse, BearerTokenJsonSerializerContext.Default.AccessTokenResponse);
    }

    // No-op to avoid interfering with any mass sign-out logic.
    protected override Task HandleSignOutAsync(AuthenticationProperties? properties) => Task.CompletedTask;

    private async ValueTask<string?> GetBearerTokenOrNullAsync()
    {
        if (Options.ExtractBearerToken is not null &&
            await Options.ExtractBearerToken(Context) is string token)
        {
            return token;
        }

        var authorization = Request.Headers.Authorization.ToString();

        return authorization.StartsWith("Bearer ", StringComparison.Ordinal)
            ? authorization["Bearer ".Length..]
            : null;
    }
}
