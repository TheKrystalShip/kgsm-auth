using System.Text.Json;
using System.Text.Json.Serialization;

namespace TheKrystalShip.KGSM.Auth.Anchor;

/// <summary>
/// The identity a provider session was proved with, which every session minted under it carries.
/// </summary>
/// <remarks>
/// Stored rather than re-derived from the handle, because a handle names a credential and not how its
/// holder is shown: a provider supplies the name and picture at the moment somebody arrives, and the
/// sessions a browser is later handed without typing anything must carry what that arrival said.
/// </remarks>
internal sealed record StoredIdentity(
    string Provider,
    string Subject,
    string Username,
    string Display,
    string? AvatarUrl,
    IReadOnlyList<string> Scopes)
{
    public static StoredIdentity From(KgsmIdentity identity) =>
        new(identity.Provider, identity.Subject, identity.Username, identity.Display, identity.AvatarUrl,
            identity.Scopes);

    public KgsmIdentity ToIdentity() => new(Provider, Subject, Username, Display, AvatarUrl, Scopes);

    public string Handle => ToIdentity().Handle;

    public string ToJson() => JsonSerializer.Serialize(this, AnchorJsonContext.Default.StoredIdentity);

    /// <summary>The identity a row holds, or null when the text is not one.</summary>
    public static StoredIdentity? Read(string json)
    {
        try
        {
            return JsonSerializer.Deserialize(json, AnchorJsonContext.Default.StoredIdentity);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>The OpenID Connect discovery document.</summary>
/// <remarks>Only what this provider does. A capability listed here and not served is a client that fails
/// somewhere its authors never looked.</remarks>
internal sealed record OidcDiscovery(
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("authorization_endpoint")] string AuthorizationEndpoint,
    [property: JsonPropertyName("token_endpoint")] string TokenEndpoint,
    [property: JsonPropertyName("userinfo_endpoint")] string UserinfoEndpoint,
    [property: JsonPropertyName("jwks_uri")] string JwksUri,
    [property: JsonPropertyName("end_session_endpoint")] string EndSessionEndpoint,
    [property: JsonPropertyName("response_types_supported")] IReadOnlyList<string> ResponseTypesSupported,
    [property: JsonPropertyName("response_modes_supported")] IReadOnlyList<string> ResponseModesSupported,
    [property: JsonPropertyName("grant_types_supported")] IReadOnlyList<string> GrantTypesSupported,
    [property: JsonPropertyName("subject_types_supported")] IReadOnlyList<string> SubjectTypesSupported,
    [property: JsonPropertyName("id_token_signing_alg_values_supported")] IReadOnlyList<string> IdTokenSigningAlgValuesSupported,
    [property: JsonPropertyName("scopes_supported")] IReadOnlyList<string> ScopesSupported,
    [property: JsonPropertyName("claims_supported")] IReadOnlyList<string> ClaimsSupported,
    [property: JsonPropertyName("code_challenge_methods_supported")] IReadOnlyList<string> CodeChallengeMethodsSupported,
    [property: JsonPropertyName("token_endpoint_auth_methods_supported")] IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    [property: JsonPropertyName("prompt_values_supported")] IReadOnlyList<string> PromptValuesSupported,
    [property: JsonPropertyName("authorization_response_iss_parameter_supported")] bool AuthorizationResponseIssParameterSupported);

/// <summary>What <c>/token</c> answers with.</summary>
internal sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string RefreshToken,
    [property: JsonPropertyName("id_token")] string? IdToken,
    [property: JsonPropertyName("scope")] string Scope);

/// <summary>An OAuth error, in the shape every OAuth client reads.</summary>
internal sealed record OAuthError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string? ErrorDescription);

/// <summary>The account as the bearer's session sees it.</summary>
internal sealed record UserInfoResponse(
    [property: JsonPropertyName("sub")] string Sub,
    [property: JsonPropertyName("preferred_username")] string PreferredUsername,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("picture")] string? Picture);

/// <summary>
/// What the provider's own pages are told after a credential, when they asked in JSON.
/// </summary>
/// <remarks>A code at the end of a URL, or the wait — never a session. Nothing the provider's pages
/// hold can call a member.</remarks>
/// <param name="Redirect">Where to send the browser: the client, carrying its code.</param>
/// <param name="Wait">The wait page, for an account an administrator has not approved.</param>
internal sealed record CredentialAnswer(string? Redirect, string? Wait);

/// <summary>A client, as the administration surface lists one.</summary>
internal sealed record ClientRecord(
    string ClientId,
    string Name,
    IReadOnlyList<string> RedirectUris,
    IReadOnlyList<string> PostLogoutRedirectUris,
    string Source,
    string? MemberId,
    DateTimeOffset Created);

/// <summary>Every registered client.</summary>
internal sealed record ClientsPage(IReadOnlyList<ClientRecord> Data);

/// <summary>What an administrator posts to register a client.</summary>
/// <param name="ClientId">The id, or null to have one made.</param>
/// <param name="Name">What a person is shown on the sign-in page.</param>
/// <param name="RedirectUris">Where codes may be sent, each matched exactly.</param>
/// <param name="PostLogoutRedirectUris">Where a signed-out browser may be returned, each matched exactly.</param>
internal sealed record ClientRegistration(
    string? ClientId,
    string? Name,
    IReadOnlyList<string>? RedirectUris,
    IReadOnlyList<string>? PostLogoutRedirectUris);

/// <summary>What the provider's pages are told about the request in flight.</summary>
/// <param name="Client">Whose sign-in this is.</param>
/// <param name="Providers">The external providers wired here, in the order the page draws them.</param>
/// <param name="Registration">Whether somebody with no account may make one here.</param>
/// <param name="Account">Who this browser is already signed in as, or null.</param>
internal sealed record AuthorizeContext(
    AuthorizeContextClient Client,
    IReadOnlyList<string> Providers,
    bool Registration,
    AuthorizeContextAccount? Account);

/// <summary>The client a request in flight belongs to.</summary>
internal sealed record AuthorizeContextClient(string Id, string Name);

/// <summary>The account a browser's provider session proves.</summary>
internal sealed record AuthorizeContextAccount(string Username, string DisplayName, string Status);

/// <summary>Everything the account page draws, for the account this browser is signed in to.</summary>
/// <param name="UserId">The account.</param>
/// <param name="Username">What it signs in as.</param>
/// <param name="DisplayName">What it is shown as.</param>
/// <param name="Tier">What it may do, as the store resolves it now.</param>
/// <param name="Status">Active, pending or disabled.</param>
/// <param name="Identities">The provider accounts attached to it.</param>
/// <param name="HasPassword">Whether the account holds a password, which decides how it re-proves itself.</param>
/// <param name="Providers">The providers an identity can be attached from here.</param>
/// <param name="KnownProviders">Every provider this build speaks, configured or not.</param>
/// <param name="ProvedAt">When a credential last proved this browser's sign-in.</param>
/// <param name="FreshUntil">Until when a change to how the account signs in is allowed without asking
/// again, or null when it has to ask.</param>
/// <param name="ReauthWindowSeconds">How long a proof stays recent.</param>
/// <param name="Sessions">Where the account is signed in, this browser's sign-in marked current.</param>
internal sealed record AccountView(
    string UserId,
    string Username,
    string DisplayName,
    string Tier,
    string Status,
    bool HasPassword,
    IReadOnlyList<AccountIdentity> Identities,
    IReadOnlyList<string> Providers,
    IReadOnlyList<string> KnownProviders,
    DateTimeOffset ProvedAt,
    DateTimeOffset? FreshUntil,
    int ReauthWindowSeconds,
    IReadOnlyList<SessionRecord> Sessions);

/// <summary>An identity attached to the account.</summary>
internal sealed record AccountIdentity(
    string Id, string Provider, string Handle, string? Label, DateTimeOffset Created, DateTimeOffset? LastUsed);
