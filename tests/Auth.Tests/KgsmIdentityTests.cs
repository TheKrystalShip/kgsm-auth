namespace TheKrystalShip.KGSM.Auth.Tests;

/// <summary>
/// The two strings an identity produces. They are deliberately different, and each is load-bearing
/// somewhere the other would be wrong.
/// </summary>
public class KgsmIdentityTests
{
    private static KgsmIdentity Identity(string provider = "discord", string subject = "198772043",
        string username = "haru") =>
        new(provider, subject, username, "Haru", null, []);

    [Fact]
    public void TheHandleIsProviderColonSubject() =>
        Assert.Equal("discord:198772043", Identity().Handle);

    [Fact]
    public void TheActorStringPrefersTheUsername() =>
        // An audit log is read by people. The subject is stable but tells a reader nothing.
        Assert.Equal("discord:haru", Identity().ActorString);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TheActorStringFallsBackToTheSubject(string username) =>
        // A username is not guaranteed by every provider; the subject always is. Falling back keeps
        // the action attributable rather than blank.
        Assert.Equal("discord:198772043", Identity(username: username).ActorString);

    [Fact]
    public void TheHandleNeverFallsBackToTheUsername()
    {
        // The handle keys sessions and, later, a linked account. A username can be changed by its
        // owner at most providers, so keying on one would silently detach a person from their own
        // sessions the day they renamed themselves.
        Assert.Equal("discord:198772043", Identity(username: "").Handle);
    }

    [Fact]
    public void AHandleRoundTripsThroughTheActorParser()
    {
        Assert.True(KgsmActor.TryParse(Identity(provider: "github", subject: "u_9931").Handle,
            out string provider, out string subject));
        Assert.Equal("github", provider);
        Assert.Equal("u_9931", subject);
    }
}
