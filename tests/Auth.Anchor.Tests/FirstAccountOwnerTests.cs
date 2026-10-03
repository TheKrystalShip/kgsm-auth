using TheKrystalShip.KGSM.Auth.Access;
using TheKrystalShip.KGSM.Auth.Users;

namespace TheKrystalShip.KGSM.Auth.Anchor.Tests;

/// <summary>
/// The first account an anchor with an empty store makes for itself is an Owner.
/// </summary>
/// <remarks>
/// Read off the fixture's anchor, which started on an empty store, so this is the account a real first
/// start leaves behind rather than one a test assembled.
/// </remarks>
[Collection(AnchorCollection.Name)]
public sealed class FirstAccountOwnerTests(AnchorFixture anchor)
{
    [Fact]
    public async Task The_first_account_an_empty_store_gets_is_an_Owner()
    {
        KgsmUser first = (await anchor.Store.FindByUsernameAsync(FirstAdmin.DefaultUsername))!;

        AuthoritySnapshot s = await anchor.Store.LoadAsync();
        Assert.True(s.IsOwner(first.UserId));
        Assert.True(new AccessEvaluator(s).Allows(first.UserId, AuthActions.RolesEdit, AccessScope.Cluster).Allowed);
    }
}
