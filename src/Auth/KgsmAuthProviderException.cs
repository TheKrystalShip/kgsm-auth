namespace TheKrystalShip.Auth;

/// <summary>
/// An identity provider or the account store could not be reached, or answered in a way that leaves
/// the question unanswered. A caller surfaces this as an upstream error and <b>never</b> as a denial or
/// a default grant: "we could not ask" is a different fact from "the answer is no", and collapsing them
/// either locks out an Owner during an outage or, far worse, admits someone during one.
/// </summary>
public class KgsmAuthProviderException(string message, Exception? inner = null)
    : Exception(message, inner);
