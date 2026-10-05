import { Icon, Modal } from "@thekrystalship/krystal-ui";

// ConfirmRevokeDialog — the confirmation in front of ending somebody else's session, for whoever
// holds auth:accounts.disable on the Accounts page. A person's own sessions are ended on the
// account page, which asks for its own confirmation.
//
// Two variants over the same markup:
//   "other-one" — one of another person's sessions
//   "other-all" — every one of another person's, on every device
//
// Both take `targetName` so the copy names who is affected. A destructive action against another
// person is never anonymous: whoever is about to sign somebody out is owed the name they will have
// to explain it to.
function ConfirmRevokeDialog({ mode, targetName, busy, onConfirm, onClose }) {
  const isAll = mode === "other-all";
  const who = targetName || "that account";

  const title = isAll ? `Sign ${who} out everywhere?` : `End this session for ${who}?`;
  const text = isAll
    ? `This ends every active session for ${who}, on every device. They can sign in again straight away — this ends the sessions, it does not disable the account.`
    : `This ends that one session. ${who}'s other devices stay signed in.`;

  return (
    <Modal onClose={busy ? undefined : onClose} canClose={!busy}>
      <div className="modal host-remove">
        <div className="host-remove__icon host-remove__icon--danger">
          <Icon name="log-out" size={20} />
        </div>
        <h2 className="host-remove__title">{title}</h2>
        <p className="host-remove__text">{text}</p>
        <div className="host-remove__foot">
          <button className="host-btn host-btn--ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="host-btn host-btn--danger" onClick={onConfirm} disabled={busy}>
            <Icon name="log-out" size={14} />{" "}
            {busy ? "Working…" : isAll ? "Sign out" : "End session"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export { ConfirmRevokeDialog };
