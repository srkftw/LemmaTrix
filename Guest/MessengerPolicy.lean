namespace Guest.MessengerPolicy
-- Called by the live owner, not a parallel specification-only policy.
def canApprove (candidate current : UInt64) (exactFingerprint : Bool) : Bool :=
  (candidate == 1 || candidate == 2) && current == 1 && exactFingerprint
def canPublishSend (unlocked approved stateCommitted : Bool) : Bool := unlocked && approved && stateCommitted
def canAcknowledge (authenticated stateCommitted : Bool) : Bool := authenticated && stateCommitted
def mayResumeSending (normalRecovery : Bool) (importedHistory : Bool) : Bool := normalRecovery && !importedHistory
def contactAllowed (state : UInt64) : Bool := state == 2
def initialSendAllowed (phase message validated : UInt64) : Bool :=
  phase != 0 || (message != 0 && message == validated)
def attachmentActionAllowed (rights action : UInt64) : Bool :=
  (rights &&& 1024) == 0 || action == 11 || action == 14 || action == 18 || action == 20 ||
    action == 23 || action == 24 || action == 25

theorem changed_fingerprint_denied (candidate current : UInt64) :
    canApprove candidate current false = false := by simp [canApprove]
theorem blocked_approval_denied (current : UInt64) (fingerprint : Bool) :
    canApprove 3 current fingerprint = false := by simp [canApprove]
theorem approved_identity_reselection : canApprove 2 1 true = true := by decide
theorem uncommitted_send_denied (unlocked approved : Bool) :
    canPublishSend unlocked approved false = false := by simp [canPublishSend]
theorem unauthenticated_receive_denied (committed : Bool) :
    canAcknowledge false committed = false := by simp [canAcknowledge]
theorem uncommitted_receive_denied (authenticated : Bool) :
    canAcknowledge authenticated false = false := by simp [canAcknowledge]
theorem history_restore_denies_sending (normal : Bool) :
    mayResumeSending normal true = false := by simp [mayResumeSending]
theorem blocked_contact_denied : contactAllowed 3 = false := by decide
theorem initial_send_without_claim_denied (message : UInt64) :
    initialSendAllowed 0 message 0 = false := by simp [initialSendAllowed]
theorem changed_claim_denied (message validated : UInt64) (different : (message == validated) = false) :
    initialSendAllowed 0 message validated = false := by simp [initialSendAllowed,different]

theorem network_cannot_decrypt_attachment : attachmentActionAllowed 1024 3 = false := by decide
theorem network_cannot_create_attachment : attachmentActionAllowed 1024 1 = false := by decide
theorem network_can_get_mailbox_capability : attachmentActionAllowed 1024 11 = true := by decide
end Guest.MessengerPolicy
