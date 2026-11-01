namespace Guest.ServiceBindingPolicy
-- Registry-v1 is local authority: role numbers are never caller authentication.
def roleValid (role : UInt64) : Bool := role > 0 && role <= 4
def operationValid (role operation : UInt64) : Bool :=
  operation > 0 && operation < 1024 &&
  (role != 1 || (operation >= 400 && operation <= 409)) &&
  (role != 2 || (operation >= 420 && operation <= 435)) &&
  (role != 3 || operation == 440 || operation == 441) &&
  (role != 4 || (operation >= 460 && operation <= 464))
def serviceRightsValid (role rights : UInt64) : Bool :=
  ((role != 1 && role != 2) || rights == 0) &&
  (role != 3 || rights == 2048) && (role != 4 || rights == 1024)
def currentGrant (caller target operation generation expectedCaller expectedTarget expectedOperation expectedGeneration : UInt64) : Bool :=
  generation != 0 && caller == expectedCaller && target == expectedTarget &&
  operation == expectedOperation && generation == expectedGeneration

def builtInAsyncAllowed (caller service operation generation : UInt64) : Bool :=
  caller == 1 && service == 6 && operation >= 20 && operation <= 47 && generation == 0
def terminalRegistryRead (caller service operation generation : UInt64) : Bool :=
  caller == 6 && service != 0 && (operation == 6 || operation == 7) && generation == 0
def receiptConsumer (role rights : UInt64) : Bool := role == 3 && rights == 2048
theorem graphical_cannot_receive_receipt_authority : receiptConsumer 3 799 = false := by decide
theorem network_cannot_receive_receipt_authority : receiptConsumer 4 1024 = false := by decide
theorem terminal_cannot_admit (service generation : UInt64) : terminalRegistryRead 6 service 2 generation = false := by
  have denied : ((2 : UInt64) == 6 || (2 : UInt64) == 7) = false := by decide
  simp only [terminalRegistryRead, denied, Bool.and_false, Bool.false_and]
theorem terminal_cannot_sign (service generation : UInt64) : terminalRegistryRead 6 service 5 generation = false := by
  have denied : ((5 : UInt64) == 6 || (5 : UInt64) == 7) = false := by decide
  simp only [terminalRegistryRead, denied, Bool.and_false, Bool.false_and]
theorem ordinary_cannot_proxy_registry (service operation generation : UInt64) : terminalRegistryRead 7 service operation generation = false := by
  have denied : ((7 : UInt64) == 6) = false := by decide
  simp only [terminalRegistryRead, denied, Bool.false_and]
theorem ordinary_cannot_admit_builtin_crypto (service operation generation : UInt64) :
    builtInAsyncAllowed 7 service operation generation = false := by simp [builtInAsyncAllowed]
theorem builtin_bulk_not_async_management : builtInAsyncAllowed 1 6 3 0 = false := by decide

theorem signer_has_no_package_rights (rights : UInt64) :
    serviceRightsValid 1 rights = true → rights = 0 := by
  simp [serviceRightsValid]
theorem session_owner_has_no_package_rights (rights : UInt64) :
    serviceRightsValid 2 rights = true → rights = 0 := by
  simp [serviceRightsValid]
theorem session_owner_cannot_sign : operationValid 2 402 = false := by decide
theorem session_owner_cannot_use_mailbox : operationValid 2 441 = false := by decide
theorem mailbox_cannot_use_session : operationValid 3 426 = false := by decide
def entropyOwner (role rights : UInt64) : Bool :=
  (role == 1 || role == 2) && rights == 0
theorem network_service_not_entropy_owner : entropyOwner 2 1024 = false := by decide
theorem mailbox_not_entropy_owner (rights : UInt64) : entropyOwner 3 rights = false := by
  simp [entropyOwner]
theorem zero_generation_denied (caller target operation ec et eo eg : UInt64) :
    currentGrant caller target operation 0 ec et eo eg = false := by
  simp [currentGrant]
theorem wrong_incarnation_denied (caller target operation generation ec et eo eg : UInt64)
    (h : caller ≠ ec) : currentGrant caller target operation generation ec et eo eg = false := by
  simp [currentGrant, h]
theorem wrong_operation_denied (caller target operation generation ec et eo eg : UInt64)
    (h : operation ≠ eo) : currentGrant caller target operation generation ec et eo eg = false := by
  simp [currentGrant, h]
theorem revoked_generation_denied (caller target operation generation ec et eo eg : UInt64)
    (h : generation ≠ eg) : currentGrant caller target operation generation ec et eo eg = false := by
  simp [currentGrant, h]
end Guest.ServiceBindingPolicy
