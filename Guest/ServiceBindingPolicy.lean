namespace Guest.ServiceBindingPolicy
-- Registry-v1 is local authority: role numbers are never caller authentication.
def roleValid (role : UInt64) : Bool := role > 0 && role <= 4
def operationValid (role operation : UInt64) : Bool :=
  operation > 0 && operation < 1024 && (role != 1 || (operation >= 400 && operation <= 409))
def serviceRightsValid (role rights : UInt64) : Bool := role != 1 || rights == 0
def currentGrant (caller target operation generation expectedCaller expectedTarget expectedOperation expectedGeneration : UInt64) : Bool :=
  generation != 0 && caller == expectedCaller && target == expectedTarget &&
  operation == expectedOperation && generation == expectedGeneration

theorem signer_has_no_package_rights (rights : UInt64) :
    serviceRightsValid 1 rights = true → rights = 0 := by
  simp [serviceRightsValid]
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
