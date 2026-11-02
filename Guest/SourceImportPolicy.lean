namespace Guest.SourceImportPolicy
-- One transaction still consumes the existing finite64-record arena. Public
-- graph consumers need the same node ceiling as publication/archive closure;
-- ordinary aggregate bytes and root ownership limits remain unchanged.
def accepts (privileged : Bool) (count nodes bytes length : UInt64) : Bool :=
  count > 0 && count <= 6 && nodes > 0 && nodes <= 64 && bytes <= 4194304 &&
    length == 64+count*128 &&
    (privileged || (count <= 4 && bytes <= 1048576))
end Guest.SourceImportPolicy
