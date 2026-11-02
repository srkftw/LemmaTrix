namespace Guest.NetworkGrantLease
-- A lease refresh carries forward a finite existing byte allowance. It cannot
-- refill an exhausted grant, change its contract, or migrate pending work.
def accepts (owned current idle : Bool) (budget used lifetime clock : UInt64) : Bool :=
  owned && current && idle && budget > used && lifetime > 0 &&
    lifetime <= 100000 && clock+lifetime > clock
end Guest.NetworkGrantLease
