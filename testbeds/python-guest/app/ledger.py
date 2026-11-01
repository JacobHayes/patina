ORIGIN = "app"


def settle(accounts):
    if accounts:
        raise RuntimeError(f"unsettled accounts: {sorted(accounts)}")
