from .atomic_swap_1 import AtomicSwapInterface


class NavSwapInterface(AtomicSwapInterface):
    """NAV (Navio) secret-hash HTLC swap.

    NAV uses the SELLER_FIRST secret-hash protocol with BLSCT-specific
    message exchanges on top. Behaviour currently matches the base
    AtomicSwapInterface; NAV-specific logic migrates here in later phases.
    """

    pass
