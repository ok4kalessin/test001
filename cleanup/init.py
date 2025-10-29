import logging
import store
def main(timer):
    store.purge_old_nonces(keep_days=7)
    logging.info("nonce GC ran")

