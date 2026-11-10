"""OpenSSL reads a config file, a provider directory and an engine directory from the
environment, and each can load a shared library into any process that links OpenSSL (Python's
ssl module, curl, git over https). That is code loading, the same class as LD_PRELOAD, so audit
flags these keys rather than only listing them."""
from hook_integrity_kit import manifest


def test_openssl_code_loading_keys_are_flagged():
    for key in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "openssl_conf"):
        assert manifest.is_exec_env(key), key


def test_openssl_keys_that_load_nothing_are_not_flagged():
    # CPU-capability masks and trace switches pick no file and load no code
    for key in ("OPENSSL_ia32cap", "OPENSSL_TRACE"):
        assert not manifest.is_exec_env(key), key
