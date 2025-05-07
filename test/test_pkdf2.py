import unittest

from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_Pbkdf2(self):
        # Generate a password key
        mechanism = PyKCS11.PKCS5_PBKD2_Mechanism(1024, "password", "1234")

        keyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_LABEL, "passwordKey")
        ]

        passwordKey = self.session.generateKey(keyTemplate, mechanism)
        self.session.destroyObject(passwordKey)
