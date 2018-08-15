#!/bin/usr/python3
#from CryptoPals7 import sub_bytes, inv_sub_bytes
import unittest
import os
import json
import GF28
import build_subtable
import CryptoPals7

class GFOperations(unittest.TestCase):
    def test_xor_multiplication(self):
        self.assertEqual(GF28.xor_multiply_base_2(3,3), 5)
    def test_xor_mult(self):
        self.assertEqual(GF28.xor_multiply_base_2(283, 1), 283)

    def test_xor_div_quot_no_rem(self):
        self.assertEqual(GF28.xor_divide_quot_base_2(10, 2),5)

    def test_xor_div_quot_rem(self):
        self.assertEqual(GF28.xor_divide_quot_base_2(11,3), 6)

    def test_xor_div_one_below(self):
        self.assertEqual(GF28.xor_divide_quot_base_2(283,1), 283)

    def test_xor_div_one(self):
        self.assertEqual(GF28.xor_divide_quot_base_2(11,11), 1)

    def test_mod_by(self):
        self.assertEqual(GF28.mod_by_in_GF28(1033), 101)

class GCDtests(unittest.TestCase):
    def test_gcd(self):
        value = GF28.GF28(1)
        self.assertEqual(value.inverse().number, 1)

    def test_gcd_inv(self):
        value = GF28.GF28(9)
        self.assertEqual(value.inverse().number, 79)

    def test_mult_GF28(self):
        elt_1 = GF28.GF28(37)
        elt_2 = GF28.GF28(10)
        self.assertEqual((elt_1 * elt_2).number, 121)

    def test_some_mult_GF28(self):
        elt_1 = GF28.GF28(9)
        elt_2 = GF28.GF28(3)
        self.assertEqual((elt_1 * elt_2).number, 27)

    def test_simple_add_GF28(self):
        elt_1 = GF28.GF28(3)
        elt_2 = GF28.GF28(2)
        self.assertEqual((elt_1 + elt_2).number, 1)

class Substests(unittest.TestCase):
    def setUp(self):
        def custom_equal(a,b,msg=None):
            if a.number != b.number:
                raise self.failureException(a.number + " != " + b.number)
            else:
                return True
        self.addTypeEqualityFunc(GF28.GF28, custom_equal)

    def test_all_zero(self):
        test1 = [GF28.GF28(0)] * 16
        solution = [GF28.GF28(99)] * 16
        CryptoPals7.sub_bytes(test1)
        for idx,item in enumerate(test1):
            self.assertEqual(test1[idx], solution[idx])
        #self.assertSequenceEqual(test1, solution, seq_type=GF28.GF28)

    def test_simple(self):
        test1 = [GF28.GF28(1), GF28.GF28(2), GF28.GF28(3), GF28.GF28(4)] * 4
        solution = [GF28.GF28(124), GF28.GF28(119), GF28.GF28(123), GF28.GF28(242)] * 4
        CryptoPals7.sub_bytes(test1)
        for idx,item in enumerate(test1):
            self.assertEqual(test1[idx], solution[idx])

    def test_simple_subs_inverse(self):
        test2 = [GF28.GF28(124), GF28.GF28(119), GF28.GF28(123), GF28.GF28(242)] * 4
        solution = [GF28.GF28(1),GF28.GF28(2),GF28.GF28(3),GF28.GF28(4)] * 4
        CryptoPals7.inv_sub_bytes(test2)
        for idx,item in enumerate(test2):
            self.assertEqual(test2[idx], solution[idx])

class ShiftRowTests(unittest.TestCase):
    def setUp(self):
        def custom_equal(a,b,msg=None):
            if a.number != b.number:
                raise self.failureException(a.number + " != " + b.number)
            else:
                return True
        self.addTypeEqualityFunc(GF28.GF28, custom_equal)

    def test_inv_row_shift(self):
        beg_state = [
            0,1,1,0,
            1,0,0,0,
            0,0,1,0,
            1,1,0,0
        ]

        end_state = [
            0,1,1,0,
            0,1,0,0,
            1,0,0,0,
            1,0,0,1
        ]
        for idx, value in enumerate(beg_state):
            beg_state[idx] = GF28.GF28(value)
        for idx, value in enumerate(end_state):
            end_state[idx] = GF28.GF28(value)
        new_state = CryptoPals7.inv_shift_rows(beg_state)
        for idx, val in enumerate(new_state):
            self.assertEqual(new_state[idx], end_state[idx])

    def test_row_shift(self):
        end_state = [
            0,1,1,0,
            1,0,0,0,
            0,0,1,0,
            1,1,0,0
        ]

        beg_state = [
            0,1,1,0,
            0,1,0,0,
            1,0,0,0,
            1,0,0,1
        ]

        for idx, value in enumerate(beg_state):
            beg_state[idx] = GF28.GF28(value)
        for idx, value in enumerate(end_state):
            end_state[idx] = GF28.GF28(value)
        new_state = CryptoPals7.shift_rows(beg_state)
        for idx, val in enumerate(new_state):
            self.assertEqual(new_state[idx], end_state[idx])

class MixedColsTests(unittest.TestCase):
    def setUp(self):
        def custom_equal(a,b,msg=None):
            if a.number != b.number:
                raise self.failureException(a.number + " != " + b.number)
            else:
                return True
        self.addTypeEqualityFunc(GF28.GF28, custom_equal)

    def test_mix_col_simple(self):
        beg_state = [
            1,0,0,1,
            1,0,0,0,
            0,0,0,0,
            0,0,0,0
        ]

        end_state = [
            1,0,0,2,
            3,0,0,1,
            0,0,0,1,
            2,0,0,3
        ]

        for idx, value in enumerate(beg_state):
            beg_state[idx] = GF28.GF28(value)
        for idx, value in enumerate(end_state):
            end_state[idx] = GF28.GF28(value)

        beg_state = CryptoPals7.mix_cols(beg_state)

        for idx, num in enumerate(beg_state):
            self.assertEqual(end_state[idx], beg_state[idx])

    def test_inv_mix_cols(self):
        end_state = [
            1,0,0,1,
            1,0,0,0,
            0,0,0,0,
            0,0,0,0
        ]

        beg_state = [
            1,0,0,2,
            3,0,0,1,
            0,0,0,1,
            2,0,0,3
        ]

        for idx, value in enumerate(beg_state):
            beg_state[idx] = GF28.GF28(value)
        for idx, value in enumerate(end_state):
            end_state[idx] = GF28.GF28(value)

        beg_state = CryptoPals7.inv_mix_cols(beg_state)

        for idx, num in enumerate(beg_state):
            self.assertEqual(end_state[idx], beg_state[idx])

    def test_wiki_mix_col(self):
        beg_state = [
            219, 242, 1, 198,
            19, 10, 1, 198,
            83, 34, 1, 198,
            69, 92, 1, 198
        ]
        end_state = [
            142, 159, 1, 198,
            77, 220, 1, 198,
            161, 88, 1, 198,
            188, 157, 1, 198
        ]
        for idx, value in enumerate(beg_state):
            beg_state[idx] = GF28.GF28(value)
        for idx, value in enumerate(end_state):
            end_state[idx] = GF28.GF28(value)

        beg_state = CryptoPals7.mix_cols(beg_state)

        for idx, num in enumerate(beg_state):
            self.assertEqual(end_state[idx], beg_state[idx])

class Bit128Test(unittest.TestCase):
    def test_zero_key(self):
        plaintext = 'Perseverance man'
        plaintext_in_GF28 = []
        for let in plaintext:
            plaintext_in_GF28.append(GF28.GF28(ord(let)))
        key = [GF28.GF28(0)] * 16
        cipher_text_GF28 = CryptoPals7.encrypt_aes(key, plaintext_in_GF28)
        res_dec = CryptoPals7.decrypt_aes(key, cipher_text_GF28)
        res_dec = CryptoPals7.GF28_to_string(res_dec)
        # TODO change to string at end or byte array (just not GF28)
        self.assertEqual(res_dec, plaintext)

    def test_non_zero_key(self):
        plaintext= 'Perseverance man'
        plaintext_in_GF28 = []
        for let in plaintext:
            plaintext_in_GF28.append(GF28.GF28(ord(let)))
        key = [GF28.GF28(3)] * 15
        key.append(GF28.GF28(4))
        cipher_text_GF28 = CryptoPals7.encrypt_aes(key, plaintext_in_GF28)
        res_dec = CryptoPals7.decrypt_aes(key, cipher_text_GF28)
        res_dec = CryptoPals7.GF28_to_string(res_dec)

        # TODO change to string at end or byte array (just not GF28)
        self.assertEqual(res_dec, plaintext)

    def test_aes_blocks(self):
        plaintext= "Apple has inklin" + "Perseverance man"
        key = [3] * 15
        key.append(4)
        key = bytearray(key)
        res = CryptoPals7.encryption_mode_ECB(key, plaintext, CryptoPals7.encrypt_aes)
        other_res = CryptoPals7.decryption_mode_ECB(key, res, CryptoPals7.decrypt_aes)
        self.assertEqual(other_res, plaintext)

class KeyExpandTest(unittest.TestCase):
    def setUp(self):
        def custom_equal(a,b,msg=None):
            if a.number != b.number:
                raise self.failureException(str(a.number) + " != " + str(b.number) + " at index ")
            else:
                return True
        self.addTypeEqualityFunc(GF28.GF28, custom_equal)

    def test_key_submarine(self):
        key = "YELLOW SUBMARINE"
        beginning_of_expanded_key = [
            89, 69, 76, 76,
            79, 87, 32, 83,
            85, 66, 77, 65,
            82, 73, 78, 69,
            99, 106, 34, 76,
            44, 61, 2, 31,
            121, 127, 79, 94,
            43, 54, 1, 27,
            100, 22, 141, 189
        ]
        exp_key_in_GF28 = []
        for idx, num in enumerate(beginning_of_expanded_key):
            exp_key_in_GF28.append(GF28.GF28(num))
        small_key = [GF28.GF28(ord(let)) for let in key]
        some_exp_key = CryptoPals7.key_expansion(small_key)
        for ind in range(len(beginning_of_expanded_key)):
            self.assertEqual(exp_key_in_GF28[ind], some_exp_key[ind])

class CBCTest(unittest.TestCase):
    def setUp(self):
        def custom_equal(a,b,msg=None):
            if a.number != b.number:
                raise self.failureException(str(a.number) + " != " + str(b.number) + " at index ")
            else:
                return True
        self.addTypeEqualityFunc(GF28.GF28, custom_equal)
    def test_CBC(self):
        key = 'Apple Apple. And'
        text = 'Perseverance manPerseverance man'
        IV = '0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0'
        ciphertext = CryptoPals7.ENCRYPTION_CBC_MODE(IV, key, text, CryptoPals7.encrypt_aes)
        plaintext = CryptoPals7.DECRYPTION_CBC_MODE(IV, key, ciphertext, CryptoPals7.decrypt_aes)
        # only checks the beginning
        for idx, let in enumerate(text):
            self.assertEqual(plaintext[idx], text[idx])


if __name__ == "__main__":
    unittest.main()
