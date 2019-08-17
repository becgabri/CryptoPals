modulus_GF28 = bytes([1, 27])
modulus_integer_GF28 = int.from_bytes(modulus_GF28, byteorder='big')
modulus_bit_length = modulus_integer_GF28.bit_length()

# Requires: num_a and num_b are integers
# Returns: integer response that is multiplication
# of num_a and num_b WITH NO CARRY
def xor_multiply_base_2(num_a, num_b):
    res = 0
    for mask in range(num_a.bit_length()):
        if (num_a & (1 << mask)):
            # xor with a also shifted out that far
            res = res ^ (num_b << mask)
    return res

# divide a by b and give back the quotient --- this is using the multiplication
# of xor_mult
def xor_divide_quot_base_2(num_a, num_b):
    quot = 0
    if num_a < num_b:
        return 0
    remainder = num_a ^ xor_multiply_base_2(num_b, quot)
    while (remainder >= num_b and remainder != 0):
        # increase the quotient
        quot = quot + 1
        remainder = num_a ^ xor_multiply_base_2(num_b, quot)
    return quot

# expect that num has an exponent of 8 or higher
# Expect: num is an integer that represents a polynomial with coefficients in
# Z_2
# Returned Value: an integer that represents a polynomial with coefficients in
# Z_2 where num < the modulus GF28
def mod_by_in_GF28(num):
    while (num >= (1 << 8)):
        highest_exp = num.bit_length() - modulus_bit_length
        num = num ^ (modulus_integer_GF28 << highest_exp)
    return num

def find_gcd(left_arg, right_arg, old_state):
    if right_arg == 0:
        return left_arg
    else:
        quotient = xor_divide_quot_base_2(left_arg, right_arg)
        rem = left_arg ^ xor_multiply_base_2(right_arg, quotient)

        new_s = old_state[0][0] ^ xor_multiply_base_2(quotient, old_state[1][0])
        new_t =  old_state[0][1] ^ xor_multiply_base_2(quotient, old_state[1][1])
        old_state[0] = old_state[1]
        old_state[1] = (new_s, new_t)
        return find_gcd(right_arg, rem, old_state)

def dot_prod_in_GF28(vect_a, vect_b):
    if len(vect_a) != len(vect_b):
        raise Error("Vector lengths with dot product are not the same.")
    res = GF28(0)
    for idx in range(len(vect_a)):
        add_to_sum = vect_a[idx] * vect_b[idx]
        res = add_to_sum + res
    if res.number >= 256:
        raise ValueError('multiplying_elt_in_GF28 lead to value larger than modulus')
    return res

class GF28:
    def __init__(self, initial=0, bypass_modcheck=False):
        if bypass_modcheck:
            self.number = initial
        else:
            self.number = initial if initial == 0 else mod_by_in_GF28(initial)

    def __equal__(self, other):
        if isinstance(other, GF28):
            return other.number == self.number

    def __add__(self, other):
        return GF28(self.number ^ other.number, bypass_modcheck=True)

    def __mul__(self, other):
        res = 0
        other_bit_length = other.number.bit_length()
        for mask in range(other_bit_length):
            if (other.number & (1 << mask)):
                # xor with a also shifted out that far
                res = res ^ mod_by_in_GF28(self.number << mask)
                #TODO this value should never be over the modulus -- check this
                """
                if (res >= (1 << (modulus_integer_GF28.bit_length() - 1))):
                    raise ValueError("Unexpected break from expectation: result in multiplication should never be over the modulus")
                    #res = res ^ modulus_integer_GF28
                """
        return GF28(res, bypass_modcheck=True)

    def __repr__(self):
        return str(self.number)

    def inverse(self):
        if self.number == 0:
            return GF28(0)
        state_block = [(1,0), (0,1)]
        find_gcd(modulus_integer_GF28, self.number, state_block)
        return GF28(state_block[0][1])

    # internally rotates the number so that bits are shifted
    # one to the left
    def rotate_bit(self):
        bit_carry = self.number & (1 << 7)
        new_value = (self.number & 0x7f) << 1

        if bit_carry:
            new_value = new_value | 1

        self.number = new_value

# Requires: a and b are both arrays of length 4 with GF28 elements
# Returns: the multiplication of a and b with result in GF28[x] / x^4 + 1
def multiply_polys(a,b):
    result_poly = [GF28(0)] * 4
    for it in len(a):
        for it2 in len(b):
            index_affected = it + it2 % 4
            result_poly[index_affected] = result_poly[index_affected] + (a[it] * b[it2])
    return result_poly
