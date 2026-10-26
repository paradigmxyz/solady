// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Arithmetic library with operations for fixed-point numbers.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol)
/// @dev The checked port returns what the assembly returns and reverts with the
/// same custom errors. Where the assembly wraps on purpose, as the approximations,
/// the 512-bit division and the modular inverse do, or relies on a bound that only
/// the algorithm proves, as the roots' Newton steps and the rounding additions do,
/// the port spells the step with the library's own `raw` operations, whose
/// unchecked bodies are its only trusted code. Every other step is checked.
/// The port has no inline assembly, including its zero-divisor and signed-overflow cases.
/// @custom:solar-safe memory arithmetic
library FixedPointMathLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The operation failed, as the output exceeds the maximum value of uint256.
    error ExpOverflow();

    /// @dev The operation failed, as the output exceeds the maximum value of uint256.
    error FactorialOverflow();

    /// @dev The operation failed, due to an overflow.
    error RPowOverflow();

    /// @dev The mantissa is too big to fit.
    error MantissaOverflow();

    /// @dev The operation failed, due to an multiplication overflow.
    error MulWadFailed();

    /// @dev The operation failed, due to an multiplication overflow.
    error SMulWadFailed();

    /// @dev The operation failed, either due to a multiplication overflow, or a division by a zero.
    error DivWadFailed();

    /// @dev The operation failed, either due to a multiplication overflow, or a division by a zero.
    error SDivWadFailed();

    /// @dev The operation failed, either due to a multiplication overflow, or a division by a zero.
    error MulDivFailed();

    /// @dev The division failed, as the denominator is zero.
    error DivFailed();

    /// @dev The full precision multiply-divide operation failed, either due
    /// to the result being larger than 256 bits, or a division by a zero.
    error FullMulDivFailed();

    /// @dev The output is undefined, as the input is less-than-or-equal to zero.
    error LnWadUndefined();

    /// @dev The input outside the acceptable domain.
    error OutOfDomain();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The scalar of ETH and most ERC20s.
    uint256 internal constant WAD = 1e18;

    /// @dev Selects a table slot from a byte value: shifted right by the byte
    /// and masked to five bits, it gives a distinct slot for each position the
    /// byte's highest set bit can have, and slot 30 for a zero byte.
    uint256 private constant _SELECTOR = 0x8421084210842108cc6318c6db6d54be;

    /// @dev The highest set bit's index within a byte, per selector slot.
    bytes32 private constant _HIGHEST =
        0x0706060506020504060203020504030106050205030304010505030400000000;

    /// @dev The same table complemented to 255, so that `255 - log2(x)` is the
    /// byte position exclusive-ored with the slot.
    bytes32 private constant _LEADING =
        0xf8f9f9faf9fdfafbf9fdfcfdfafbfcfef9fafdfafcfcfbfefafafcfbffffffff;

    /// @dev The divisors of `lambertW0Wad`'s first estimate, one per `log2(x)`
    /// from 49 to 62.
    bytes32 private constant _LAMBERT_DIVISORS =
        0x0303030303030303040506080c13000000000000000000000000000000000000;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              SIMPLIFIED FIXED POINT OPERATIONS             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `(x * y) / WAD` rounded down.
    function mulWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        // Equivalent to `require(y == 0 || x <= type(uint256).max / y)`.
        if (y != 0 && x > type(uint256).max / y) revert MulWadFailed();
        z = rawMul(x, y) / WAD;
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded down.
    /// The quotient rounds towards zero.
    function sMulWad(int256 x, int256 y) internal pure returns (int256 z) {
        z = rawMul(x, y);
        // Equivalent to `require((x == 0 || z / x == y) && !(x == -1 && y == type(int256).min))`.
        if (!((x == 0 || rawSDiv(z, x) == y) && !(x == -1 && y == type(int256).min))) {
            revert SMulWadFailed();
        }
        z = z / int256(WAD);
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded down, but without overflow checks.
    function rawMulWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawMul(x, y) / WAD;
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded down, but without overflow checks.
    /// The quotient rounds towards zero.
    function rawSMulWad(int256 x, int256 y) internal pure returns (int256 z) {
        z = rawMul(x, y) / int256(WAD);
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded up.
    function mulWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawMul(x, y);
        // Equivalent to `require(y == 0 || x <= type(uint256).max / y)`.
        if (y != 0 && z / y != x) revert MulWadFailed();
        z = z / WAD + (z % WAD == 0 ? 0 : 1);
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded up, but without overflow checks.
    function rawMulWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawMul(x, y);
        z = z / WAD + (z % WAD == 0 ? 0 : 1);
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded down.
    function divWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        // Equivalent to `require(y != 0 && x <= type(uint256).max / WAD)`.
        if (y == 0 || x > type(uint256).max / WAD) revert DivWadFailed();
        z = rawMul(x, WAD) / y;
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded down.
    /// The quotient rounds towards zero.
    function sDivWad(int256 x, int256 y) internal pure returns (int256 z) {
        z = rawMul(x, int256(WAD));
        // Equivalent to `require(y != 0 && ((x * WAD) / WAD == x))`.
        if (y == 0 || z / int256(WAD) != x) revert SDivWadFailed();
        z = rawSDiv(z, y);
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded down, but without overflow and divide by zero checks.
    function rawDivWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawDiv(rawMul(x, WAD), y);
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded down, but without overflow and divide by zero checks.
    /// The quotient rounds towards zero.
    function rawSDivWad(int256 x, int256 y) internal pure returns (int256 z) {
        z = rawSDiv(rawMul(x, int256(WAD)), y);
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded up.
    function divWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        // Equivalent to `require(y != 0 && x <= type(uint256).max / WAD)`.
        if (y == 0 || x > type(uint256).max / WAD) revert DivWadFailed();
        z = rawMul(x, WAD);
        // The quotient is below the maximum whenever `y` leaves a remainder.
        z = rawAdd(z / y, z % y == 0 ? 0 : 1);
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded up, but without overflow and divide by zero checks.
    function rawDivWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawMul(x, WAD);
        z = rawAdd(rawDiv(z, y), rawMod(z, y) == 0 ? 0 : 1);
    }

    /// @dev Equivalent to `x` to the power of `y`.
    /// because `x ** y = (e ** ln(x)) ** y = e ** (ln(x) * y)`.
    /// Note: This function is an approximation.
    function powWad(int256 x, int256 y) internal pure returns (int256) {
        // Using `ln(x)` means `x` must be greater than 0.
        return expWad((lnWad(x) * y) / int256(WAD));
    }

    /// @dev Returns `exp(x)`, denominated in `WAD`.
    /// Credit to Remco Bloemen under MIT license: https://2π.com/22/exp-ln
    /// Note: This function is an approximation. Monotonically increasing.
    function expWad(int256 x) internal pure returns (int256 r) {
        // When the result is less than 0.5 we return zero.
        // This happens when `x <= (log(1e-18) * 1e18) ~ -4.15e19`.
        if (x <= -41446531673892822313) return r;

        // When the result is greater than `(2**255 - 1) / 1e18` we can not represent it as
        // an int. This happens when `x >= floor(log((2**255 - 1) / 1e18) * 1e18) ≈ 135`.
        if (x >= 135305999368893231589) revert ExpOverflow();

        // `x` is now in the range `(-42, 136) * 1e18`. Convert to `(-42, 136) * 2**96`
        // for more intermediate precision and a binary basis. This base conversion
        // is a multiplication by 1e18 / 2**96 = 5**18 / 2**78.
        x = (x << 78) / 5 ** 18;

        // Reduce range of x to (-½ ln 2, ½ ln 2) * 2**96 by factoring out powers
        // of two such that exp(x) = exp(x') * 2**k, where k is an integer.
        // Solving this gives k = round(x / log(2)) and x' = x - k * log(2).
        int256 k = rawAdd((x << 96) / 54916777467707473351141471128, 2 ** 95) >> 96;
        x = rawSub(x, rawMul(k, 54916777467707473351141471128));

        // `k` is in the range `[-61, 195]`.

        // Evaluate using a (6, 7)-term rational approximation.
        // `p` is made monic, we'll multiply by a scale factor later.
        int256 y = rawAdd(x, 1346386616545796478920950773328);
        y = rawAdd(rawMul(y, x) >> 96, 57155421227552351082224309758442);
        int256 p = rawSub(rawAdd(y, x), 94201549194550492254356042504812);
        p = rawAdd(rawMul(p, y) >> 96, 28719021644029726153956944680412240);
        p = rawAdd(rawMul(p, x), 4385272521454847904659076985693276 << 96);

        // We leave `p` in `2**192` basis so we don't need to scale it back up for the division.
        int256 q = rawSub(x, 2855989394907223263936484059900);
        q = rawAdd(rawMul(q, x) >> 96, 50020603652535783019961831881945);
        q = rawSub(rawMul(q, x) >> 96, 533845033583426703283633433725380);
        q = rawAdd(rawMul(q, x) >> 96, 3604857256930695427073651918091429);
        q = rawSub(rawMul(q, x) >> 96, 14423608567350463180887372962807573);
        q = rawAdd(rawMul(q, x) >> 96, 26449188498355588339934803723976023);

        // The q polynomial won't have zeros in the domain as all its roots are complex.
        // No scaling is necessary because p is already `2**96` too large.
        r = rawSDiv(p, q);

        // r should be in the range `(0.09, 0.25) * 2**96`.

        // We now need to multiply r by:
        // - The scale factor `s ≈ 6.031367120`.
        // - The `2**k` factor from the range reduction.
        // - The `1e18 / 2**96` factor for base conversion.
        // We do this all at once, with an intermediate result in `2**213`
        // basis, so the final right shift is always by a positive amount.
        r = int256(
            rawMul(uint256(r), 3822833074963236453042738258902158003155416615667)
                >> uint256(rawSub(195, k))
        );
    }

    /// @dev Returns `ln(x)`, denominated in `WAD`.
    /// Credit to Remco Bloemen under MIT license: https://2π.com/22/exp-ln
    /// Note: This function is an approximation. Monotonically increasing.
    function lnWad(int256 x) internal pure returns (int256 r) {
        // We want to convert `x` from `10**18` fixed point to `2**96` fixed point.
        // We do this by multiplying by `2**96 / 10**18`. But since
        // `ln(x * C) = ln(x) + ln(C)`, we can simply do nothing here
        // and add `ln(2**96 / 10**18)` at the end.

        // Compute `k = log2(x) - 96`, `s = 159 - k = 255 - log2(x) = 255 ^ log2(x)`.
        uint256 s = _msbByte(uint256(x));
        if (x <= 0) revert LnWadUndefined();
        s ^= uint8(_LEADING[(_SELECTOR >> (uint256(x) >> s)) & 31]);

        // Reduce range of x to (1, 2) * 2**96
        // ln(2^k * x) = k * ln(2) + ln(x)
        x = int256((uint256(x) << s) >> 159);

        // Evaluate using a (8, 8)-term rational approximation.
        // `p` is made monic, we will multiply by a scale factor later.
        int256 p = rawAdd(3273285459638523848632254066296, x);
        p = rawAdd(24828157081833163892658089445524, rawMul(p, x) >> 96);
        p = rawAdd(43456485725739037958740375743393, rawMul(p, x) >> 96);
        p = rawSub(rawMul(p, x) >> 96, 11111509109440967052023855526967);
        p = rawSub(rawMul(p, x) >> 96, 45023709667254063763336534515857);
        p = rawSub(rawMul(p, x) >> 96, 14706773417378608786704636184526);
        p = rawSub(rawMul(p, x), 795164235651350426258249787498 << 96);
        // We leave `p` in `2**192` basis so we don't need to scale it back up for the division.

        // `q` is monic by convention.
        int256 q = rawAdd(5573035233440673466300451813936, x);
        q = rawAdd(71694874799317883764090561454958, rawMul(x, q) >> 96);
        q = rawAdd(283447036172924575727196451306956, rawMul(x, q) >> 96);
        q = rawAdd(401686690394027663651624208769553, rawMul(x, q) >> 96);
        q = rawAdd(204048457590392012362485061816622, rawMul(x, q) >> 96);
        q = rawAdd(31853899698501571402653359427138, rawMul(x, q) >> 96);
        q = rawAdd(909429971244387300277376558375, rawMul(x, q) >> 96);

        // `p / q` is in the range `(0, 0.125) * 2**96`.

        // Finalization, we need to:
        // - Multiply by the scale factor `s = 5.549…`.
        // - Add `ln(2**96 / 10**18)`.
        // - Add `k * ln(2)`.
        // - Multiply by `10**18 / 2**96 = 5**18 >> 78`.

        // The q polynomial is known not to have zeros in the domain.
        // No scaling required because p is already `2**96` too large.
        p = rawSDiv(p, q);
        // Multiply by the scaling factor: `s * 5**18 * 2**96`, base is now `5**18 * 2**192`.
        p = rawMul(1677202110996718588342820967067443963516166, p);
        // Add `ln(2) * k * 5**18 * 2**192`.
        // forgefmt: disable-next-item
        p = rawAdd(rawMul(16597577552685614221487285958193947469193820559219878177908093499208371,
            rawSub(159, int256(s))), p);
        // Add `ln(2**96 / 10**18) * 5**18 * 2**192`.
        p = rawAdd(600920179829731861736702779321621459595472258049074101567377883020018308, p);
        // Base conversion: mul `2**18 / 2**192`.
        r = p >> 174;
    }

    /// @dev Returns `W_0(x)`, denominated in `WAD`.
    /// See: https://en.wikipedia.org/wiki/Lambert_W_function
    /// a.k.a. Product log function. This is an approximation of the principal branch.
    /// Note: This function is an approximation. Monotonically increasing.
    function lambertW0Wad(int256 x) internal pure returns (int256 w) {
        if ((w = x) <= -367879441171442322) revert OutOfDomain(); // `x` less than `-1/e`.
        int256 p = x;
        uint256 c; // Whether we need to avoid catastrophic cancellation.
        uint256 i = 4; // Number of iterations.
        if (w <= 0x1ffffffffffff) {
            if (-0x4000000000000 <= w) {
                i = 1; // Inputs near zero only take one step to converge.
            } else if (w <= -0x3ffffffffffffff) {
                i = 32; // Inputs near `-1/e` take very long to converge.
            }
        } else if (w >> 63 == 0) {
            // Inline log2 for more performance, since the range is small.
            uint256 v = uint256(w) >> 49;
            uint256 l = v > 0xff ? 8 : 0;
            l = (l | uint8(_HIGHEST[(_SELECTOR >> (v >> l)) & 31])) + 49;
            w = int256(rawDiv(uint256(7) << l, uint8(_LAMBERT_DIVISORS[l - 49])));
            c = l > 60 ? 1 : 0;
            i = 2 + (l > 53 ? 1 : 0) + c;
        } else {
            int256 ll = lnWad(w = lnWad(w));
            // `w = ln(x) - ln(ln(x)) + b * ln(ln(x)) / ln(x)`.
            w = rawAdd(rawSDiv(rawMul(ll, 1023715080943847266), w), rawSub(w, ll));
            i = 3 + (x >> 68 == 0 ? 1 : 0);
            c = x >> 143 == 0 ? 1 : 0;
            if (c == 0) {
                do {
                    // If `x` is big, use Newton's so that intermediate values won't overflow.
                    int256 e = expWad(w);
                    int256 t = rawMul(w, int256(uint256(e) / WAD));
                    w = rawSub(w, rawSDiv(rawSub(t, x), int256(uint256(rawAdd(e, t)) / WAD)));
                    if (p <= w) break;
                    p = w;
                } while (--i != 0);
                return rawSub(w, w > 2 ? int256(1) : int256(0));
            }
        }
        do {
            // Otherwise, use Halley's for faster convergence.
            int256 e = expWad(w);
            int256 t = rawAdd(w, int256(WAD));
            int256 s = rawSub(rawMul(w, e), rawMul(x, int256(WAD)));
            // `e` becomes the step's denominator: a new local overflows the legacy stack.
            e = rawSub(rawMul(e, t), rawSDiv(rawMul(rawAdd(t, int256(WAD)), s), rawAdd(t, t)));
            w = rawSub(w, rawSDiv(rawMul(s, int256(WAD)), e));
            if (p <= w) break;
            p = w;
        } while (--i != c);
        w = rawSub(w, w > 2 ? int256(1) : int256(0));
        // For certain ranges of `x`, we'll use the quadratic-rate recursive formula of
        // R. Iacono and J.P. Boyd for the last iteration, to avoid catastrophic cancellation.
        if (c == 0) return w;
        int256 u = w | 1;
        x = rawSDiv(rawMul(x, int256(WAD)), u);
        x = rawMul(u, rawAdd(int256(WAD), lnWad(x)));
        w = rawSDiv(x, rawAdd(int256(WAD), u));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  GENERAL NUMBER UTILITIES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `a * b == x * y`, with full precision.
    function fullMulEq(uint256 a, uint256 b, uint256 x, uint256 y)
        internal
        pure
        returns (bool result)
    {
        result = rawMul(a, b) == rawMul(x, y)
            && mulmod(x, y, type(uint256).max) == mulmod(a, b, type(uint256).max);
    }

    /// @dev Calculates `floor(x * y / d)` with full precision.
    /// Throws if result overflows a uint256 or when `d` is zero.
    /// Credit to Remco Bloemen under MIT license: https://2π.com/21/muldiv
    function fullMulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        // 512-bit multiply `[p1 p0] = x * y`.
        // Compute the product mod `2**256` and mod `2**256 - 1`
        // then use the Chinese Remainder Theorem to reconstruct
        // the 512 bit result. The result is stored in two 256
        // variables such that `product = p1 * 2**256 + p0`.

        // Temporarily use `z` as `p0` to save gas.
        z = rawMul(x, y); // Lower 256 bits of `x * y`.
        // If it does not overflow.
        if ((x == 0 || rawDiv(z, x) == y) && d != 0) return z / d;
        uint256 mm = mulmod(x, y, type(uint256).max);
        uint256 p1 = rawSub(mm, rawAdd(z, mm < z ? 1 : 0)); // Upper 256 bits of `x * y`.

        /*------------------- 512 by 256 division --------------------*/

        // Make sure `z` is less than `2**256`. Also prevents `d == 0`.
        if (d <= p1) revert FullMulDivFailed();
        // Make division exact by subtracting the remainder from `[p1 p0]`.
        uint256 r = mulmod(x, y, d); // Compute remainder using mulmod.
        uint256 t = d & rawSub(0, d); // The least significant bit of `d`. `t >= 1`.
        d = rawDiv(d, t); // Divide `d` by `t`, which is a power of two.
        // Invert `d mod 2**256`
        // Now that `d` is an odd number, it has an inverse
        // modulo `2**256` such that `d * inv = 1 mod 2**256`.
        // Compute the inverse by starting with a seed that is
        // correct for four bits. That is, `d * inv = 1 mod 2**4`.
        uint256 inv = 2 ^ rawMul(3, d);
        // Now use Newton-Raphson iteration to improve the precision.
        // Thanks to Hensel's lifting lemma, this also works in modular
        // arithmetic, doubling the correct bits in each step.
        inv = rawMul(inv, rawSub(2, rawMul(d, inv))); // inverse mod 2**8
        inv = rawMul(inv, rawSub(2, rawMul(d, inv))); // inverse mod 2**16
        inv = rawMul(inv, rawSub(2, rawMul(d, inv))); // inverse mod 2**32
        inv = rawMul(inv, rawSub(2, rawMul(d, inv))); // inverse mod 2**64
        inv = rawMul(inv, rawSub(2, rawMul(d, inv))); // inverse mod 2**128
        z = rawMul(
            // Divide [p1 p0] by the factors of two.
            // Shift in bits from `p1` into `p0`. For this we need
            // to flip `t` such that it is `2**256 / t`.
            rawMul(rawSub(p1, r > z ? 1 : 0), rawAdd(rawDiv(rawSub(0, t), t), 1))
                | rawDiv(rawSub(z, r), t),
            rawMul(rawSub(2, rawMul(d, inv)), inv) // inverse mod 2**256
        );
    }

    /// @dev Calculates `floor(x * y / d)` with full precision.
    /// Behavior is undefined if `d` is zero or the final result cannot fit in 256 bits.
    /// Performs the full 512 bit calculation regardless.
    /// @custom:solar-inline
    function fullMulDivUnchecked(uint256 x, uint256 y, uint256 d)
        internal
        pure
        returns (uint256 z)
    {
        z = rawMul(x, y);
        uint256 mm = mulmod(x, y, type(uint256).max);
        uint256 p1 = rawSub(mm, rawAdd(z, mm < z ? 1 : 0));
        uint256 t = d & rawSub(0, d);
        uint256 r = rawMulMod(x, y, d);
        d = rawDiv(d, t);
        uint256 inv = 2 ^ rawMul(3, d);
        inv = rawMul(inv, rawSub(2, rawMul(d, inv)));
        inv = rawMul(inv, rawSub(2, rawMul(d, inv)));
        inv = rawMul(inv, rawSub(2, rawMul(d, inv)));
        inv = rawMul(inv, rawSub(2, rawMul(d, inv)));
        inv = rawMul(inv, rawSub(2, rawMul(d, inv)));
        z = rawMul(
            rawMul(rawSub(p1, r > z ? 1 : 0), rawAdd(rawDiv(rawSub(0, t), t), 1))
                | rawDiv(rawSub(z, r), t),
            rawMul(rawSub(2, rawMul(d, inv)), inv)
        );
    }

    /// @dev Calculates `floor(x * y / d)` with full precision, rounded up.
    /// Throws if result overflows a uint256 or when `d` is zero.
    /// Credit to Uniswap-v3-core under MIT license:
    /// https://github.com/Uniswap/v3-core/blob/main/contracts/libraries/FullMath.sol
    function fullMulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        z = fullMulDiv(x, y, d);
        if (mulmod(x, y, d) != 0) {
            if (z == type(uint256).max) revert FullMulDivFailed();
            ++z;
        }
    }

    /// @dev Calculates `floor(x * y / 2 ** n)` with full precision.
    /// Throws if result overflows a uint256.
    /// Credit to Philogy under MIT license:
    /// https://github.com/SorellaLabs/angstrom/blob/main/contracts/src/libraries/X128MathLib.sol
    function fullMulDivN(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 z) {
        // Temporarily use `z` as `p0` to save gas.
        z = rawMul(x, y); // Lower 256 bits of `x * y`. We'll call this `z`.
        if (x == 0 || rawDiv(z, x) == y) return z >> n;
        uint256 mm = mulmod(x, y, type(uint256).max);
        uint256 p1 = rawSub(mm, rawAdd(z, mm < z ? 1 : 0)); // Upper 256 bits of `x * y`.
        //         |      p1     |      z     |
        // Before: | p1_0 ¦ p1_1 | z_0  ¦ z_1 |
        // Final:  |   0  ¦ p1_0 | p1_1 ¦ z_0 |
        // Check that final `z` doesn't overflow by checking that p1_0 = 0.
        if (p1 >> n != 0) revert FullMulDivFailed();
        z = (p1 << (256 - uint256(n))) | (z >> n);
    }

    /// @dev Returns `floor(x * y / d)`.
    /// Reverts if `x * y` overflows, or `d` is zero.
    function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        z = rawMul(x, y);
        // Equivalent to `require(d != 0 && (y == 0 || x <= type(uint256).max / y))`.
        if (!((x == 0 || rawDiv(z, x) == y) && d != 0)) revert MulDivFailed();
        z = z / d;
    }

    /// @dev Returns `ceil(x * y / d)`.
    /// Reverts if `x * y` overflows, or `d` is zero.
    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        z = rawMul(x, y);
        // Equivalent to `require(d != 0 && (y == 0 || x <= type(uint256).max / y))`.
        if (!((x == 0 || rawDiv(z, x) == y) && d != 0)) revert MulDivFailed();
        // The quotient is below the maximum whenever `d` leaves a remainder.
        z = rawAdd(z / d, z % d == 0 ? 0 : 1);
    }

    /// @dev Returns `x`, the modular multiplicative inverse of `a`, such that `(a * x) % n == 1`.
    function invMod(uint256 a, uint256 n) internal pure returns (uint256 x) {
        // The extended Euclidean algorithm, whose second coefficient wraps.
        uint256 g = n;
        uint256 r = rawMod(a, n);
        uint256 y = 1;
        do {
            uint256 q = rawDiv(g, r);
            uint256 t = g;
            g = r;
            r = rawSub(t, rawMul(r, q));
            uint256 u = x;
            x = y;
            y = rawSub(u, rawMul(y, q));
        } while (r != 0);
        if (g != 1) return 0;
        x = rawAdd(x, int256(x) < 0 ? n : 0);
    }

    /// @dev Returns `ceil(x / d)`.
    /// Reverts if `d` is zero.
    function divUp(uint256 x, uint256 d) internal pure returns (uint256 z) {
        if (d == 0) revert DivFailed();
        // The quotient is below the maximum whenever `d` leaves a remainder.
        z = rawAdd(x / d, x % d == 0 ? 0 : 1);
    }

    /// @dev Returns `max(0, x - y)`. Alias for `saturatingSub`.
    function zeroFloorSub(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x > y ? x - y : 0;
    }

    /// @dev Returns `max(0, x - y)`.
    function saturatingSub(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x > y ? x - y : 0;
    }

    /// @dev Returns `min(2 ** 256 - 1, x + y)`.
    function saturatingAdd(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawAdd(x, y);
        if (z < x) z = type(uint256).max;
    }

    /// @dev Returns `min(2 ** 256 - 1, x * y)`.
    function saturatingMul(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = rawMul(x, y);
        if (!(x == 0 || rawDiv(z, x) == y)) z = type(uint256).max;
    }

    /// @dev Returns `condition ? x : y`, without branching.
    function ternary(bool condition, uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = condition ? x : y;
    }

    /// @dev Returns `condition ? x : y`, without branching.
    function ternary(bool condition, bytes32 x, bytes32 y) internal pure returns (bytes32 z) {
        z = condition ? x : y;
    }

    /// @dev Returns `condition ? x : y`, without branching.
    function ternary(bool condition, address x, address y) internal pure returns (address z) {
        z = condition ? x : y;
    }

    /// @dev Returns `x != 0 ? x : y`, without branching.
    function coalesce(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x != 0 ? x : y;
    }

    /// @dev Returns `x != bytes32(0) ? x : y`, without branching.
    function coalesce(bytes32 x, bytes32 y) internal pure returns (bytes32 z) {
        z = x != bytes32(0) ? x : y;
    }

    /// @dev Returns `x != address(0) ? x : y`, without branching.
    function coalesce(address x, address y) internal pure returns (address z) {
        z = x != address(0) ? x : y;
    }

    /// @dev Exponentiate `x` to `y` by squaring, denominated in base `b`.
    /// Reverts if the computation overflows.
    function rpow(uint256 x, uint256 y, uint256 b) internal pure returns (uint256 z) {
        z = y == 0 ? b : 0; // `0 ** 0 = 1`. Otherwise, `0 ** n = 0`.
        if (x != 0) {
            z = y & 1 == 0 ? b : x; // `z = isEven(y) ? scale : x`
            uint256 half = b >> 1; // Divide `b` by 2.
            // Divide `y` by 2 every iteration.
            for (y >>= 1; y != 0; y >>= 1) {
                uint256 xx = rawMul(x, x); // Store x squared.
                uint256 xxRound = rawAdd(xx, half); // Round to the nearest number.
                // Revert if `xx + half` overflowed, or if `x ** 2` overflows.
                if (xxRound < xx || x >> 128 != 0) revert RPowOverflow();
                x = rawDiv(xxRound, b); // Set `x` to scaled `xxRound`.
                // If `y` is odd:
                if (y & 1 != 0) {
                    uint256 zx = rawMul(z, x); // Compute `z * x`.
                    uint256 zxRound = rawAdd(zx, half); // Round to the nearest number.
                    // If `z * x` overflowed or `zx + half` overflowed, revert if `x` is non-zero.
                    if ((rawDiv(zx, x) != z || zxRound < zx) && x != 0) revert RPowOverflow();
                    z = rawDiv(zxRound, b); // Return properly scaled `zxRound`.
                }
            }
        }
    }

    /// @dev Returns the square root of `x`, rounded down.
    /// @custom:solar-inline
    function sqrt(uint256 x) internal pure returns (uint256 z) {
        // `floor(sqrt(2**15)) = 181`. `sqrt(2**15) - 181 = 2.84`.
        z = 181; // The "correct" value is 1, but this saves a multiplication later.

        // This segment is to get a reasonable initial estimate for the Babylonian method. With a bad
        // start, the correct # of bits increases ~linearly each iteration instead of ~quadratically.

        // Let `y = x / 2**r`. We check `y >= 2**(k + 8)`
        // but shift right by `k` bits to ensure that if `x >= 256`, then `y >= 256`.
        uint256 r = x > 0xffffffffffffffffffffffffffffffffff ? 128 : 0;
        r |= (x >> r) > 0xffffffffffffffffff ? 64 : 0;
        r |= (x >> r) > 0xffffffffff ? 32 : 0;
        r |= (x >> r) > 0xffffff ? 16 : 0;
        z <<= r >> 1;

        // Goal was to get `z*z*y` within a small factor of `x`. More iterations could
        // get y in a tighter range. Currently, we will have y in `[256, 256*(2**16))`.
        // We ensured `y >= 256` so that the relative difference between `y` and `y+1` is small.
        // That's not possible if `x < 256` but we can just verify those cases exhaustively.

        // Now, `z*z*y <= x < z*z*(y+1)`, and `y <= 2**(16+8)`, and either `y >= 256`, or `x < 256`.
        // Correctness can be checked exhaustively for `x < 256`, so we assume `y >= 256`.
        // Then `z*sqrt(y)` is within `sqrt(257)/sqrt(256)` of `sqrt(x)`, or about 20bps.

        // For `s` in the range `[1/256, 256]`, the estimate `f(s) = (181/1024) * (s+1)`
        // is in the range `(1/2.84 * sqrt(s), 2.84 * sqrt(s))`,
        // with largest error when `s = 1` and when `s = 256` or `1/256`.

        // Since `y` is in `[256, 256*(2**16))`, let `a = y/65536`, so that `a` is in `[1/256, 256)`.
        // Then we can estimate `sqrt(y)` using
        // `sqrt(65536) * 181/1024 * (a + 1) = 181/4 * (y + 65536)/65536 = 181 * (y + 65536)/2**18`.

        // There is no overflow risk here since `y < 2**136` after the first branch above.
        z = rawMul(z, rawAdd(x >> r, 65536)) >> 18; // A `mul()` is saved from starting `z` at 181.

        // Given the worst case multiplicative error of 2.84 above, 7 iterations should be enough.
        // An estimate can reach zero when `x` is small, and a division by zero is zero.
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;
        z = rawAdd(z, rawDiv(x, z)) >> 1;

        // If `x+1` is a perfect square, the Babylonian method cycles between
        // `floor(sqrt(x))` and `ceil(sqrt(x))`. This statement ensures we return floor.
        // See: https://en.wikipedia.org/wiki/Integer_square_root#Using_only_integer_division
        z = rawSub(z, rawDiv(x, z) < z ? 1 : 0);
    }

    /// @dev Returns the cube root of `x`, rounded down.
    /// Credit to bout3fiddy and pcaversaccio under AGPLv3 license:
    /// https://github.com/pcaversaccio/snekmate/blob/main/src/snekmate/utils/math.vy
    /// Formally verified by xuwinnie:
    /// https://github.com/vectorized/solady/blob/main/audits/xuwinnie-solady-cbrt-proof.pdf
    /// @custom:solar-inline
    function cbrt(uint256 x) internal pure returns (uint256 z) {
        uint256 r = _msbByte(x);
        // Makeshift lookup table to nudge the approximate log2 result.
        z = rawDiv((uint256(0xf) << ((x >> r) > 0xf ? 1 : 0)) << (r / 3), 7 ^ (r % 3));
        // Newton-Raphson's.
        // An estimate can reach zero when `x` is small, and a division by zero is zero.
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        z = rawAdd(rawAdd(rawDiv(x, rawMul(z, z)), z), z) / 3;
        // Round down.
        z = rawSub(z, rawDiv(x, rawMul(z, z)) < z ? 1 : 0);
    }

    /// @dev Returns the square root of `x`, denominated in `WAD`, rounded down.
    function sqrtWad(uint256 x) internal pure returns (uint256 z) {
        if (x <= type(uint256).max / 10 ** 18) return sqrt(x * 10 ** 18);
        z = rawMul(rawAdd(1, sqrt(x)), 10 ** 9);
        z = rawAdd(fullMulDivUnchecked(x, 10 ** 18, z), z) >> 1;
        // Round down.
        z = rawSub(z, 999999999999999999 > rawSub(mulmod(z, z, x), 1) ? 1 : 0);
    }

    /// @dev Returns the cube root of `x`, denominated in `WAD`, rounded down.
    /// Formally verified by xuwinnie:
    /// https://github.com/vectorized/solady/blob/main/audits/xuwinnie-solady-cbrt-proof.pdf
    function cbrtWad(uint256 x) internal pure returns (uint256 z) {
        if (x <= type(uint256).max / 10 ** 36) return cbrt(x * 10 ** 36);
        z = rawMul(rawAdd(1, cbrt(x)), 10 ** 12);
        z = rawAdd(rawAdd(fullMulDivUnchecked(x, 10 ** 36, rawMul(z, z)), z), z) / 3;
        uint256 p = x;
        if (p >> 229 == 0) {
            if (p >> 199 == 0) p *= 10 ** 17;
            else p *= 10 ** 8;
        } else if (p >> 249 == 0) {
            p *= 100;
        }
        uint256 t = mulmod(rawMul(z, z), z, p);
        z = rawSub(z, (t < (p >> 1) ? 1 : 0) & (t != 0 ? 1 : 0)); // Round down.
    }

    /// @dev Returns `sqrt(x * y)`. Also called the geometric mean.
    function mulSqrt(uint256 x, uint256 y) internal pure returns (uint256 z) {
        if (x == y) return x;
        uint256 p = rawMul(x, y);
        if (y == rawDiv(p, x)) return sqrt(p);
        for (z = saturatingMul(rawAdd(sqrt(x), 1), rawAdd(sqrt(y), 1));; z = avg(z, p)) {
            if ((p = fullMulDivUnchecked(x, y, z)) >= z) break;
        }
    }

    /// @dev Returns the factorial of `x`.
    function factorial(uint256 x) internal pure returns (uint256 z) {
        if (x >= 58) revert FactorialOverflow();
        // `57!` is below `2**256`.
        for (z = 1; x != 0; --x) {
            z = rawMul(z, x);
        }
    }

    /// @dev Returns the log2 of `x`.
    /// Equivalent to computing the index of the most significant bit (MSB) of `x`.
    /// Returns 0 if `x` is zero.
    function log2(uint256 x) internal pure returns (uint256 r) {
        r = _msbByte(x);
        r |= uint8(_HIGHEST[(_SELECTOR >> (x >> r)) & 31]);
    }

    /// @dev Returns the log2 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log2Up(uint256 x) internal pure returns (uint256 r) {
        r = log2(x);
        // `r` is at most 255.
        r = rawAdd(r, uint256(1) << r < x ? 1 : 0);
    }

    /// @dev Returns the log10 of `x`.
    /// Returns 0 if `x` is zero.
    function log10(uint256 x) internal pure returns (uint256 r) {
        if (x >= 100000000000000000000000000000000000000) {
            x /= 100000000000000000000000000000000000000;
            r = 38;
        }
        if (x >= 100000000000000000000) {
            x /= 100000000000000000000;
            r += 20;
        }
        if (x >= 10000000000) {
            x /= 10000000000;
            r += 10;
        }
        if (x >= 100000) {
            x /= 100000;
            r += 5;
        }
        r += (x > 9 ? 1 : 0) + (x > 99 ? 1 : 0) + (x > 999 ? 1 : 0) + (x > 9999 ? 1 : 0);
    }

    /// @dev Returns the log10 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log10Up(uint256 x) internal pure returns (uint256 r) {
        r = log10(x);
        // `r` is at most 77, so the power fits.
        r = rawAdd(r, 10 ** r < x ? 1 : 0);
    }

    /// @dev Returns the log256 of `x`.
    /// Returns 0 if `x` is zero.
    function log256(uint256 x) internal pure returns (uint256 r) {
        r = x > type(uint128).max ? 128 : 0;
        r |= (x >> r) > type(uint64).max ? 64 : 0;
        r |= (x >> r) > type(uint32).max ? 32 : 0;
        r |= (x >> r) > type(uint16).max ? 16 : 0;
        r = (r >> 3) | ((x >> r) > type(uint8).max ? 1 : 0);
    }

    /// @dev Returns the log256 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log256Up(uint256 x) internal pure returns (uint256 r) {
        r = log256(x);
        // `r` is at most 31.
        r = rawAdd(r, uint256(1) << (r << 3) < x ? 1 : 0);
    }

    /// @dev Returns the scientific notation format `mantissa * 10 ** exponent` of `x`.
    /// Useful for compressing prices (e.g. using 25 bit mantissa and 7 bit exponent).
    function sci(uint256 x) internal pure returns (uint256 mantissa, uint256 exponent) {
        mantissa = x;
        if (mantissa != 0) {
            if (mantissa % 1000000000000000000000000000000000 == 0) {
                mantissa /= 1000000000000000000000000000000000;
                exponent = 33;
            }
            if (mantissa % 10000000000000000000 == 0) {
                mantissa /= 10000000000000000000;
                exponent += 19;
            }
            if (mantissa % 1000000000000 == 0) {
                mantissa /= 1000000000000;
                exponent += 12;
            }
            if (mantissa % 1000000 == 0) {
                mantissa /= 1000000;
                exponent += 6;
            }
            if (mantissa % 10000 == 0) {
                mantissa /= 10000;
                exponent += 4;
            }
            if (mantissa % 100 == 0) {
                mantissa /= 100;
                exponent += 2;
            }
            if (mantissa % 10 == 0) {
                mantissa /= 10;
                exponent += 1;
            }
        }
    }

    /// @dev Convenience function for packing `x` into a smaller number using `sci`.
    /// The `mantissa` will be in bits [7..255] (the upper 249 bits).
    /// The `exponent` will be in bits [0..6] (the lower 7 bits).
    /// Use `SafeCastLib` to safely ensure that the `packed` number is small
    /// enough to fit in the desired unsigned integer type:
    /// ```
    ///     uint32 packed = SafeCastLib.toUint32(FixedPointMathLib.packSci(777 ether));
    /// ```
    function packSci(uint256 x) internal pure returns (uint256 packed) {
        (x, packed) = sci(x); // Reuse for `mantissa` and `exponent`.
        if (x >> 249 != 0) revert MantissaOverflow();
        packed |= x << 7;
    }

    /// @dev Convenience function for unpacking a packed number from `packSci`.
    function unpackSci(uint256 packed) internal pure returns (uint256 unpacked) {
        // Like the assembly, both the power and the product wrap.
        unpacked = rawMul(packed >> 7, _rawExp(10, packed & 0x7f));
    }

    /// @dev Returns the average of `x` and `y`. Rounds towards zero.
    function avg(uint256 x, uint256 y) internal pure returns (uint256 z) {
        // The sum is `floor((x + y) / 2)`, which fits.
        z = rawAdd(x & y, (x ^ y) >> 1);
    }

    /// @dev Returns the average of `x` and `y`. Rounds towards negative infinity.
    function avg(int256 x, int256 y) internal pure returns (int256 z) {
        // The sum is `floor((x + y) / 2)`, which fits.
        z = rawAdd(rawAdd(x >> 1, y >> 1), x & y & 1);
    }

    /// @dev Returns the absolute value of `x`.
    function abs(int256 x) internal pure returns (uint256 z) {
        // A negative `x` is complemented and incremented, which only wraps for the minimum.
        uint256 m = uint256(x >> 255);
        z = rawAdd(uint256(x), m) ^ m;
    }

    /// @dev Returns the absolute distance between `x` and `y`.
    function dist(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x > y ? x - y : y - x;
    }

    /// @dev Returns the absolute distance between `x` and `y`.
    function dist(int256 x, int256 y) internal pure returns (uint256 z) {
        // The distance fits in a word, so the words' difference is exact.
        z = x > y ? rawSub(uint256(x), uint256(y)) : rawSub(uint256(y), uint256(x));
    }

    /// @dev Returns the minimum of `x` and `y`.
    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = y < x ? y : x;
    }

    /// @dev Returns the minimum of `x` and `y`.
    function min(int256 x, int256 y) internal pure returns (int256 z) {
        z = y < x ? y : x;
    }

    /// @dev Returns the maximum of `x` and `y`.
    function max(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = y > x ? y : x;
    }

    /// @dev Returns the maximum of `x` and `y`.
    function max(int256 x, int256 y) internal pure returns (int256 z) {
        z = y > x ? y : x;
    }

    /// @dev Returns `x`, bounded to `minValue` and `maxValue`.
    function clamp(uint256 x, uint256 minValue, uint256 maxValue)
        internal
        pure
        returns (uint256 z)
    {
        z = minValue > x ? minValue : x;
        z = maxValue < z ? maxValue : z;
    }

    /// @dev Returns `x`, bounded to `minValue` and `maxValue`.
    function clamp(int256 x, int256 minValue, int256 maxValue) internal pure returns (int256 z) {
        z = minValue > x ? minValue : x;
        z = maxValue < z ? maxValue : z;
    }

    /// @dev Returns greatest common divisor of `x` and `y`.
    function gcd(uint256 x, uint256 y) internal pure returns (uint256 z) {
        for (z = x; y != 0;) {
            uint256 t = y;
            y = z % y;
            z = t;
        }
    }

    /// @dev Returns `a + (b - a) * (t - begin) / (end - begin)`,
    /// with `t` clamped between `begin` and `end` (inclusive).
    /// Agnostic to the order of (`a`, `b`) and (`end`, `begin`).
    /// If `begins == end`, returns `t <= begin ? a : b`.
    function lerp(uint256 a, uint256 b, uint256 t, uint256 begin, uint256 end)
        internal
        pure
        returns (uint256)
    {
        if (begin > end) (t, begin, end) = (~t, ~begin, ~end);
        if (t <= begin) return a;
        if (t >= end) return b;
        // `begin < t < end`, so the scaled difference is below `|b - a|`.
        if (b >= a) return rawAdd(a, fullMulDiv(b - a, t - begin, rawSub(end, begin)));
        return rawSub(a, fullMulDiv(a - b, t - begin, rawSub(end, begin)));
    }

    /// @dev Returns `a + (b - a) * (t - begin) / (end - begin)`.
    /// with `t` clamped between `begin` and `end` (inclusive).
    /// Agnostic to the order of (`a`, `b`) and (`end`, `begin`).
    /// If `begins == end`, returns `t <= begin ? a : b`.
    function lerp(int256 a, int256 b, int256 t, int256 begin, int256 end)
        internal
        pure
        returns (int256)
    {
        if (begin > end) (t, begin, end) = (~t, ~begin, ~end);
        if (t <= begin) return a;
        if (t >= end) return b;
        // The signed differences fit as words, and so does the interpolated result.
        // forgefmt: disable-next-item
        if (b >= a) return int256(rawAdd(uint256(a), fullMulDiv(uint256(rawSub(b, a)),
            uint256(rawSub(t, begin)), uint256(rawSub(end, begin)))));
        // forgefmt: disable-next-item
        return int256(rawSub(uint256(a), fullMulDiv(uint256(rawSub(a, b)),
            uint256(rawSub(t, begin)), uint256(rawSub(end, begin)))));
    }

    /// @dev Returns if `x` is an even number. Some people may need this.
    function isEven(uint256 x) internal pure returns (bool) {
        return x & uint256(1) == uint256(0);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   RAW NUMBER OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `x + y`, without checking for overflow.
    /// @custom:solar-trusted
    function rawAdd(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x + y;
        }
    }

    /// @dev Returns `x + y`, without checking for overflow.
    /// @custom:solar-trusted
    function rawAdd(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x + y;
        }
    }

    /// @dev Returns `x - y`, without checking for underflow.
    /// @custom:solar-trusted
    function rawSub(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x - y;
        }
    }

    /// @dev Returns `x - y`, without checking for underflow.
    /// @custom:solar-trusted
    function rawSub(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x - y;
        }
    }

    /// @dev Returns `x * y`, without checking for overflow.
    /// @custom:solar-trusted
    function rawMul(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Returns `x * y`, without checking for overflow.
    /// @custom:solar-trusted
    function rawMul(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Returns `x / y`, returning 0 if `y` is zero.
    function rawDiv(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = y == 0 ? 0 : x / y;
    }

    /// @dev Returns `x / y`, returning 0 if `y` is zero.
    /// @custom:solar-trusted
    function rawSDiv(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = y == 0 ? int256(0) : x / y;
        }
    }

    /// @dev Returns `x % y`, returning 0 if `y` is zero.
    function rawMod(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = y == 0 ? 0 : x % y;
    }

    /// @dev Returns `x % y`, returning 0 if `y` is zero.
    function rawSMod(int256 x, int256 y) internal pure returns (int256 z) {
        z = y == 0 ? int256(0) : x % y;
    }

    /// @dev Returns `(x + y) % d`, return 0 if `d` if zero.
    function rawAddMod(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        z = d == 0 ? 0 : addmod(x, y, d);
    }

    /// @dev Returns `(x * y) % d`, return 0 if `d` if zero.
    function rawMulMod(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        z = d == 0 ? 0 : mulmod(x, y, d);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `b ** e`, without checking for overflow.
    /// @custom:solar-trusted
    function _rawExp(uint256 b, uint256 e) private pure returns (uint256 z) {
        unchecked {
            z = b ** e;
        }
    }

    /// @dev Returns the bit position, a multiple of 8, of the byte of `x` that
    /// holds its highest set bit, or 0 if `x` is zero.
    /// @custom:solar-inline
    function _msbByte(uint256 x) private pure returns (uint256 r) {
        r = x > type(uint128).max ? 128 : 0;
        r |= (x >> r) > type(uint64).max ? 64 : 0;
        r |= (x >> r) > type(uint32).max ? 32 : 0;
        r |= (x >> r) > type(uint16).max ? 16 : 0;
        r |= (x >> r) > type(uint8).max ? 8 : 0;
    }
}
