// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for date time operations.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/DateTimeLib.sol)
/// @author Modified from BokkyPooBahsDateTimeLibrary (https://github.com/bokkypoobah/BokkyPooBahsDateTimeLibrary)
/// @dev
/// Conventions:
/// --------------------------------------------------------------------+
/// Unit      | Range                | Notes                            |
/// --------------------------------------------------------------------|
/// timestamp | 0..0x1e18549868c76ff | Unix timestamp.                  |
/// epochDay  | 0..0x16d3e098039     | Days since 1970-01-01.           |
/// year      | 1970..0xffffffff     | Gregorian calendar year.         |
/// month     | 1..12                | Gregorian calendar month.        |
/// day       | 1..31                | Gregorian calendar day of month. |
/// weekday   | 1..7                 | The day of the week (1-indexed). |
/// --------------------------------------------------------------------+
/// All timestamps of days are rounded down to 00:00:00 UTC.
///
/// The checked port computes as the assembly does, including outside the supported
/// ranges: each step that wraps there goes through the raw `_add`, `_sub` and `_mul`
/// helpers, so a date converts to its epoch day and back for every word, and every
/// step that cannot wrap is checked Solidity. `epochDayToDate` splits the day of the
/// 400-year era with Neri and Schneider's Euclidean affine functions, which give the
/// assembly's dates for every day of the era with sums, products and quotients only, so
/// no check can fail. The date conversions are tagged for inlining, so calls with
/// constant arguments fold.
/// @custom:solar-safe memory arithmetic
library DateTimeLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Weekdays are 1-indexed, adhering to ISO 8601.

    uint256 internal constant MON = 1;
    uint256 internal constant TUE = 2;
    uint256 internal constant WED = 3;
    uint256 internal constant THU = 4;
    uint256 internal constant FRI = 5;
    uint256 internal constant SAT = 6;
    uint256 internal constant SUN = 7;

    // Months and days of months are 1-indexed, adhering to ISO 8601.

    uint256 internal constant JAN = 1;
    uint256 internal constant FEB = 2;
    uint256 internal constant MAR = 3;
    uint256 internal constant APR = 4;
    uint256 internal constant MAY = 5;
    uint256 internal constant JUN = 6;
    uint256 internal constant JUL = 7;
    uint256 internal constant AUG = 8;
    uint256 internal constant SEP = 9;
    uint256 internal constant OCT = 10;
    uint256 internal constant NOV = 11;
    uint256 internal constant DEC = 12;

    // These limits are large enough for most practical purposes.
    // Inputs that exceed these limits result in undefined behavior.

    uint256 internal constant MAX_SUPPORTED_YEAR = 0xffffffff;
    uint256 internal constant MAX_SUPPORTED_EPOCH_DAY = 0x16d3e098039;
    uint256 internal constant MAX_SUPPORTED_TIMESTAMP = 0x1e18549868c76ff;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    DATE TIME OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of days since 1970-01-01 from (`year`,`month`,`day`).
    /// See: https://howardhinnant.github.io/date_algorithms.html
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedDate} to check if the inputs are supported.
    /// @custom:solar-inline always
    function dateToEpochDay(uint256 year, uint256 month, uint256 day)
        internal
        pure
        returns (uint256 epochDay)
    {
        year = _sub(year, month < 3 ? 1 : 0);
        uint256 doy = _add((62719 * (_add(month, 9) % 12) + 769) >> 11, day);
        uint256 yoe = year % 400;
        uint256 doe = _sub(_add(yoe * 365 + (yoe >> 2), doy), yoe / 100);
        epochDay = _sub(_add(_mul(year / 400, 146097), doe), 719469);
    }

    /// @dev Returns (`year`,`month`,`day`) from the number of days since 1970-01-01.
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedDays} to check if the inputs is supported.
    /// @custom:solar-inline always
    function epochDayToDate(uint256 epochDay)
        internal
        pure
        returns (uint256 year, uint256 month, uint256 day)
    {
        epochDay = _add(epochDay, 719468);
        // Four times the day of the era, plus three, gives the century of the era and,
        // past whole centuries, four times the day of the century plus three, which
        // gives the year of the century and the day of the year from March.
        uint256 n = (epochDay % 146097) * 4 + 3;
        uint256 c = n / 146097;
        n = (n % 146097) | 3;
        uint256 doy = (n % 1461) >> 2;
        // The month from March, 3 to 14, in the high bits; the day of the month below.
        uint256 m = doy * 2141 + 197913;
        day = (m & 0xffff) / 2141 + 1;
        // `[.., .., .., 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 1, 2][m >> 16]`.
        month = (0x02010c0b0a09080706050403000000 >> ((m >> 16) << 3)) & 0xff;
        year = epochDay / 146097 * 400 + c * 100 + n / 1461 + (month < 3 ? 1 : 0);
    }

    /// @dev Returns the unix timestamp from (`year`,`month`,`day`).
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedDate} to check if the inputs are supported.
    /// @custom:solar-inline always
    function dateToTimestamp(uint256 year, uint256 month, uint256 day)
        internal
        pure
        returns (uint256 result)
    {
        result = _mul(dateToEpochDay(year, month, day), 86400);
    }

    /// @dev Returns (`year`,`month`,`day`) from the given unix timestamp.
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedTimestamp} to check if the inputs are supported.
    /// @custom:solar-inline always
    function timestampToDate(uint256 timestamp)
        internal
        pure
        returns (uint256 year, uint256 month, uint256 day)
    {
        (year, month, day) = epochDayToDate(timestamp / 86400);
    }

    /// @dev Returns the unix timestamp from
    /// (`year`,`month`,`day`,`hour`,`minute`,`second`).
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedDateTime} to check if the inputs are supported.
    function dateTimeToTimestamp(
        uint256 year,
        uint256 month,
        uint256 day,
        uint256 hour,
        uint256 minute,
        uint256 second
    ) internal pure returns (uint256 result) {
        result = _add(
            _add(
                _add(_mul(dateToEpochDay(year, month, day), 86400), _mul(hour, 3600)),
                _mul(minute, 60)
            ),
            second
        );
    }

    /// @dev Returns (`year`,`month`,`day`,`hour`,`minute`,`second`)
    /// from the given unix timestamp.
    /// Note: Inputs outside the supported ranges result in undefined behavior.
    /// Use {isSupportedTimestamp} to check if the inputs are supported.
    /// @custom:solar-inline always
    function timestampToDateTime(uint256 timestamp)
        internal
        pure
        returns (
            uint256 year,
            uint256 month,
            uint256 day,
            uint256 hour,
            uint256 minute,
            uint256 second
        )
    {
        (year, month, day) = epochDayToDate(timestamp / 86400);
        uint256 secs = timestamp % 86400;
        hour = secs / 3600;
        secs = secs % 3600;
        minute = secs / 60;
        second = secs % 60;
    }

    /// @dev Returns if the `year` is leap.
    /// @custom:solar-inline always
    function isLeapYear(uint256 year) internal pure returns (bool leap) {
        leap = year & (year % 25 == 0 ? 15 : 3) == 0;
    }

    /// @dev Returns number of days in given `month` of `year`.
    /// @custom:solar-inline always
    function daysInMonth(uint256 year, uint256 month) internal pure returns (uint256 result) {
        bool flag = isLeapYear(year);
        // `daysInMonths = [31,28,31,30,31,30,31,31,30,31,30,31]`.
        // `result = daysInMonths[month - 1] + isLeapYear(year)`, zero for another month.
        if (month != 0 && month <= 12) {
            result = (0x1f1c1f1e1f1e1f1f1e1f1e1f >> ((12 - month) << 3)) & 0xff;
            if (month == 2 && flag) ++result;
        }
    }

    /// @dev Returns the weekday from the unix timestamp.
    /// Monday: 1, Tuesday: 2, ....., Sunday: 7.
    function weekday(uint256 timestamp) internal pure returns (uint256 result) {
        result = ((timestamp / 86400 + 3) % 7) + 1;
    }

    /// @dev Returns if (`year`,`month`,`day`) is a supported date.
    /// - `1970 <= year <= MAX_SUPPORTED_YEAR`.
    /// - `1 <= month <= 12`.
    /// - `1 <= day <= daysInMonth(year, month)`.
    function isSupportedDate(uint256 year, uint256 month, uint256 day)
        internal
        pure
        returns (bool result)
    {
        uint256 md = daysInMonth(year, month);
        result = year >= 1970 && year <= MAX_SUPPORTED_YEAR && month >= 1 && month <= 12 && day >= 1
            && day <= md;
    }

    /// @dev Returns if (`year`,`month`,`day`,`hour`,`minute`,`second`) is a supported date time.
    /// - `1970 <= year <= MAX_SUPPORTED_YEAR`.
    /// - `1 <= month <= 12`.
    /// - `1 <= day <= daysInMonth(year, month)`.
    /// - `hour < 24`.
    /// - `minute < 60`.
    /// - `second < 60`.
    function isSupportedDateTime(
        uint256 year,
        uint256 month,
        uint256 day,
        uint256 hour,
        uint256 minute,
        uint256 second
    ) internal pure returns (bool result) {
        if (isSupportedDate(year, month, day)) {
            result = hour < 24 && minute < 60 && second < 60;
        }
    }

    /// @dev Returns if `epochDay` is a supported unix epoch day.
    function isSupportedEpochDay(uint256 epochDay) internal pure returns (bool result) {
        result = epochDay <= MAX_SUPPORTED_EPOCH_DAY;
    }

    /// @dev Returns if `timestamp` is a supported unix timestamp.
    function isSupportedTimestamp(uint256 timestamp) internal pure returns (bool result) {
        result = timestamp <= MAX_SUPPORTED_TIMESTAMP;
    }

    /// @dev Returns the unix timestamp of the given `n`th weekday `wd`, in `month` of `year`.
    /// Example: 3rd Friday of Feb 2022 is `nthWeekdayInMonthOfYearTimestamp(2022, 2, 3, 5)`
    /// Note: `n` is 1-indexed for traditional consistency.
    /// Invalid weekdays (i.e. `wd == 0 || wd > 7`) result in undefined behavior.
    /// @custom:solar-inline always
    function nthWeekdayInMonthOfYearTimestamp(uint256 year, uint256 month, uint256 n, uint256 wd)
        internal
        pure
        returns (uint256 result)
    {
        uint256 d = dateToEpochDay(year, month, 1);
        uint256 md = daysInMonth(year, month);
        // The days from the 1st to the first `wd`, wrapped into `0..6`.
        uint256 diff = _sub(wd, _add(d, 3) % 7 + 1);
        uint256 date = _add(_mul(_sub(n, 1), 7), _add(diff > 6 ? 7 : 0, diff));
        if (date < md && n != 0) result = _mul(86400, _add(date, d));
    }

    /// @dev Returns the unix timestamp of the most recent Monday.
    function mondayTimestamp(uint256 timestamp) internal pure returns (uint256 result) {
        uint256 day = timestamp / 86400;
        if (timestamp > 345599) result = (day - (day + 3) % 7) * 86400;
    }

    /// @dev Returns whether the unix timestamp falls on a Saturday or Sunday.
    /// To check whether it is a week day, just take the negation of the result.
    function isWeekEnd(uint256 timestamp) internal pure returns (bool result) {
        result = weekday(timestamp) > FRI;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              DATE TIME ARITHMETIC OPERATIONS               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Adds `numYears` to the unix timestamp, and returns the result.
    /// Note: The result will share the same Gregorian calendar month,
    /// but different Gregorian calendar years for non-zero `numYears`.
    /// If the Gregorian calendar month of the result has less days
    /// than the Gregorian calendar month day of the `timestamp`,
    /// the result's month day will be the maximum possible value for the month.
    /// (e.g. from 29th Feb to 28th Feb)
    function addYears(uint256 timestamp, uint256 numYears) internal pure returns (uint256 result) {
        (uint256 year, uint256 month, uint256 day) = epochDayToDate(timestamp / 86400);
        result = _offsetted(year + numYears, month, day, timestamp);
    }

    /// @dev Adds `numMonths` to the unix timestamp, and returns the result.
    /// Note: If the Gregorian calendar month of the result has less days
    /// than the Gregorian calendar month day of the `timestamp`,
    /// the result's month day will be the maximum possible value for the month.
    /// (e.g. from 29th Feb to 28th Feb)
    function addMonths(uint256 timestamp, uint256 numMonths)
        internal
        pure
        returns (uint256 result)
    {
        (uint256 year, uint256 month, uint256 day) = epochDayToDate(timestamp / 86400);
        month = _sub(month + numMonths, 1);
        result = _offsetted(year + month / 12, _add(month % 12, 1), day, timestamp);
    }

    /// @dev Adds `numDays` to the unix timestamp, and returns the result.
    function addDays(uint256 timestamp, uint256 numDays) internal pure returns (uint256 result) {
        result = timestamp + numDays * 86400;
    }

    /// @dev Adds `numHours` to the unix timestamp, and returns the result.
    function addHours(uint256 timestamp, uint256 numHours) internal pure returns (uint256 result) {
        result = timestamp + numHours * 3600;
    }

    /// @dev Adds `numMinutes` to the unix timestamp, and returns the result.
    function addMinutes(uint256 timestamp, uint256 numMinutes)
        internal
        pure
        returns (uint256 result)
    {
        result = timestamp + numMinutes * 60;
    }

    /// @dev Adds `numSeconds` to the unix timestamp, and returns the result.
    function addSeconds(uint256 timestamp, uint256 numSeconds)
        internal
        pure
        returns (uint256 result)
    {
        result = timestamp + numSeconds;
    }

    /// @dev Subtracts `numYears` from the unix timestamp, and returns the result.
    /// Note: The result will share the same Gregorian calendar month,
    /// but different Gregorian calendar years for non-zero `numYears`.
    /// If the Gregorian calendar month of the result has less days
    /// than the Gregorian calendar month day of the `timestamp`,
    /// the result's month day will be the maximum possible value for the month.
    /// (e.g. from 29th Feb to 28th Feb)
    function subYears(uint256 timestamp, uint256 numYears) internal pure returns (uint256 result) {
        (uint256 year, uint256 month, uint256 day) = epochDayToDate(timestamp / 86400);
        result = _offsetted(year - numYears, month, day, timestamp);
    }

    /// @dev Subtracts `numYears` from the unix timestamp, and returns the result.
    /// Note: If the Gregorian calendar month of the result has less days
    /// than the Gregorian calendar month day of the `timestamp`,
    /// the result's month day will be the maximum possible value for the month.
    /// (e.g. from 29th Feb to 28th Feb)
    function subMonths(uint256 timestamp, uint256 numMonths)
        internal
        pure
        returns (uint256 result)
    {
        (uint256 year, uint256 month, uint256 day) = epochDayToDate(timestamp / 86400);
        uint256 yearMonth = _totalMonths(year, month) - _add(numMonths, 1);
        result = _offsetted(yearMonth / 12, _add(yearMonth % 12, 1), day, timestamp);
    }

    /// @dev Subtracts `numDays` from the unix timestamp, and returns the result.
    function subDays(uint256 timestamp, uint256 numDays) internal pure returns (uint256 result) {
        result = timestamp - numDays * 86400;
    }

    /// @dev Subtracts `numHours` from the unix timestamp, and returns the result.
    function subHours(uint256 timestamp, uint256 numHours) internal pure returns (uint256 result) {
        result = timestamp - numHours * 3600;
    }

    /// @dev Subtracts `numMinutes` from the unix timestamp, and returns the result.
    function subMinutes(uint256 timestamp, uint256 numMinutes)
        internal
        pure
        returns (uint256 result)
    {
        result = timestamp - numMinutes * 60;
    }

    /// @dev Subtracts `numSeconds` from the unix timestamp, and returns the result.
    function subSeconds(uint256 timestamp, uint256 numSeconds)
        internal
        pure
        returns (uint256 result)
    {
        result = timestamp - numSeconds;
    }

    /// @dev Returns the difference in Gregorian calendar years
    /// between `fromTimestamp` and `toTimestamp`.
    /// Note: Even if the true time difference is less than a year,
    /// the difference can be non-zero is the timestamps are
    /// from different Gregorian calendar years
    function diffYears(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        toTimestamp - fromTimestamp;
        (uint256 fromYear,,) = epochDayToDate(fromTimestamp / 86400);
        (uint256 toYear,,) = epochDayToDate(toTimestamp / 86400);
        result = _sub(toYear, fromYear);
    }

    /// @dev Returns the difference in Gregorian calendar months
    /// between `fromTimestamp` and `toTimestamp`.
    /// Note: Even if the true time difference is less than a month,
    /// the difference can be non-zero is the timestamps are
    /// from different Gregorian calendar months.
    function diffMonths(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        toTimestamp - fromTimestamp;
        (uint256 fromYear, uint256 fromMonth,) = epochDayToDate(fromTimestamp / 86400);
        (uint256 toYear, uint256 toMonth,) = epochDayToDate(toTimestamp / 86400);
        result = _sub(_totalMonths(toYear, toMonth), _totalMonths(fromYear, fromMonth));
    }

    /// @dev Returns the difference in days between `fromTimestamp` and `toTimestamp`.
    function diffDays(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        result = (toTimestamp - fromTimestamp) / 86400;
    }

    /// @dev Returns the difference in hours between `fromTimestamp` and `toTimestamp`.
    function diffHours(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        result = (toTimestamp - fromTimestamp) / 3600;
    }

    /// @dev Returns the difference in minutes between `fromTimestamp` and `toTimestamp`.
    function diffMinutes(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        result = (toTimestamp - fromTimestamp) / 60;
    }

    /// @dev Returns the difference in seconds between `fromTimestamp` and `toTimestamp`.
    function diffSeconds(uint256 fromTimestamp, uint256 toTimestamp)
        internal
        pure
        returns (uint256 result)
    {
        result = toTimestamp - fromTimestamp;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Unchecked arithmetic for computing the total number of months.
    /// @custom:solar-trusted
    function _totalMonths(uint256 numYears, uint256 numMonths)
        private
        pure
        returns (uint256 total)
    {
        unchecked {
            total = numYears * 12 + numMonths;
        }
    }

    /// @dev Unchecked arithmetic for adding two numbers.
    /// @custom:solar-trusted
    function _add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev Unchecked arithmetic for subtracting two numbers.
    /// @custom:solar-trusted
    function _sub(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a - b;
        }
    }

    /// @dev Unchecked arithmetic for multiplying two numbers.
    /// @custom:solar-trusted
    function _mul(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a * b;
        }
    }

    /// @dev Returns the offsetted timestamp.
    /// @custom:solar-inline always
    function _offsetted(uint256 year, uint256 month, uint256 day, uint256 timestamp)
        private
        pure
        returns (uint256 result)
    {
        uint256 dm = daysInMonth(year, month);
        if (day >= dm) {
            day = dm;
        }
        result = dateToEpochDay(year, month, day) * 86400 + (timestamp % 86400);
    }
}
