/*
 * Copyright (c) 2025 Sam Packer
 *
 * This software is licensed under the PolyForm Noncommercial License 1.0.0.
 *
 * You may use, copy, modify, and distribute this software for noncommercial purposes only.
 * Commercial use of this software, in whole or in part, is prohibited.
 *
 * See the full license text at:
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 * or in the LICENSE.md file included with this source code.
 */

package com.sampacker.shibboleth.rba.utils;

public class NumberHelper
{
    public static int clamp(double v, int lo, int hi) {
        if (Double.isNaN(v)) {
            return lo;
        }
        long lv = Math.round(v);
        return (int) Math.max(lo, Math.min(hi, lv));
    }

    public static long clamp(double v, long lo, long hi) {
        if (Double.isNaN(v)) {
            return lo;
        }
        long lv = Math.round(v);
        return Math.max(lo, Math.min(hi, lv));
    }

    public static double clampDouble(double v, double lo, double hi) {
        if (Double.isNaN(v)) {
            return lo;
        }
        return Math.max(lo, Math.min(hi, v));
    }
}
