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
