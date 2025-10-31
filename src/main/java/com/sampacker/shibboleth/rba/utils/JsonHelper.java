package com.sampacker.shibboleth.rba.utils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.sampacker.shibboleth.rba.RiskBasedAuthAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.sampacker.shibboleth.rba.RiskBasedAuthAction.*;
import static com.sampacker.shibboleth.rba.utils.NumberHelper.clamp;
import static com.sampacker.shibboleth.rba.utils.NumberHelper.clampDouble;
import static com.sampacker.shibboleth.rba.utils.StringHelper.sanitizeString;

public class JsonHelper
{
    private static final Logger log = LoggerFactory.getLogger(JsonHelper.class);

    public static final int MAX_METRICS_BYTES = 8 * 1024; // 8 KB max raw metrics JSON
    public static final int MAX_NUM_PARTITION = 1_000_000_000; // general numeric cap to avoid overflow
    public static final int MAX_KEY_COUNT = 10_000;
    public static final int MAX_CLICK_COUNT = 10_000;
    public static final int MAX_POINTER_DISTANCE_PX = 10_000_000;
    public static final int MAX_SCROLL_DISTANCE_PX = 10_000_000;
    public static final int MAX_DOM_READY_MS = 86_400_000; // 24 hours in ms
    public static final int MAX_TZ_OFFSET_MIN = 24 * 60; // +/- 24 hours
    public static final int MAX_DEVICE_MEMORY_GB = 1024;
    public static final int MAX_HW_CONCURRENCY = 1024;
    public static final double MAX_PIXEL_RATIO = 16.0;
    public static final int MAX_COLLECTION_TIMESTAMP_LEN = 64;

    /**
     * Sanitize and validate the metrics JSON string.
     * Returns a JsonObject containing only the allowed sanitized fields, or null if invalid/too large.
     */
    public static JsonObject sanitizeAndValidateMetrics(String raw)
    {
        if (raw == null)
        {
            return null;
        }

        final byte[] rawBytes = raw.getBytes(StandardCharsets.UTF_8);
        if (rawBytes.length > MAX_METRICS_BYTES)
        {
            log.warn("rbaMetricsField exceeded max allowed size ({} bytes) and was rejected.", rawBytes.length);
            return null;
        }

        JsonElement parsed;
        try
        {
            parsed = JsonParser.parseString(raw);
        }
        catch (JsonParseException jpe)
        {
            log.warn("rbaMetricsField JSON parse failed", jpe);
            return null;
        }

        if (!parsed.isJsonObject())
        {
            log.warn("rbaMetricsField is not a JSON object; rejecting.");
            return null;
        }

        JsonObject obj = parsed.getAsJsonObject();
        JsonObject out = new JsonObject();

        for (Map.Entry<String, RiskBasedAuthAction.FieldType> entry : ALLOWED_FIELDS.entrySet())
        {
            final String key = entry.getKey();
            final RiskBasedAuthAction.FieldType expected = entry.getValue();

            if (!obj.has(key))
            {
                continue;
            }

            try
            {
                JsonElement el = obj.get(key);
                if (el == null || el.isJsonNull())
                {
                    continue;
                }

                switch (expected)
                {
                    case NUMBER:
                        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isNumber())
                        {
                            log.warn("rbaMetricsField field '{}' expected NUMBER but was not; skipping.", key);
                            continue;
                        }
                        double dv = el.getAsDouble();
                        if (Double.isInfinite(dv) || Double.isNaN(dv))
                        {
                            log.warn("rbaMetricsField field '{}' is not finite; skipping.", key);
                            continue;
                        }
                        switch (key)
                        {
                            case "key_count":
                                out.addProperty(key, clamp(dv, 0, MAX_KEY_COUNT));
                                break;
                            case "click_count":
                                out.addProperty(key, clamp(dv, 0, MAX_CLICK_COUNT));
                                break;
                            case "pointer_distance_px":
                                out.addProperty(key, (long) clamp(dv, 0, MAX_POINTER_DISTANCE_PX));
                                break;
                            case "pointer_event_count", "focus_changes", "blur_events", "input_focus_count",
                                 "paste_events", "resize_events", "scroll_event_count", "screen_width_px",
                                 "screen_height_px", "color_depth":
                                out.addProperty(key, clamp(dv, 0, MAX_NUM_PARTITION));
                                break;
                            case "scroll_distance_px":
                                out.addProperty(key, (long) clamp(dv, 0, MAX_SCROLL_DISTANCE_PX));
                                break;
                            case "avg_key_delay_ms":
                            case "time_to_first_key_ms":
                            case "time_to_first_click_ms":
                            case "idle_time_total_ms":
                            case "dom_ready_ms":
                                out.addProperty(key, (long) clamp(dv, 0, MAX_DOM_READY_MS));
                                break;
                            case "metrics_version":
                                out.addProperty(key, clamp(dv, 0, 1000));
                                break;
                            case "tz_offset_min":
                                out.addProperty(key, clamp(dv, -MAX_TZ_OFFSET_MIN, MAX_TZ_OFFSET_MIN));
                                break;
                            case "device_memory_gb":
                                out.addProperty(key, clamp(dv, 0, MAX_DEVICE_MEMORY_GB));
                                break;
                            case "hardware_concurrency":
                                out.addProperty(key, clamp(dv, 1, MAX_HW_CONCURRENCY));
                                break;
                            case "pixel_ratio":
                                out.addProperty(key, clampDouble(dv, 0.0, MAX_PIXEL_RATIO));
                                break;
                            default:
                                out.addProperty(key, clampDouble(dv, -MAX_NUM_PARTITION, MAX_NUM_PARTITION));
                                break;
                        }
                        break;

                    case BOOLEAN:
                        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isBoolean())
                        {
                            log.warn("rbaMetricsField field '{}' expected BOOLEAN but was not; skipping.", key);
                            continue;
                        }
                        out.addProperty(key, el.getAsBoolean());
                        break;

                    case STRING:
                        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isString())
                        {
                            log.warn("rbaMetricsField field '{}' expected STRING but was not; skipping.", key);
                            continue;
                        }
                        String s = el.getAsString();
                        s = sanitizeString(s);
                        if ("collection_timestamp".equals(key) && s.length() > MAX_COLLECTION_TIMESTAMP_LEN)
                        {
                            // timestamp must be reasonably sized
                            s = s.substring(0, MAX_COLLECTION_TIMESTAMP_LEN);
                        }
                        out.addProperty(key, s);
                        break;
                }
            }
            catch (Exception ex)
            {
                log.warn("Exception validating metrics field '{}': {}", key, ex.getMessage());
            }
        }

        byte[] outBytes = out.toString().getBytes(StandardCharsets.UTF_8);
        if (outBytes.length > MAX_METRICS_BYTES)
        {
            log.warn("Sanitized metrics exceed allowed size ({} bytes); rejecting.", outBytes.length);
            return null;
        }
        return out;
    }
}
