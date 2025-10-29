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

package com.sampacker.shibboleth.rba;

import com.google.gson.*;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.shared.servlet.impl.HttpServletRequestResponseContext;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static com.sampacker.shibboleth.rba.utils.JsonHelper.sanitizeAndValidateMetrics;
import static com.sampacker.shibboleth.rba.utils.StringHelper.*;

/**
 * Calls an external RBA service with behavioral metrics and enforces access based on threatScore.
 */
public class RiskBasedAuthAction extends AbstractProfileAction {

    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    private static final ConcurrentHashMap<String, Long> DENIED_USERS = new ConcurrentHashMap<>();
    private static final long DENIAL_TIMEOUT_MS = TimeUnit.HOURS.toMillis(1);

    private final Logger log = LoggerFactory.getLogger(RiskBasedAuthAction.class);

    private String rbaEndpoint;
    private double failureThreshold;

    public enum FieldType {NUMBER, BOOLEAN, STRING}

    public static final Map<String, FieldType> ALLOWED_FIELDS;

    static {
        Map<String, FieldType> m = new LinkedHashMap<>();
        m.put("focus_changes", FieldType.NUMBER);
        m.put("blur_events", FieldType.NUMBER);
        m.put("click_count", FieldType.NUMBER);
        m.put("key_count", FieldType.NUMBER);
        m.put("avg_key_delay_ms", FieldType.NUMBER);
        m.put("pointer_distance_px", FieldType.NUMBER);
        m.put("pointer_event_count", FieldType.NUMBER);
        m.put("scroll_distance_px", FieldType.NUMBER);
        m.put("scroll_event_count", FieldType.NUMBER);
        m.put("dom_ready_ms", FieldType.NUMBER);
        m.put("time_to_first_key_ms", FieldType.NUMBER);
        m.put("time_to_first_click_ms", FieldType.NUMBER);
        m.put("idle_time_total_ms", FieldType.NUMBER);
        m.put("input_focus_count", FieldType.NUMBER);
        m.put("paste_events", FieldType.NUMBER);
        m.put("resize_events", FieldType.NUMBER);
        m.put("metrics_version", FieldType.NUMBER);
        m.put("collection_timestamp", FieldType.STRING);
        m.put("tz_offset_min", FieldType.NUMBER);
        m.put("language", FieldType.STRING);
        m.put("platform", FieldType.STRING);
        m.put("device_memory_gb", FieldType.NUMBER);
        m.put("hardware_concurrency", FieldType.NUMBER);
        m.put("screen_width_px", FieldType.NUMBER);
        m.put("screen_height_px", FieldType.NUMBER);
        m.put("pixel_ratio", FieldType.NUMBER);
        m.put("color_depth", FieldType.NUMBER);
        m.put("touch_support", FieldType.BOOLEAN);
        m.put("webauthn_supported", FieldType.BOOLEAN);
        m.put("device_uuid", FieldType.STRING);
        ALLOWED_FIELDS = Collections.unmodifiableMap(m);
    }

    public String getRbaEndpoint() {
        return rbaEndpoint;
    }

    public void setRbaEndpoint(String rbaEndpoint) {
        this.rbaEndpoint = rbaEndpoint;
    }

    public double getFailureThreshold() {
        return failureThreshold;
    }

    public void setFailureThreshold(double failureThreshold) {
        this.failureThreshold = failureThreshold;
    }

    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext prc) {
        final AuthenticationContext authnCtx = prc.getSubcontext(AuthenticationContext.class);
        if (authnCtx == null || authnCtx.getAuthenticationResult() == null) {
            log.error("AuthenticationContext or AuthenticationResult is not available.");
            emit(prc, EventIds.RUNTIME_EXCEPTION);
            return;
        }

        if (rbaEndpoint == null || rbaEndpoint.isBlank()) {
            log.error("rbaEndpoint is not configured.");
            emit(prc, EventIds.RUNTIME_EXCEPTION);
            return;
        }

        final HttpServletRequest servletRequest = HttpServletRequestResponseContext.getRequest();
        if (servletRequest == null) {
            log.error("HttpServletRequest is not available.");
            emit(prc, EventIds.RUNTIME_EXCEPTION);
            return;
        }

        final AuthenticationResult result = authnCtx.getAuthenticationResult();
        final Set<UsernamePrincipal> ups = result.getSubject().getPrincipals(UsernamePrincipal.class);
        final String username = ups.isEmpty() ? null : ups.iterator().next().getName();

        final String ipAddress = extractClientIp(servletRequest);
        final String userAgent = safeString(servletRequest.getHeader("User-Agent"));

        log.info("Starting RBA check for user='{}', ip='{}'", username, ipAddress);

        // Capture raw metrics string
        final String metricsRaw = servletRequest.getParameter("rbaMetricsField");
        log.debug("rbaMetricsField raw={}", metricsRaw);

        // Check if metrics are null (SSO attempt)
        if (metricsRaw == null || metricsRaw.isBlank()) {
            // Check if this user was previously denied
            Long denialTime = DENIED_USERS.get(username);
            if (denialTime != null) {
                long timeSinceDenial = System.currentTimeMillis() - denialTime;
                if (timeSinceDenial < DENIAL_TIMEOUT_MS) {
                    log.warn("RBA: SSO attempt by previously denied user '{}' (denied {}ms ago) - BLOCKING",
                            username, timeSinceDenial);
                    emit(prc, EventIds.ACCESS_DENIED);
                    return;
                } else {
                    // Timeout expired, remove from denied list
                    DENIED_USERS.remove(username);
                    log.info("RBA: Denial timeout expired for user '{}', allowing SSO", username);
                }
            }

            // User not in denied list - allow SSO
            log.info("RBA: SSO attempt by user '{}' who is not in denied list - ALLOWING", username);
            emit(prc, EventIds.PROCEED_EVENT_ID);
            return;
        }

        // Metrics present - this is a fresh login, perform full RBA check
        JsonObject sanitizedMetrics = sanitizeAndValidateMetrics(metricsRaw);
        if (sanitizedMetrics == null) {
            log.warn("Metrics were rejected or invalid; denying access for user='{}'", username);
            DENIED_USERS.put(username, System.currentTimeMillis());
            emit(prc, EventIds.ACCESS_DENIED);
            return;
        }

        // Build payload
        final JsonObject payload = new JsonObject();
        payload.addProperty("username", safeString(username));
        payload.addProperty("ipAddress", safeString(ipAddress));
        payload.addProperty("userAgent", safeString(userAgent));
        payload.add("metrics", sanitizedMetrics);

        // Send to RBA endpoint
        HttpURLConnection conn = null;
        try {
            final URL url = new URL(rbaEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            final String jsonPayload = GSON.toJson(payload);
            log.debug("Sending payload to RBA service: {}", maskPayloadForLogs(jsonPayload));
            try (OutputStream os = conn.getOutputStream()) {
                byte[] bytes = jsonPayload.getBytes(StandardCharsets.UTF_8);
                if (bytes.length > (64 * 1024)) {
                    log.warn("Prepared RBA payload too large ({} bytes); aborting call.", bytes.length);
                    emit(prc, EventIds.RUNTIME_EXCEPTION);
                    return;
                }
                os.write(bytes);
            }

            final int status = conn.getResponseCode();
            final boolean ok = status >= 200 && status < 300;
            final String body = readAll(ok ? conn.getInputStream() : conn.getErrorStream());
            log.debug("RBA service HTTP {} body: {}", status, body);

            if (!ok) {
                log.error("RBA service returned non-2xx status: {}", status);
                emit(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            final JsonObject json = GSON.fromJson(body, JsonObject.class);
            if (json == null || !json.has("threatScore")) {
                log.error("RBA response missing required 'threatScore'.");
                emit(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            final double threatScore = json.get("threatScore").getAsDouble();
            if (!Double.isFinite(threatScore)) {
                log.error("RBA 'threatScore' is not a finite number: {}", threatScore);
                emit(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            log.info("RBA score={}, idpThreshold={}", threatScore, failureThreshold);

            if (threatScore < failureThreshold) {
                // User passed RBA - remove from denied list if present
                DENIED_USERS.remove(username);
                log.info("RBA: User '{}' passed RBA check - ALLOWING", username);
                emit(prc, EventIds.PROCEED_EVENT_ID);
            } else {
                // User failed RBA - add to denied list
                DENIED_USERS.put(username, System.currentTimeMillis());
                log.warn("Login denied by RBA: threatScore {} >= threshold {}. User '{}' blocked for {}ms",
                        threatScore, failureThreshold, username, DENIAL_TIMEOUT_MS);
                emit(prc, EventIds.ACCESS_DENIED);
            }

        } catch (JsonSyntaxException jse) {
            log.error("Invalid JSON from RBA service.", jse);
            emit(prc, EventIds.RUNTIME_EXCEPTION);
        } catch (Exception e) {
            log.error("Error calling RBA service at {}", rbaEndpoint, e);
            emit(prc, EventIds.RUNTIME_EXCEPTION);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    public void emit(ProfileRequestContext prc, String eventId) {
        final EventContext ec = prc.ensureSubcontext(EventContext.class);
        ec.setEvent(eventId);
        final EventContext readback = prc.getSubcontext(EventContext.class);
        log.info("RBA: emitting event='{}'", (readback != null ? readback.getEvent() : "<missing EventContext>"));
    }
}
