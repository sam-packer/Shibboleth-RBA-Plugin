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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Calls an external RBA service and decides based on "threatScore".
 */
public class RiskBasedAuthAction extends AbstractProfileAction {
    private static final Gson GSON = new Gson();
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    private final Logger log = LoggerFactory.getLogger(RiskBasedAuthAction.class);

    /**
     * e.g. https://rba.example.com/score (required)
     */
    private String rbaEndpoint;

    /**
     * Deny when threatScore >= failureThreshold (required)
     */
    private double failureThreshold;

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
        final String userAgent = sanitizeUserAgent(servletRequest.getHeader("User-Agent"));

        log.info("Starting RBA check for user='{}', ip='{}'", username, ipAddress);

        // Build payload
        final String payload = String.format(
                "{\"username\":\"%s\",\"ipAddress\":\"%s\",\"userAgent\":\"%s\"}",
                username, ipAddress, userAgent
        );

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

            log.debug("Sending payload to RBA service: {}", payload);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
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

            // Parse JSON and extract threatScore
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
                emit(prc, EventIds.PROCEED_EVENT_ID); // "proceed"
            } else {
                log.warn("Login denied by RBA: threatScore {} >= threshold {}", threatScore, failureThreshold);
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

    /**
     * Helper to set an event and log it.
     */
    private void emit(ProfileRequestContext prc, String eventId) {
        final EventContext ec = prc.ensureSubcontext(EventContext.class);
        ec.setEvent(eventId);
        final EventContext readback = prc.getSubcontext(EventContext.class);
        log.info("RBA: emitting event='{}'", (readback != null ? readback.getEvent() : "<missing EventContext>"));
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            final StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    /**
     * Pull client IP, preferring X-Forwarded-For safely (first non-empty token).
     */
    private static String extractClientIp(HttpServletRequest req) {
        final String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            final String first = xff.split(",")[0].trim();
            if (!first.isEmpty()) return first;
        }
        return req.getRemoteAddr();
    }

    /**
     * Cap UA length to avoid log spam / oversized payloads.
     */
    private static String sanitizeUserAgent(String ua) {
        if (ua == null) return "";
        final int MAX = 512;
        return ua.length() <= MAX ? ua : ua.substring(0, MAX);
    }
}
