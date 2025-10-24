package com.sampacker.shibboleth.rba;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.shared.servlet.impl.HttpServletRequestResponseContext;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
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

    private final Logger log = LoggerFactory.getLogger(RiskBasedAuthAction.class);

    /**
     * e.g. https://rba.example.com/score
     */
    private String rbaEndpoint;

    /**
     * Local deny threshold (deny when threatScore >= failureThreshold).
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
            ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
            return;
        }

        final HttpServletRequest servletRequest = HttpServletRequestResponseContext.getRequest();
        if (servletRequest == null) {
            log.error("HttpServletRequest is not available.");
            ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
            return;
        }

        final AuthenticationResult result = authnCtx.getAuthenticationResult();
        final Set<UsernamePrincipal> ups = result.getSubject().getPrincipals(UsernamePrincipal.class);
        final String username = ups.isEmpty() ? null : ups.iterator().next().getName();

        final String ipAddress = servletRequest.getRemoteAddr();
        final String userAgent = servletRequest.getHeader("User-Agent");

        log.info("Starting RBA check for user='{}', ip='{}'", username, ipAddress);

        // Build payload
        final String payload = String.format(
                "{\"username\":\"%s\",\"ipAddress\":\"%s\",\"userAgent\":\"%s\"}",
                nullToEmpty(username), nullToEmpty(ipAddress), nullToEmpty(userAgent)
        );

        HttpURLConnection conn = null;
        try {
            final URL url = new URL(rbaEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

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
                ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            // Parse JSON and extract threatScore
            final JsonObject json = GSON.fromJson(body, JsonObject.class);
            if (json == null || !json.has("threatScore")) {
                log.error("RBA response missing required 'threatScore'.");
                ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            final double threatScore = json.get("threatScore").getAsDouble();
            if (!Double.isFinite(threatScore)) {
                log.error("RBA 'threatScore' is not a finite number: {}", threatScore);
                ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
                return;
            }

            log.info("RBA score={}, idpThreshold={}", threatScore, failureThreshold);

            if (threatScore < failureThreshold) {
                final EventContext ec = prc.ensureSubcontext(EventContext.class);
                ec.setEvent(EventIds.PROCEED_EVENT_ID);
            } else {
                log.warn("Login denied by RBA: threatScore {} >= threshold {}", threatScore, failureThreshold);
                final EventContext ec = prc.ensureSubcontext(EventContext.class);
                ec.setEvent(EventIds.ACCESS_DENIED);
            }

        } catch (JsonSyntaxException jse) {
            log.error("Invalid JSON from RBA service.", jse);
            ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
        } catch (Exception e) {
            log.error("Error calling RBA service at {}", rbaEndpoint, e);
            ActionSupport.buildEvent(prc, EventIds.RUNTIME_EXCEPTION);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
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

    private static String nullToEmpty(String s) {
        return (s == null) ? "" : s;
    }
}
