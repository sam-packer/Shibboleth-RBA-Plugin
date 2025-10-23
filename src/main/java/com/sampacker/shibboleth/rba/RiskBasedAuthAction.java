package com.sampacker.shibboleth.rba;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * This action calls an external risk-based authentication (RBA) service
 * and makes a decision based on the returned threat score.
 */
public class RiskBasedAuthAction extends AbstractProfileAction {

    private final Logger log = LoggerFactory.getLogger(RiskBasedAuthAction.class);
    private String rbaEndpoint;
    private double failureThreshold;

    // --- GETTERS & SETTERS ---
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
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final AuthenticationContext authenticationContext = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authenticationContext == null || authenticationContext.getAuthenticationResult() == null) {
            log.error("AuthenticationContext or AuthenticationResult is not available.");
            ActionSupport.buildEvent(profileRequestContext, "error");
            return;
        }

        final HttpServletRequest servletRequest = getHttpServletRequest();

        if (servletRequest == null) {
            log.error("HttpServletRequest is not available.");
            ActionSupport.buildEvent(profileRequestContext, "error");
            return;
        }

        final AuthenticationResult authResult = authenticationContext.getAuthenticationResult();
        final UsernamePrincipal userPrincipal = authResult.getSubject().getPrincipals(UsernamePrincipal.class).iterator().next();
        final String username = userPrincipal != null ? userPrincipal.getName() : null;
        final String ipAddress = servletRequest.getRemoteAddr();
        final String userAgent = servletRequest.getHeader("User-Agent");
        final String transactionId = profileRequestContext.getLoggingId();

        log.info("Starting RBA check for user: {}, IP: {}", username, ipAddress);

        try {
            final URL url = new URL(rbaEndpoint);
            final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000); // 5 seconds
            conn.setReadTimeout(5000);    // 5 seconds

            // Create JSON payload
            String jsonInputString = String.format(
                    "{\"username\": \"%s\", \"ipAddress\": \"%s\", \"userAgent\": \"%s\", \"transactionId\": \"%s\"}",
                    username, ipAddress, userAgent, transactionId
            );

            log.debug("Sending payload to RBA service: {}", jsonInputString);

            // Send request
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                log.debug("Received response from RBA service: {}", response.toString());
                handleRbaResponse(profileRequestContext, response.toString());
            }

        } catch (Exception e) {
            log.error("Error connecting to RBA service at endpoint: {}", rbaEndpoint, e);
            ActionSupport.buildEvent(profileRequestContext, "error");
        }
    }

    /**
     * Parses the JSON response from the RBA service and signals the outcome.
     *
     * @param profileRequestContext The context to signal events to.
     * @param jsonResponse          The JSON string from the Flask API.
     */
    private void handleRbaResponse(ProfileRequestContext profileRequestContext, String jsonResponse) {
        try {
            Gson gson = new Gson();
            JsonObject jsonObject = gson.fromJson(jsonResponse, JsonObject.class);

            double threatScore = jsonObject.get("threatScore").getAsDouble();
            String decision = jsonObject.get("decision").getAsString();

            log.info("RBA service decision: '{}' with score: {}", decision, threatScore);

            if ("allow".equalsIgnoreCase(decision) && threatScore < failureThreshold) {
                log.info("Login allowed by RBA policy.");
                ActionSupport.buildProceedEvent(profileRequestContext);
            } else {
                log.warn("Login denied by RBA policy. Threat score {} exceeded threshold {}.", threatScore, failureThreshold);
                ActionSupport.buildEvent(profileRequestContext, "rbaDenied");
            }
        } catch (Exception e) {
            log.error("Failed to parse JSON response from RBA service.", e);
            ActionSupport.buildEvent(profileRequestContext, "error");
        }
    }
}
