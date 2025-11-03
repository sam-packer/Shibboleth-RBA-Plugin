# Shibboleth IdP RBA Plugin

A plugin for Shibboleth IdP that forwards requests to a Flask API for threat analysis. The Flask server will use a
trained neural network model to assign a score based on how high risk it believes the login will be. The plugin will get
the response and either allow / deny the login.

This plugin was tested on Shibboleth IdP 5.1.6.

## Requirements

- Java 17
- Shibboleth IdP
- Maven

## To compile

```
mvn clean package
```

## Setting up in Shibboleth

This assumes your Shibboleth IdP directory is in: `/opt/shibboleth-idp`. This is also assuming a base Shibboleth
instance with no customizations. You'll likely have to adapt this in some capacity to fit your Shibboleth environment.

### Building the plugin

After compiling the plugin, you'll want to copy the compiled JAR to `/opt/shibboleth-idp/edit-webapp/WEB-INF/lib`. If
the directory doesn't exist, create it.

Then, rebuild Shibboleth: `/opt/shibboleth-idp/bin/build.sh`. You can then copy the `idp.war` file to your servlet
container of choice (Jetty, Tomcat, etc.)

If all goes well, you should see something similar:

```
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:57] - Shibboleth IdP Version 5.1.6
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:58] - Java version='17.0.16' vendor='Debian'
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:73] - Plugins:
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:75] -                 com.sampacker.shibboleth.rba : v1.0.0
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:93] - Enabled Modules:
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Core IdP Functions (Required)
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Command Line Scripts
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Overlay Tree for WAR Build
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Password Authentication
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Hello World
INFO [net.shibboleth.idp.admin.impl.ReportUpdateStatus:136] - No upgrade available from 5.1.6
INFO [net.shibboleth.idp.admin.impl.ReportUpdateStatus:147] - Version 5.1.6 is current
```

---

Next, you'll need to modify the `/opt/shibboleth-idp/conf/relying-party.xml` file. Where you see this section:

```xml

<bean id="shibboleth.DefaultRelyingParty" parent="RelyingParty">
    ...
</bean>
```

By default, you will have this line:

```xml

<ref bean="SAML2.SSO"/>
```

You'll want to change it to this:

```xml

<bean parent="SAML2.SSO" p:postAuthenticationFlows="#{{'rba'}}"/>
```

If you already have existing flows, you can simply add rba as another entry in your list.

---

Next, you'll want to modify your `/opt/shibboleth-idp/conf/interceptors/profile-intercept.xml` file to add this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:util="http://www.springframework.org/schema/util"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
         http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
         http://www.springframework.org/schema/util  http://www.springframework.org/schema/util/spring-util.xsd">

    <bean id="shibboleth.AvailableInterceptFlows" parent="shibboleth.DefaultInterceptFlows" lazy-init="true">
        <property name="sourceList">
            <list merge="true">
                <bean id="intercept/rba" parent="shibboleth.InterceptFlow"/>
            </list>
        </property>
    </bean>

</beans>
```

You may have other entries in your file, which is okay. The important line to add is:

```
<bean id="intercept/rba" parent="shibboleth.InterceptFlow"/>
```

---

Next, modify your `/opt/shibboleth-idp/conf/interceptors/intercept-events-flow.xml` as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      abstract="true">

    <end-state id="AccessDenied"/>
    <end-state id="RuntimeException"/>

    <global-transitions>
        <transition on="AccessDenied" to="AccessDenied"/>
        <transition on="RuntimeException" to="RuntimeException"/>

        <transition on="#{!'proceed'.equals(currentEvent.id)}" to="InvalidEvent"/>
    </global-transitions>
</flow>
```

The key change here is to tell Shibboleth about the AccessDenied and RuntimeException events. Otherwise, if someone is
denied access, it will always be treated as an `InvalidEvent`.

---

Now, you'll want to add the XML files for the flow at `/opt/shibboleth-idp/flows/intercept/rba`.

Create the directory:

```
mkdir -p /opt/shibboleth-idp/flows/intercept/rba
```

Add this to `/opt/shibboleth-idp/flows/intercept/rba/rba-flow.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      parent="intercept.abstract">

    <action-state id="CallRBA">
        <evaluate expression="rbaWebflowAction"/>
        <transition on="proceed" to="proceed"/>
        <transition on="AccessDenied" to="ShowDenialPage"/>
        <transition on="RuntimeException" to="RuntimeException"/>
    </action-state>

    <view-state id="ShowDenialPage" view="access-denied">
        <transition on="proceed" to="AccessDenied"/>
    </view-state>

    <end-state id="AccessDenied"/>

    <bean-import resource="rba-beans.xml"/>
</flow>
```

Add this to `/opt/shibboleth-idp/flows/intercept/rba/rba-beans.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
         http://www.springframework.org/schema/beans https://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="rbaAction"
          class="com.sampacker.shibboleth.rba.RiskBasedAuthAction"
          init-method="initialize"
          destroy-method="destroy"
          p:rbaEndpoint="https://shib-predict.sampacker.local/score"
          p:failureThreshold="0.60"/>

    <bean id="rbaWebflowAction"
          class="net.shibboleth.idp.profile.impl.WebFlowProfileActionAdaptor"
          init-method="initialize"
          destroy-method="destroy">
        <constructor-arg ref="rbaAction"/>
    </bean>
</beans>
```

This file is important as this is where you'll want to set the RBA endpoint and failure threshold.

---

Next, add the JavaScript collection. In `/opt/shibboleth-idp/edit-webapp`, create a new `js` folder and put the file `rba-metrics.js` inside:
```javascript

(() => {
  const start = performance.now();

  // ---- Counters ----
  let focusChanges = 0,
    blurEvents = 0;
  let clickCount = 0,
    keyCount = 0;
  let totalKeyDelay = 0,
    lastKeyTime = null;
  let pointerDistance = 0,
    pointerEventCount = 0;
  let scrollDistance = 0,
    scrollEventCount = 0;
  let lastScroll = window.scrollY || document.documentElement.scrollTop;
  let lastMoveTime = 0,
    lastX = null,
    lastY = null;
  let firstKeyTime = null,
    firstClickTime = null;
  let pasteCount = 0,
    inputFocusCount = 0,
    resizeCount = 0;

  // ---- Idle tracking ----
  let lastActivity = performance.now();
  let idleTimeTotal = 0;
  let wasIdle = false;
  let idleStartTime = null;

  function recordActivity() {
    const now = performance.now();
    if (wasIdle && idleStartTime !== null) {
      // We were idle, now we're active - add the idle period
      idleTimeTotal += now - idleStartTime;
      wasIdle = false;
      idleStartTime = null;
    }
    lastActivity = now;
  }

  // Check for idle periods periodically
  setInterval(() => {
    const now = performance.now();
    const timeSinceActivity = now - lastActivity;

    // If it's been more than 100ms since last activity, consider it idle
    if (timeSinceActivity > 100 && !wasIdle) {
      wasIdle = true;
      idleStartTime = lastActivity;
    }
  }, 50);

  [
    "mousemove",
    "pointermove",
    "touchmove",
    "keydown",
    "click",
    "scroll",
    "focus",
  ].forEach((ev) =>
    document.addEventListener(ev, recordActivity, { passive: true }),
  );

  // ---- Event listeners ----
  document.addEventListener("visibilitychange", () => focusChanges++);
  window.addEventListener("focus", () => focusChanges++);
  window.addEventListener("blur", () => blurEvents++);
  document.addEventListener("click", () => {
    clickCount++;
    if (!firstClickTime) firstClickTime = performance.now();
  });

  document.addEventListener("keydown", () => {
    const now = performance.now();
    if (!firstKeyTime) firstKeyTime = now;
    if (lastKeyTime) totalKeyDelay += now - lastKeyTime;
    lastKeyTime = now;
    keyCount++;
  });

  document.addEventListener("paste", () => pasteCount++);
  document.addEventListener("focusin", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")
      inputFocusCount++;
  });

  const trackPointer = (e) => {
    const now = performance.now();
    if (now - lastMoveTime < 50) return; // throttle ~20 Hz
    pointerEventCount++;
    if (lastX !== null && lastY !== null) {
      pointerDistance += Math.hypot(e.pageX - lastX, e.pageY - lastY);
    }
    lastX = e.pageX;
    lastY = e.pageY;
    lastMoveTime = now;
  };
  document.addEventListener("mousemove", trackPointer, { passive: true });
  document.addEventListener("pointermove", trackPointer, { passive: true });
  document.addEventListener(
    "touchmove",
    (e) => {
      pointerEventCount++;
      const touch = e.touches && e.touches[0];
      if (!touch) return;
      const { pageX, pageY } = touch;
      if (lastX !== null && lastY !== null) {
        pointerDistance += Math.hypot(pageX - lastX, pageY - lastY);
      }
      lastX = pageX;
      lastY = pageY;
    },
    { passive: true },
  );

  window.addEventListener(
    "scroll",
    () => {
      const currentScroll =
        window.scrollY || document.documentElement.scrollTop;
      scrollDistance += Math.abs(currentScroll - lastScroll);
      lastScroll = currentScroll;
      scrollEventCount++;
    },
    { passive: true },
  );

  window.addEventListener("resize", () => resizeCount++);

  // ---- Device UUID management ----
  function generateUUIDv4() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  let deviceUUID = localStorage.getItem("rbaDeviceUUID");
  if (!deviceUUID) {
    deviceUUID = generateUUIDv4();
    localStorage.setItem("rbaDeviceUUID", deviceUUID);
  }

  // ---- On form submit, attach metrics ----
  const form = document.querySelector("form");
  const metricsField = document.getElementById("rbaMetricsField");

  if (form && metricsField) {
    form.addEventListener("submit", () => {
      const now = performance.now();
      const elapsed = Math.max(0, now - start);
      const avgKeyDelay = keyCount ? totalKeyDelay / keyCount : 0;

      // Account for final idle period if currently idle
      if (wasIdle && idleStartTime !== null) {
        idleTimeTotal += now - idleStartTime;
      }

      // --- Environment snapshot ---
      const env = {
        tz_offset_min: new Date().getTimezoneOffset(),
        language: navigator.language || "unknown",
        platform:
          navigator.userAgentData?.platform || navigator.platform || "unknown",
        device_memory_gb: navigator.deviceMemory || null,
        hardware_concurrency: navigator.hardwareConcurrency || null,
        screen_width_px: screen.width,
        screen_height_px: screen.height,
        pixel_ratio: window.devicePixelRatio || 1,
        color_depth: screen.colorDepth || null,
        touch_support: "ontouchstart" in window,
        webauthn_supported: !!window.PublicKeyCredential,
      };

      // --- Metrics ---
      const metrics = {
        device_uuid: deviceUUID,
        focus_changes: focusChanges,
        blur_events: blurEvents,
        click_count: clickCount,
        key_count: keyCount,
        avg_key_delay_ms: Math.round(avgKeyDelay),
        pointer_distance_px: Math.round(pointerDistance),
        pointer_event_count: pointerEventCount,
        scroll_distance_px: Math.round(scrollDistance),
        scroll_event_count: scrollEventCount,
        time_to_first_key_ms: firstKeyTime
          ? Math.round(firstKeyTime - start)
          : null,
        time_to_first_click_ms: firstClickTime
          ? Math.round(firstClickTime - start)
          : null,
        total_session_time_ms: Math.round(elapsed),
        idle_time_total_ms: Math.round(idleTimeTotal),
        active_time_ms: Math.round(elapsed - idleTimeTotal),
        input_focus_count: inputFocusCount,
        paste_events: pasteCount,
        resize_events: resizeCount,
        metrics_version: 4,
        collection_timestamp: new Date().toISOString(),
        ...env,
      };

      try {
        metricsField.value = JSON.stringify(metrics);
      } catch (err) {
        console.error("RBA metrics serialization failed", err);
      }
    });
  } else {
    console.warn("RBA metrics script: form or #rbaMetricsField not found");
  }
})();
```

On your login form, you MUST include an invisible field for the metrics. At `/opt/shibboleth-idp/views/login.vm`, add
this right before the end of the closing `<form>` tag.

```html
<input type="hidden" id="rbaMetricsField" name="rbaMetricsField" value="" />
```

---

Finally, create an Access Denied view. You must name it `/opt/shibboleth-idp/views/access-denied.vm`. This is where you
get to style it however, you want, but here's an example one:
```html
<!DOCTYPE html>
<html>
  <head>
    <title>Access Denied</title>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <link rel="stylesheet" type="text/css" href="/idp/css/placeholder.css">
  </head>

  <body>
    <main class="main">
      <header>
        <img class="main-logo" src="/idp/images/shibboleth blue.png" alt="ShibBlue" />
        <h1>Access Denied</h1>
      </header>

      <section>
        <p class="output-message output--error">
          Your login attempt was denied by the risk-based authentication system.
        </p>

        <p>
          This can happen if the system detected unusual login behavior or a high risk score.
        </p>

        <p>
          If you believe this is in error, please contact your IT support team.
          <br />
          <a href="https://helpdesk.example.org">Need Help?</a>
        </p>

        <form action="$flowExecutionUrl" method="POST">

          #parse("csrf/csrf.vm")

          <div class="grid">
            <div class="grid-item">
              <button type="submit" class="button" name="_eventId_proceed">
                Continue
              </button>
            </div>
          </div>
        </form>
      </section>
    </main>

    <footer class="footer">
      <div class="cc">
        <p>Your IdP footer text here.</p>
      </div>
    </footer>
  </body>
</html>
```

Your environment may require different or additional configuration. However, this is what's required to get it working
with a stock Shibboleth IdP instance.

A successful authentication should look like this (or similar, depending on your flow):

```
INFO [net.shibboleth.idp.authn.impl.FinalizeAuthentication:201] - Profile Action FinalizeAuthentication: Principal sam authenticated
INFO [com.sampacker.shibboleth.rba.RiskBasedAuthAction:88] - Starting RBA check for user='sam', ip='<redacted>'
INFO [com.sampacker.shibboleth.rba.RiskBasedAuthAction:140] - RBA score=0.0305283652305603, idpThreshold=0.7
INFO [com.sampacker.shibboleth.rba.RiskBasedAuthAction:146] - RBA: emitting event='proceed' ctxClass=org.opensaml.profile.context.EventContext ctxHash=1532931382
```

## Troubleshooting

### General advice

If you plan to use large language models to help you debug, I recommend you paste the XML schema of the relevant XML
files into your model so that it has the context of what to expect. The training data LLMs have on Shibboleth by default
is either outdated, hallucinated, or plain wrong.

### Interceptor not available for use

If you get this error:

```
ERROR [net.shibboleth.idp.profile.interceptor.impl.PopulateProfileInterceptorContext:131] - Profile Action PopulateProfileInterceptorContext: Configured post-authn interceptor flow intercept/rba not available for use
```

It could mean numerous things. Make sure you specified `intercept/rba`, not just `rba` in your `profile-intercept.xml`
file. It could also point to an XML syntax issue. That error is very hard to diagnose, but the first thing to check is
the IDs are correct.

## License

This software is licensed under the **PolyForm Noncommercial License 1.0.0**. You may use, copy, and modify this
software for **noncommercial purposes only**. See [LICENSE.md](LICENSE.md) for the full license text.

Copyright © 2025 Sam Packer. Released under the PolyForm Noncommercial License 1.0.0.