# Shibboleth IdP RBA Plugin

A plugin for Shibboleth IdP that forwards requests to a Flask API for threat analysis. The Flask server will use a
trained neural network model to assign a score based on how high risk it believes the login will be. The plugin will get
the response and either allow / deny the login.

This plugin was tested on Shibboleth IdP 5.1.6.

## Table of Contents

- [Requirements](#requirements)
- [Building](#building)
- [Installation](#installation)
    - [1. Deploy the JAR](#1-deploy-the-jar)
    - [2. Configure Relying Party](#2-configure-relying-party)
    - [3. Register the Intercept Flow](#3-register-the-intercept-flow)
    - [4. Configure Intercept Events](#4-configure-intercept-events)
    - [5. Add Flow Files](#5-add-flow-files)
    - [6. Add View Templates](#6-add-view-templates)
    - [7. Add JavaScript Data Collection](#7-add-javascript-data-collection)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Requirements

- Java 17
- Shibboleth IdP
- Maven

## Building

```bash
mvn clean package
```

## Installation

This assumes your Shibboleth IdP directory is in: `/opt/shibboleth-idp`. This is also assuming a base Shibboleth
instance with no customizations. You'll likely have to adapt this in some capacity to fit your Shibboleth environment.

### 1. Deploy the JAR

After compiling the plugin, copy the compiled JAR to `/opt/shibboleth-idp/edit-webapp/WEB-INF/lib`. If the directory
doesn't exist, create it.

Then, rebuild Shibboleth:

```bash
/opt/shibboleth-idp/bin/build.sh
```

You can then copy the `idp.war` file to your servlet container of choice (Jetty, Tomcat, etc.)

### 2. Configure Relying Party

Modify `/opt/shibboleth-idp/conf/relying-party.xml`. In the `shibboleth.DefaultRelyingParty` bean, change:

```xml

<ref bean="SAML2.SSO"/>
```

To:

```xml

<bean parent="SAML2.SSO" p:postAuthenticationFlows="#{{'rba'}}"/>
```

If you already have existing flows, you can simply add rba as another entry in your list.

### 3. Register the Intercept Flow

Modify `/opt/shibboleth-idp/conf/interceptors/profile-intercept.xml` to register the RBA intercept flow.

See: [`examples/config/profile-intercept.xml`](examples/config/profile-intercept.xml)

The important line to add is:

```xml

<bean id="intercept/rba" parent="shibboleth.InterceptFlow"/>
```

### 4. Configure Intercept Events

Modify `/opt/shibboleth-idp/conf/interceptors/intercept-events-flow.xml` to tell Shibboleth about the AccessDenied and
RuntimeException events. Otherwise, if someone is denied access, it will always be treated as an `InvalidEvent`.

See: [`examples/config/intercept-events-flow.xml`](examples/config/intercept-events-flow.xml)

### 5. Add Flow Files

Create the flow directory and add the flow configuration files:

```bash
mkdir -p /opt/shibboleth-idp/flows/intercept/rba
```

Copy the following files to `/opt/shibboleth-idp/flows/intercept/rba/`:

- [`rba-flow.xml`](examples/flows/intercept/rba/rba-flow.xml) - Defines the webflow states and transitions
- [`rba-beans.xml`](examples/flows/intercept/rba/rba-beans.xml) - Configures the RBA action bean

The example flow provided does the following:

- If the threat score is below the threshold, proceed to the next event
- If the threat score is above the threshold, transition to the access denied page

The threat score from the API is exposed to the profile request context. You can optionally render it if you desire. You
are able to customize the flow however you desire.

**Bean Configuration Options:**

The `rba-beans.xml` file supports two configuration modes:

1. **MLFlow mode (recommended):** Uses dynamic threshold from your MLFlow server
2. **Manual threshold mode:** Hardcoded threshold value (not recommended for production)

See the example file for both configurations.

### 6. Add View Templates

Create the views directory and add the access denied template:

```bash
mkdir -p /opt/shibboleth-idp/views/intercept
```

Copy [`rba-access-denied.vm`](examples/views/intercept/rba-access-denied.vm) to `/opt/shibboleth-idp/views/intercept/`.

This will give a nice page to the user before sending them to the page that shows the SP denied them.

### 7. Add JavaScript Data Collection

Create the JS directory in edit-webapp:

```bash
mkdir -p /opt/shibboleth-idp/edit-webapp/js
```

Copy [`rba-metrics.js`](examples/js/rba-metrics.js) to `/opt/shibboleth-idp/edit-webapp/js/`.

On your login form, you **must** include an invisible field for the metrics. In your login template (most likely at
`/opt/shibboleth-idp/views/login.vm`), add this right before the closing `</form>` tag:

```html
<input type="hidden" id="rbaMetricsField" name="rbaMetricsField" value=""/>
```

## Verification

If all goes well, you should see something similar in your logs:

```
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:57] - Shibboleth IdP Version 5.1.6
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:58] - Java version='17.0.16' vendor='Debian'
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:73] - Plugins:
INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:75] -                 com.sampacker.shibboleth.rba : v2.1.0
```

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

---

![ShibBlue Logo](assets/shibboleth%20blue.png)