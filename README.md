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
        <transition on="AccessDenied" to="AccessDenied"/>
        <transition on="RuntimeException" to="RuntimeException"/>
    </action-state>

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
          p:failureThreshold="0.7"/>

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