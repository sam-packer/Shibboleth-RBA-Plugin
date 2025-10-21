# Shibboleth IdP RBA Plugin

A plugin for Shibboleth IdP that forwards requests to a Flask API for threat analysis. The Flask server will use a trained neural network model to assign a score based on how high risk it believes the login will be. The plugin will get the response and either allow / deny the login.

This plugin was designed for Shibboleth IdP 5.1.6.

## To compile
```
mvn clean packege
```

## Setting up in Shibboleth

In `/opt/shibboleth-idp/conf/authn/password-authn-config.xml`, add the Java bean:
```xml
<bean id="RBACheck" class="com.sampacker.shibboleth.rba.RiskBasedAuthAction">
    <property name="rbaEndpoint" value="https://shib-predict.sampacker.local/score" />
    <property name="failureThreshold" value="0.5" />
</bean>
```