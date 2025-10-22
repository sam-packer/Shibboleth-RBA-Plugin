# Shibboleth IdP RBA Plugin

A plugin for Shibboleth IdP that forwards requests to a Flask API for threat analysis. The Flask server will use a trained neural network model to assign a score based on how high risk it believes the login will be. The plugin will get the response and either allow / deny the login.

This plugin was designed for Shibboleth IdP 5.1.6.

## To compile
```
mvn clean packege
```

## Setting up in Shibboleth

You'll want to copy the compiled JAR to `/opt/shibboleth-idp/edit-webapp/WEB-INF/lib`. If the directory doesn't exist, create it.

Then, rebuild Shibboleth: `./opt/shibboleth-idp/bin/build.sh`. You can then copy the `idp.war` file to your servlet container of choice (Jetty, Tomcat, etc.)

If all goes well, you should see something similar:
```
2025-10-22 01:21:36,055 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:57] - Shibboleth IdP Version 5.1.6
2025-10-22 01:21:36,056 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:58] - Java version='17.0.16' vendor='Debian'
2025-10-22 01:21:36,058 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:73] - Plugins:
2025-10-22 01:21:36,058 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:75] -                 com.sampacker.shibboleth.rba : v1.0.0
2025-10-22 01:21:36,073 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:93] - Enabled Modules:
2025-10-22 01:21:36,075 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Core IdP Functions (Required)
2025-10-22 01:21:36,080 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Command Line Scripts
2025-10-22 01:21:36,080 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Overlay Tree for WAR Build
2025-10-22 01:21:36,080 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Password Authentication
2025-10-22 01:21:36,086 -  - INFO [net.shibboleth.idp.admin.impl.LogImplementationDetails:95] -                 Hello World
2025-10-22 01:21:36,304 -  - INFO [net.shibboleth.idp.admin.impl.ReportUpdateStatus:136] - No upgrade available from 5.1.6
2025-10-22 01:21:36,305 -  - INFO [net.shibboleth.idp.admin.impl.ReportUpdateStatus:147] - Version 5.1.6 is current
```

I have been working for hours on trying to get it implemented into the login flow with no success. 