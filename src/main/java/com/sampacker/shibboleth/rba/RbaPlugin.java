package com.sampacker.shibboleth.rba;

import net.shibboleth.idp.plugin.IdPPlugin;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;
import net.shibboleth.profile.plugin.PluginException;

import java.io.IOException;

public class RbaPlugin extends PropertyDrivenIdPPlugin implements IdPPlugin {

    public RbaPlugin() throws PluginException, IOException {
        super(RbaPlugin.class);
    }
}
