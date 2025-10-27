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

import net.shibboleth.idp.plugin.IdPPlugin;
import net.shibboleth.idp.plugin.PropertyDrivenIdPPlugin;
import net.shibboleth.profile.plugin.PluginException;

import java.io.IOException;

public class RbaPlugin extends PropertyDrivenIdPPlugin implements IdPPlugin {

    public RbaPlugin() throws PluginException, IOException {
        super(RbaPlugin.class);
    }
}
