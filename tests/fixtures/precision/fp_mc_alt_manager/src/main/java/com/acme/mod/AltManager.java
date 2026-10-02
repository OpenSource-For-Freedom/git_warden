package com.acme.mod;

import net.minecraft.client.MinecraftClient;

// Account-switcher mod: reads the session token to re-authenticate locally and
// never sends it anywhere. Must not confirm.
public class AltManager {
    public boolean isLoggedIn() {
        String token = MinecraftClient.getInstance().getSession().getAccessToken();
        return token != null && !token.isEmpty();
    }
}
