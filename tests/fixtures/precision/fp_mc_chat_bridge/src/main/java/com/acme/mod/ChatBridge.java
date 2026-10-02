package com.acme.mod;

import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;

// Paper plugin relaying in-game chat to the server's own Discord channel. A
// webhook with no credential read is a feature, not theft. Must not confirm.
public class ChatBridge implements Listener {
    private final String webhook = "https://discord.com/api/webhooks/0/FIXTURE-NOT-A-REAL-WEBHOOK";

    @EventHandler
    public void onChat(AsyncPlayerChatEvent e) {
        DiscordClient.post(webhook, e.getPlayer().getName() + ": " + e.getMessage());
    }
}
