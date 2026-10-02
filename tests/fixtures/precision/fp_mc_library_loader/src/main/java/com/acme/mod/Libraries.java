package com.acme.mod;

import java.net.URL;
import java.net.URLClassLoader;

// Plugin runtime-dependency loader: pulls a library jar from Maven Central. A
// reputable registry host, so the remote-classload rule must not confirm.
public class Libraries {
    public ClassLoader load() throws Exception {
        return new URLClassLoader(new URL[]{new URL("https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar")});
    }
}
