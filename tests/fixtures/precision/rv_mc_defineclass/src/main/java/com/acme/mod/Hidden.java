package com.acme.mod;

import java.util.Base64;

// A class defined straight from an embedded base64 blob: a hidden in-memory stager.
// The blob is a placeholder, not bytecode.
public class Hidden extends ClassLoader {
    public Class<?> stage() {
        byte[] b = Base64.getDecoder().decode("RklYVFVSRS1OT1QtQ0xBU1MtQllURVM=");
        return defineClass(null, Base64.getDecoder().decode("RklYVFVSRS1OT1QtQ0xBU1MtQllURVM="), 0, b.length);
    }
}
