// JV-009 V1,2,4/A,B,C,D: insecure ObjectInputStream.readObject() patterns
// Realistic AI-generated session restore service — multiple deserialization vulnerabilities
package com.acmecorp.session;

import java.io.*;
import java.util.Base64;

public class SessionRestoreService {

    // VULN B: direct new ObjectInputStream().readObject() one-liner
    public Object deserializeFromBytes(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();  // VULN
    }

    // VULN C: ObjectInputStream assigned to variable then readObject()
    public Object restoreSession(byte[] sessionBytes) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionBytes));
        // ... some code in between ...
        Object sessionObj = ois.readObject();  // VULN: no setObjectInputFilter before readObject
        return sessionObj;
    }

    // VULN D: ObjectInputStream in try-with-resources
    public Object loadFromStorage(InputStream inputStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {
            return ois.readObject();  // VULN: no filter set in try-with-resources
        }
    }

    // VULN E: helper method named "deserializeObject" calling readObject
    public Object fromStream(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();  // VULN: in deserialize-named method
    }

    // VULN B: decodeAndDeserialize from base64
    public Object decodeObject(String base64Encoded) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Encoded);
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();  // VULN
    }
}
