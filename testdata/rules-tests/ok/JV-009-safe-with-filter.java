// JV-009 SAFE: ObjectInputStream with ObjectInputFilter — correct pattern
package com.acmecorp.session;

import java.io.*;

public class SafeSessionRestoreService {

    private static final ObjectInputFilter SAFE_FILTER =
        ObjectInputFilter.Config.createFilter(
            "com.acmecorp.session.UserSession;com.acmecorp.session.CartSession;!*"
        );

    /**
     * Safe deserialization: ObjectInputFilter installed before readObject().
     */
    public Object restoreSession(byte[] sessionBytes) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionBytes));
        ois.setObjectInputFilter(SAFE_FILTER);  // Safe: filter set before readObject()
        return ois.readObject();
    }

    /**
     * Safe: ValidatingObjectInputStream from Apache Commons IO.
     */
    public Object fromStream(InputStream is) throws Exception {
        ValidatingObjectInputStream vois = new ValidatingObjectInputStream(is);
        vois.accept(UserSession.class, CartSession.class);
        return vois.readObject();
    }

    /**
     * Safe: JVM-wide filter configured at startup.
     */
    public static void configureSerialFilter() {
        ObjectInputFilter.Config.setSerialFilter(
            info -> info.serialClass() != null && info.serialClass().getName().startsWith("com.acmecorp.")
                ? ObjectInputFilter.Status.ALLOWED
                : ObjectInputFilter.Status.REJECTED
        );
    }
}
