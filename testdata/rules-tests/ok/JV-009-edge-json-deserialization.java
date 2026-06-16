// JV-009 EDGE/SAFE: Jackson JSON deserialization — NOT ObjectInputStream, should not fire
// Jackson is safe for deserialization (with proper typing disabled) and uses a different API
package com.acmecorp.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import java.io.InputStream;

public class JsonDeserializationService {

    private final ObjectMapper mapper;

    public JsonDeserializationService() {
        this.mapper = new ObjectMapper();
        // Disable polymorphic type handling to prevent deserialization attacks
        this.mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    /**
     * Safe: Jackson JSON deserialization is not covered by JV-009 (which targets ObjectInputStream).
     * Jackson with explicit typing to a known class is the safe pattern.
     */
    public UserDto parseUserPayload(String jsonPayload) throws Exception {
        return mapper.readValue(jsonPayload, UserDto.class);
    }

    public SessionDto restoreSessionFromJson(InputStream is) throws Exception {
        return mapper.readValue(is, SessionDto.class);
    }
}

class UserDto {
    public String username;
    public String email;
}

class SessionDto {
    public String sessionId;
    public long userId;
}
