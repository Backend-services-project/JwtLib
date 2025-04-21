package backendServices.jwtLib.utility;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;

public class JwtUtilLib {
    private final Key key;

    public JwtUtilLib(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims validateToken(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean hasRequiredRole(String token, String requiredRole) {
        Claims claims = validateToken(token);
        String userRole = claims.get("userType", String.class);
        return requiredRole.equals(userRole);
    }
}
