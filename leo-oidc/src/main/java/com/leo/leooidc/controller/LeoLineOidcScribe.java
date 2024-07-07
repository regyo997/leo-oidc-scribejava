package com.leo.leooidc.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.scribejava.apis.openid.OpenIdJsonTokenExtractor;
import com.github.scribejava.apis.openid.OpenIdOAuth2AccessToken;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.DeviceAuthorizationJsonExtractor;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.AccessTokenRequestParams;
import com.github.scribejava.core.oauth.AuthorizationUrlBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author leo
 * @date 2024/03/19
 */
@Slf4j
@RequestMapping("/line")
@RestController
public class LeoLineOidcScribe {
    private static final String NETWORK_NAME = "Line";
    private static final String PROTECTED_RESOURCE_DISCOVERY_URL = "https://access.line.me/.well-known/openid-configuration";
    private static final String PROTECTED_RESOURCE_URL = "https://api.line.me/oauth2/v2.1/userinfo";
    private static final String CERT_URL = "https://api.line.me/oauth2/v2.1/certs";

    final String clientId = "2004190739";
    final String clientSecret = "cc8a27ea8fb33f213cf5a6aba3fdcbb8";

    private ObjectMapper mapper = new ObjectMapper();

    final OAuth20Service oAuth20Service = new ServiceBuilder(clientId)
            .apiSecret(clientSecret)
            .defaultScope("openid profile email")
            .callback("http://localhost/line/callback")
            .build(LineApi20.instance());

    Cache<String, AuthorizationUrlBuilder> cache = Caffeine.newBuilder()
            .expireAfterWrite(3, TimeUnit.MINUTES)
            .maximumSize(100)
            .build();

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code, @RequestParam("state") String returnedState, HttpSession session, HttpServletResponse response) throws Exception {
        String storedState = (String) session.getAttribute("oauthState");
        String storedNonce = (String) session.getAttribute("oauthNonce");

        if (storedState == null || !storedState.equals(returnedState)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "State mismatch");
            return "state不符合";
        }
       AuthorizationUrlBuilder authorizationUrlBuilder = cache.getIfPresent(storedState);
        if (authorizationUrlBuilder == null) {
            return "授權碼失效";
        }

        // 使用返回的授權碼換取 access token
        OpenIdOAuth2AccessToken accessToken = (OpenIdOAuth2AccessToken)this.oAuth20Service.getAccessToken(
                AccessTokenRequestParams.create(code)
                .addExtraParameter("id_token_key_type","JWK")
                .pkceCodeVerifier(authorizationUrlBuilder.getPkce().getCodeVerifier()));

        // 取得 id token
        String idToken = accessToken.getOpenIdToken();
        log.info("idToken: " + accessToken.getOpenIdToken());
        log.info("accessToken: " + accessToken.getAccessToken());
        // 驗證nonce
        Claims payload = Jwts.parser()
                .keyLocator(header -> lookupKey(header.get("kid").toString()))
                .build()
                .parseSignedClaims(idToken)
                .getPayload();
        log.info(payload.toString());
        if (payload.get("nonce") == null || !payload.get("nonce").equals(storedNonce)) {
            return "nonce錯誤";
        }

        // 使用 accessToken 執行受保護的操作
        // 去line取得userinfo, profile資訊
        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
        oAuth20Service.signRequest(accessToken, request);
        Response response1 = oAuth20Service.execute(request);
        String body = response1.getBody();
        return body;
    }

    public Key lookupKey(String kid) {
        HttpClient httpClient = HttpClients.createDefault();
        try {
            HttpGet request = new HttpGet(URI.create(CERT_URL));
            String responseString = httpClient.execute(request, httpResponse ->
                    EntityUtils.toString(httpResponse.getEntity()));

            JsonNode rootNode = mapper.readTree(responseString);
            JsonNode keysNode = rootNode.get("keys");

            for (JsonNode keyNode : keysNode) {
                String keyId = keyNode.get("kid").asText();
                if (kid.equals(keyId)) {
                    String x = keyNode.get("x").asText();
                    String y = keyNode.get("y").asText();

                    byte[] decodedX = Base64.getUrlDecoder().decode(x);
                    byte[] decodedY = Base64.getUrlDecoder().decode(y);

                    ECPoint ecPoint = new ECPoint(new BigInteger(1, decodedX), new BigInteger(1, decodedY));
                    KeyFactory kf = KeyFactory.getInstance("EC");

                    // 使用 ECGenParameterSpec 初始化 AlgorithmParameters
                    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                    parameters.init(new ECGenParameterSpec("secp256r1"));

                    // 從 AlgorithmParameters 獲取 ECParameterSpec
                    ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

                    // 使用 ECPoint 和 ECParameterSpec 創建 ECPublicKeySpec
                    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);

                    return kf.generatePublic(pubKeySpec);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        }
        throw new RuntimeException("Failed to find public key with kid: " + kid);
    }

    @GetMapping("/auth")
    public void auth(HttpSession session, HttpServletResponse response) throws IOException, ExecutionException, InterruptedException {

        final String state = String.valueOf(new Random().nextInt(999_999));
        session.setAttribute("oauthState", state);
        final String nonce = UUID.randomUUID().toString();
        session.setAttribute("oauthNonce", nonce);

        final Map<String, String> additionalParams = new HashMap<>();
//        additionalParams.put("access_type", "offline");
        //force to reget refresh token (if user are asked not the first time)
//        additionalParams.put("prompt", "consent");
        //nonce
        additionalParams.put("nonce", nonce);
        //claims
//        additionalParams.put( "claims", "{\"id_token\":{\"email\":null,\"email_verified\":null}}");
        final AuthorizationUrlBuilder authorizationUrlBuilder = oAuth20Service.createAuthorizationUrlBuilder()
                .state(state)
                .additionalParams(additionalParams)
                .initPKCE();
        cache.put(state, authorizationUrlBuilder);

        response.sendRedirect(authorizationUrlBuilder.build());
    }
}


class LineApi20 extends DefaultApi20 {
    protected LineApi20() {
    }

    public static LineApi20 instance() {
        return LineApi20.InstanceHolder.INSTANCE;
    }

    public String getAccessTokenEndpoint() {
        return "https://api.line.me/oauth2/v2.1/token";
    }

    protected String getAuthorizationBaseUrl() {
        return "https://access.line.me/oauth2/v2.1/authorize";
    }

    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return OpenIdJsonTokenExtractor.instance();
    }

    public String getRevokeTokenEndpoint() {
        return "https://api.line.me/oauth2/v2.1/revoke";
    }

    public String getDeviceAuthorizationEndpoint() {
        return "";
    }

    public DeviceAuthorizationJsonExtractor getDeviceAuthorizationExtractor() {
//        return GoogleDeviceAuthorizationJsonExtractor.instance();
        return null;
    }

    private static class InstanceHolder {
        private static final LineApi20 INSTANCE = new LineApi20();

        private InstanceHolder() {
        }
    }
}
