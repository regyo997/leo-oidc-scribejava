package com.leo.leooidc.controller;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.scribejava.apis.openid.OpenIdOAuth2AccessToken;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.apis.GoogleApi20;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author leo
 * @date 2024/03/14
 * @Reference: https://github.com/scribejava/scribejava/blob/master/scribejava-apis/src/test/java/com/github/scribejava/apis/examples/Google20Example.java
 */
@Slf4j
@RestController
public class LeoOidcScribe {
    private static final String NETWORK_NAME = "Google";
    private static final String PROTECTED_RESOURCE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";
    private static final String PROTECTED_RESOURCE_URL = "https://www.googleapis.com/oauth2/v3/userinfo";

    final String clientId = "628057658113-rcm5rn2vmufiie3uitkt8p4136aceub5.apps.googleusercontent.com";
    final String clientSecret = "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";

    private ObjectMapper mapper = new ObjectMapper();

    final OAuth20Service oAuth20Service = new ServiceBuilder(clientId)
            .apiSecret(clientSecret)
        .     defaultScope("openid profile")
            .callback("http://leo.com/callback")
            .build(GoogleApi20.instance());

    Cache<String, AuthorizationUrlBuilder> cache = Caffeine.newBuilder()
            .expireAfterWrite(3, TimeUnit.MINUTES) // 设置条目在写入 10 分钟后过期
            .maximumSize(100) // 设置缓存最大条目数
            .build();

    @GetMapping("/")
    public String index() {
        return "hello";
    }

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
                .pkceCodeVerifier(authorizationUrlBuilder.getPkce().getCodeVerifier()));

        // 取得 id token
        String idToken = accessToken.getOpenIdToken();
        log.info("idToken: " + accessToken.getOpenIdToken());
        log.info("accessToken: " + accessToken.getAccessToken());
        // 驗證nonce
        Claims payload = Jwts.parser()
                .keyLocator(header -> lookupKey(header.get("kid")))
                .build()
                .parseSignedClaims(idToken)
                .getPayload();
        log.info(payload.toString());
        if (payload.get("nonce") == null || !payload.get("nonce").equals(storedNonce)) {
            return "nonce錯誤";
        }

        // 使用 accessToken 執行受保護的操作
        // 去google取得userinfo, profile資訊
        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
        oAuth20Service.signRequest(accessToken, request);
        Response response1 = oAuth20Service.execute(request);
        String body = response1.getBody();
        return body;
    }

    private Key lookupKey(Object kid) {
        try {
            URL url = new URL("https://www.googleapis.com/oauth2/v3/certs");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            try (InputStream inputStream = conn.getInputStream()) {
                JsonNode rootNode = mapper.readTree(inputStream);
                JsonNode keysNode = rootNode.get("keys");

                for (JsonNode keyNode : keysNode) {
                    String keyId = keyNode.get("kid").asText();

                    if (kid.equals(keyId)) {
                        String rsaPublicKey = keyNode.get("n").asText();
                        String exponent = keyNode.get("e").asText();

                        byte[] decodedPublicKey = Base64.getUrlDecoder().decode(rsaPublicKey);
                        byte[] decodedExponent = Base64.getUrlDecoder().decode(exponent);

                        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, decodedPublicKey), new BigInteger(1, decodedExponent));
                        KeyFactory kf = KeyFactory.getInstance("RSA");

                        return kf.generatePublic(spec);
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
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
        additionalParams.put("access_type", "offline");
        //force to reget refresh token (if user are asked not the first time)
        additionalParams.put("prompt", "consent");
        //nonce
        additionalParams.put("nonce", nonce);
        //claims
        additionalParams.put( "claims", "{\"id_token\":{\"email\":null,\"email_verified\":null}}");

        final AuthorizationUrlBuilder authorizationUrlBuilder = oAuth20Service.createAuthorizationUrlBuilder()
                .state(state)
                .additionalParams(additionalParams)
                .initPKCE();
        cache.put(state, authorizationUrlBuilder);

        response.sendRedirect(authorizationUrlBuilder.build());
    }
}
