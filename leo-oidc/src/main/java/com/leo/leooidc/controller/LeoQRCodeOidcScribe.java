package com.leo.leooidc.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.apis.openid.OpenIdOAuth2AccessToken;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.AccessTokenRequestParams;
import com.github.scribejava.core.oauth.AuthorizationUrlBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * @author leo
 * @date 2024/07/08
 */
@Slf4j
@Controller
public class LeoQRCodeOidcScribe {
    private static final String NETWORK_NAME = "Google";
    private static final String PROTECTED_RESOURCE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";
    private static final String PROTECTED_RESOURCE_URL = "https://www.googleapis.com/oauth2/v3/userinfo";
    private static final String CERT_URL = "https://www.googleapis.com/oauth2/v3/certs";

    final String clientId = "AAA1234567890-371558895240.apps.googleusercontent.com";
    final String clientSecret = "GODDA1234567890";

    private ObjectMapper mapper = new ObjectMapper();

    final OAuth20Service oAuth20ServiceQR = new ServiceBuilder(clientId)
            .apiSecret(clientSecret)
            .defaultScope("openid profile email")
            .callback("http://leo.com/mobile-callback")
            .build(GoogleApi20.instance());

    Cache<String, CacheVO> cache = Caffeine.newBuilder()
            .expireAfterWrite(3, TimeUnit.MINUTES)
            .maximumSize(100)
            .build();

    Cache<String, String> sessionStore = Caffeine.newBuilder()
            .expireAfterWrite(7, TimeUnit.DAYS)
            .maximumSize(1000)
            .build();

    public Key lookupKey(String kid) {
        try {
            HttpClient httpClient = HttpClients.createDefault();
            HttpGet request = new HttpGet(CERT_URL);
            String responseString = httpClient.execute(request, httpResponse ->
                    EntityUtils.toString(httpResponse.getEntity()));

            JsonNode rootNode = mapper.readTree(responseString);
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
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to retrieve or parse public key: " + e.getMessage(), e);
        }
        throw new RuntimeException("Failed to find public key with kid: " + kid);
    }

    @GetMapping("/authQR")
    public String authQR(HttpServletResponse response, Model model) throws IOException, ExecutionException, InterruptedException, WriterException {
        final String state = String.valueOf(new Random().nextInt(999_999));
        String qrCodeImage = generateQRCodeImage(getAuthURL(state));
        model.addAttribute("qrCodeImage", qrCodeImage);
        model.addAttribute("sessionId", state);

        return "authQRView";
    }

    @GetMapping("/mobile-callback")
    @ResponseBody
    public String handleMobileCallback(@RequestParam("code") String code, @RequestParam("state") String returnedState, HttpSession session, HttpServletResponse response) throws IOException, ExecutionException, InterruptedException {
        CacheVO cacheVO = cache.getIfPresent(returnedState);

        if (cacheVO == null) {
            return "無效請求";
        }
        AuthorizationUrlBuilder authorizationUrlBuilder = cacheVO.builder;
        String storedNonce = cacheVO.nonce;

        // 使用返回的授權碼換取 access token
        OpenIdOAuth2AccessToken accessToken = (OpenIdOAuth2AccessToken)this.oAuth20ServiceQR.getAccessToken(
                AccessTokenRequestParams.create(code)
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
//
//        // 使用 accessToken 執行受保護的操作
//        // 去google取得userinfo, profile資訊
//        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
//        oAuth20ServiceQR.signRequest(accessToken, request);
//        Response response1 = oAuth20ServiceQR.execute(request);
//        String body = response1.getBody();

        sessionStore.put(returnedState, accessToken.getAccessToken());
        return "Mobile login successful";
    }

    @GetMapping("/session-status")
    @ResponseBody
    public String checkSessionStatus(@RequestParam("sessionId") String sessionId) {
        System.out.println("sessionId: " + sessionStore.getIfPresent(sessionId));
        return Optional.ofNullable(sessionStore.getIfPresent(sessionId)).orElse("PENDING");
    }

    @GetMapping("/callbackQR")
    @ResponseBody
    public String handleWebCallback(@RequestParam("accessToken") String accessToken) {
        // 使用 accessToken 完成登录逻辑
        return "Logged in with access token: " + accessToken;
    }

    private String getAuthURL(String state) {
        final String nonce = UUID.randomUUID().toString();

        final Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline");
        //force to reget refresh token (if user are asked not the first time)
        additionalParams.put("prompt", "consent");
        //nonce
        additionalParams.put("nonce", nonce);
        //claims
        additionalParams.put( "claims", "{\"id_token\":{\"email\":null,\"email_verified\":null}}");

        final AuthorizationUrlBuilder authorizationUrlBuilder = oAuth20ServiceQR.createAuthorizationUrlBuilder()
                .state(state)
                .additionalParams(additionalParams)
                .initPKCE();
        cache.put(state, new CacheVO(authorizationUrlBuilder, nonce));
        return authorizationUrlBuilder.build();

    }

    private String generateQRCodeImage(String barcodeText) throws WriterException, IOException {
        int width =350, height = 350;
        Map<EncodeHintType, Object> hintMap = new HashMap<>();
        hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hintMap.put(EncodeHintType.MARGIN, 1);
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);

        BitMatrix bitMatrix = new MultiFormatWriter().encode(barcodeText, BarcodeFormat.QR_CODE, width, height, hintMap);

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);

        return "data:image/png;base64," + Base64.getEncoder().encodeToString(pngOutputStream.toByteArray());
    }

    private class CacheVO {
        CacheVO(AuthorizationUrlBuilder builder, String nonce) {
            this.builder = builder;
            this.nonce = nonce;
        }
        AuthorizationUrlBuilder builder;
        String nonce;
    }
}
