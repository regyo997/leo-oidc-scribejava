package com.leo.leooidc.controller;

import java.util.Random;
import java.util.Scanner;

import com.github.scribejava.apis.openid.OpenIdOAuth2AccessToken;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

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

    final OAuth20Service oAuth20Service = new ServiceBuilder(clientId)
            .apiSecret(clientSecret)
        .     defaultScope("openid profile")
            .callback("http://leo.com/callback")
            .build(GoogleApi20.instance());

    private ConcurrentHashMap<String, String> stateMap = new ConcurrentHashMap<>();

    @GetMapping("/")
    public String index() {
        return "hello";
    }

    @GetMapping("/callback")
    public String callback(@RequestParam("code") String code, @RequestParam("state") String returnedState, HttpSession session, HttpServletResponse response) throws IOException, ExecutionException, InterruptedException {
        String storedState = (String) session.getAttribute("oauthState");

        if (storedState == null || !storedState.equals(returnedState)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "State mismatch");
            return "state不符合";
        }

        // 使用返回的授權碼換取 access token
        OpenIdOAuth2AccessToken accessToken = (OpenIdOAuth2AccessToken)this.oAuth20Service.getAccessToken(code);

        // 取得 id token
        String idToken = accessToken.getParameter("access_token");
        log.info("idToken: " + accessToken.getOpenIdToken());

        // 使用 accessToken 執行受保護的操作
        // 去google取得userinfo, profile資訊
        OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
        oAuth20Service.signRequest(accessToken, request);
        Response response1 = oAuth20Service.execute(request);
        String body = response1.getBody();
        return body;
    }

    @GetMapping("/auth")
    public void auth(HttpSession session, HttpServletResponse response) throws IOException, ExecutionException, InterruptedException {

        final String secretState = "secret" + new Random().nextInt(999_999);
        session.setAttribute("oauthState", secretState);

        final Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline");
        //force to reget refresh token (if user are asked not the first time)
        additionalParams.put("prompt", "consent");
        final String authorizationUrl = oAuth20Service.createAuthorizationUrlBuilder()
                .state(secretState)
                .additionalParams(additionalParams)
                .build();
//        return "redirect:" + authorizationUrl;
        response.sendRedirect(authorizationUrl);
    }
}
