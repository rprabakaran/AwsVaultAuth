package com.example.demo;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;

import org.springframework.beans.factory.annotation.Autowired;

import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
	
/**
 * @based on https://github.com/BetterCloud/vault-java-driver/issues/118#issuecomment-520070588
 */

public class AwsVaultAuthHeaders {

	@Autowired
	ObjectMapper mapper;

	private final String region;
	private final AWSCredentials credentials;
	private final String endpoint;
	private final String requestBody;

	private AwsVaultAuthHeaders() {
		this.region = new DefaultAwsRegionProviderChain().getRegion();
		this.credentials = new DefaultAWSCredentialsProviderChain().getCredentials();
		this.endpoint = String.format("https://sts.%s.amazonaws.com", region);
		this.requestBody = "Action=GetCallerIdentity&Version=2011-06-15";
	}

	private String getBase64EncodedRequestHeaders(String url) throws URISyntaxException, JsonProcessingException {

		LinkedHashMap<String, String> headers = new LinkedHashMap<>();
		headers.put("X-Vault-AWS-IAM-Server-ID", url);
		headers.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

		DefaultRequest<String> defaultRequest = new DefaultRequest<>("sts");
		defaultRequest.setContent(new ByteArrayInputStream(requestBody.getBytes(StandardCharsets.UTF_8)));
		defaultRequest.setHeaders(headers);
		defaultRequest.setHttpMethod(HttpMethodName.POST);
		defaultRequest.setEndpoint(new URI(endpoint));

		AWS4Signer aws4Signer = new AWS4Signer();
		aws4Signer.setServiceName(defaultRequest.getServiceName());
		aws4Signer.setRegionName(region);
		aws4Signer.sign(defaultRequest, credentials);

		String signedHeaderString = mapper.writeValueAsString(defaultRequest.getHeaders());
		return Base64.getEncoder().encodeToString(signedHeaderString.getBytes(StandardCharsets.UTF_8));
	}

	private String getBase64EncodedRequestBody() {
		return Base64.getEncoder().encodeToString(requestBody.getBytes(StandardCharsets.UTF_8));
	}

	private String getBase64EncodedRequestUrl() {
		return Base64.getEncoder().encodeToString(endpoint.getBytes(StandardCharsets.UTF_8));
	}

	private String generateHeaders() throws JsonProcessingException, URISyntaxException {
		LinkedHashMap<String, String> headers = new LinkedHashMap<>();

		headers.put("iam_http_request_method", "POST");
		headers.put("iam_request_url", getBase64EncodedRequestUrl());
		headers.put("iam_request_body", getBase64EncodedRequestBody());
		headers.put("iam_request_headers", getBase64EncodedRequestHeaders("your vault url"));
		headers.put("role", "your iam role");

		return mapper.writeValueAsString(headers);
	}

	public static void main(String[] args) throws JsonProcessingException, URISyntaxException {
		AwsVaultAuthHeaders vaultHeaders = new AwsVaultAuthHeaders();

		System.out.println(vaultHeaders.generateHeaders());

	}

}
