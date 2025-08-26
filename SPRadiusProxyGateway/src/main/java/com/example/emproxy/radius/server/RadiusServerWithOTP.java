package com.example.emproxy.radius.server;

import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.tinyradius.packet.AccessRequest;
import org.tinyradius.packet.RadiusPacket;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusServer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@SuppressWarnings("deprecation")
@Service
public class RadiusServerWithOTP extends RadiusServer {
	@Value("${radius.enabled}")
	private boolean radiusEnabled;

	@Value("${radius.idamServerIp}")
	private String idamServerIp;

	@Value("${radius.context}")
	private String context;

	private RestTemplate restTemplate;

	String isActive = "Is_active";
	String radiusServerIP = null;
	String idamServerIpAddress = null;
	String sharedSecretKey = null;
	String usernamefromRP = null;
	String policyAuthOne = null;
	String policyAuthTwo = null;
	String isDeleted = null;
	String userid = null;
	String useridstr = null;

	protected static final String REPLY_MESSAGE = "Reply-Message";
	protected static final HashMap<String, String> users = new HashMap<>();
	protected static final HashMap<String, String> otp = new HashMap<>();
	protected static final HashMap<String, String> authState = new HashMap<>();
	protected static ArrayList<String> auth = new ArrayList<>();

	private final org.apache.logging.log4j.Logger log = LogManager.getLogger(RadiusServerWithOTP.class);

	public RadiusServerWithOTP() {
		try {
			this.idamServerIpAddress = idamServerIp;
			this.radiusServerIP = idamServerIp;
			restTemplate = new RestTemplate();
		} catch (Exception e) {
			log.error("RadiusServerWithOTP exception occured in constructor");
		}
	}

	@Override
	public String getSharedSecret(InetSocketAddress client) {
		log.info("RadiusServerWithOTP : getSharedSecret Start");
		log.info("=========== Client IP Address: {}", client.getAddress().getHostAddress());
		sharedSecretKey = getRadiusAttributeConfiguration(client.getAddress().getHostAddress());
		if (sharedSecretKey != null) {
			log.info("=========== Shared secretkey: {} ", sharedSecretKey);
			return sharedSecretKey;// client Shared secret Key
		} else {
			return "testing123";
		}
	}

	public String getRadiusAttributeConfiguration(String radiusClientIPAddress){
		String secKey=null;
		log.info("RadiusServerWithOTP : getRadiusAttributeConfiguration  start");
		try {
			String url = "https://localhost:8081/securepass/getRadiusAttributeConfigurationFromRadiusClient.htm";
			// Set headers (if needed)
			HttpHeaders headers = new HttpHeaders();
			headers.set("Content-Type", "application/json");

			// Create request body
			String requestBody = "{\"radiusClientIP\":" + radiusClientIPAddress + "}";

			// Create HttpEntity with headers and body
			HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);

			// Call POST method
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
			int responseCode = response.getStatusCodeValue(); // HTTP status code
			String responseBody = response.getBody(); // Response body
			if (responseCode == 200) {
				Map<String, Object> responseMap = new ObjectMapper().readValue(responseBody, new TypeReference<Map<String, Object>>() {});
				secKey = (String) responseMap.get("secretKey");
			}
		}catch (Exception e) {
			log.error("RadiusServerWithOTP : getRadiusAttributeConfiguration  error {} ", e.getMessage());
		}
		return secKey;
	}

	@Override
	public String getUserPassword(String userName) {
		if (auth.contains(userName))
			return otp.get(userName);
		else
			return users.get(userName);
	}


	@SuppressWarnings({ "unused" })
	@Override
	public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client)
			throws RadiusException {
		log.info("RadiusServerWithOTP : accessRequestReceived Start");
		RadiusPacket packet = null;

		String username = accessRequest.getUserName();
		String clientIP = client.getAddress().getHostAddress();

		if (sharedSecretKey == null) {
			RadiusPacket accessReject = new RadiusPacket(RadiusPacket.ACCESS_REJECT,
					accessRequest.getPacketIdentifier());
			accessReject.addAttribute(REPLY_MESSAGE, "InvalidRequest, Client request not Registered.");
			return accessReject;
		}

		log.info("=========== Received Access-Request:\n {} ", accessRequest);
		String plainpwd = accessRequest.getUserPassword();
		String isAuthenticated = authenticateUser(username, plainpwd, clientIP, "10.80.240.85", "10.80.240.85", sharedSecretKey);
		log.info("RadiusServerWithOTP : accessRequestReceived isAuthenticated {} ", isAuthenticated);

		if (!isAuthenticated.toLowerCase().contains("success")) {
			// Might be OTP instead of password
			if (plainpwd.matches("\\d") && plainpwd.length() > 4) {
				String state = authState.get(username);
				if ("OTP_SENT".equals(state)) {
					String verifyOTP = authenticateOTP(username, plainpwd);
					if (!verifyOTP.toLowerCase().contains("success")) {
						RadiusPacket accessReject = new RadiusPacket(RadiusPacket.ACCESS_REJECT,
								accessRequest.getPacketIdentifier());
						accessReject.addAttribute(REPLY_MESSAGE, "Incorrect OTP, please try again.");
						return accessReject;
					}

					// OTP verified
					authState.remove(username);
					otp.remove(username);

					RadiusPacket accessAccept = new RadiusPacket(RadiusPacket.ACCESS_ACCEPT,
							accessRequest.getPacketIdentifier());
					accessAccept.addAttribute(REPLY_MESSAGE, "Welcome " + username);
					return accessAccept;
				}
			}

			// Failed password
			RadiusPacket accessReject = new RadiusPacket(RadiusPacket.ACCESS_REJECT,
					accessRequest.getPacketIdentifier());
			accessReject.addAttribute(REPLY_MESSAGE, "Incorrect Password, please try again.");
			return accessReject;
		}

		// Password authentication successful
		if ("0".equals(policyAuthTwo)) {
			RadiusPacket accessAccept = new RadiusPacket(RadiusPacket.ACCESS_ACCEPT,
					accessRequest.getPacketIdentifier());
			accessAccept.addAttribute(REPLY_MESSAGE, "Welcome " + username);
			log.info("successfully authenticated : {} ", username);
			return accessAccept;
		}

		// Update state
		authState.put(username, "PWD_AUTHENTICATED");

		try {
			String userMobileNumber = getUserMobileNo(username);
			String generatedOtp = getOtp(username, plainpwd, userMobileNumber);
			otp.put(username, generatedOtp);
			authState.put(username, "OTP_SENT");

			RadiusPacket accessChallenge = new RadiusPacket(RadiusPacket.ACCESS_CHALLENGE,
					accessRequest.getPacketIdentifier());
			accessChallenge.addAttribute(REPLY_MESSAGE, "One time password");
			log.info("=========== UserMobileNumber: {} ", userMobileNumber);
			log.info("=========== Otp: {} ", generatedOtp);
			return accessChallenge;
		} catch (Exception e) {
			log.error("Failed to send OTP to user:  {}", username, e);
			authState.remove(username);

			RadiusPacket accessReject = new RadiusPacket(RadiusPacket.ACCESS_REJECT, accessRequest.getPacketIdentifier());
			accessReject.addAttribute(REPLY_MESSAGE, "Error sending OTP, please try again.");
			return accessReject;
		}
	}

	public String getUserMobileNo(String userName) {
		log.info("RadiusServerWithOTP : getUserMobileNo  Start ");
		String output = "";
		try {
			String url = "https://localhost:8081/securepass/UserMobileNumberForApi";
			// Set headers (if needed)
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			String requestBody = "{\"user_name\":" + userName + "}";
			HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
			int responseCode = response.getStatusCodeValue(); // HTTP status code
			String responseBody = response.getBody(); // Response body
			log.info("RadiusServerWithOTP : getUserMobileNo  responseCode {} ", responseCode);
			if (responseCode == 200) {
				output = responseBody;
			}
		}catch (Exception e) {
			log.error("RadiusServerWithOTP : getUserMobileNo  error {} ", e.getMessage());
		}

		return output;
	}

	//verify the OTP given by user by calling to the restAPI of emasIDAM.
	public String authenticateOTP(String username, String plainpwd) {
		log.info("RadiusServerWithOTP : authenticateOTP  Start ");
		String output = "";
		try {
			String url = "https://localhost:8081/securepass/authenticatesmsotpForApi";
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			String requestBody = "{\"otp\":" + plainpwd + ",\"username\":\"" + username + "\"}";
			HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
			int responseCode = response.getStatusCodeValue(); // HTTP status code
			String responseBody = response.getBody(); // Response body
			log.info("RadiusServerWithOTP : authenticateOTP responseCode {} ", responseCode);
			if (responseCode == 200) {
				output = responseBody;
			}
		}catch (Exception e) {
			log.error("RadiusServerWithOTP : authenticateOTP  error {} ", e.getMessage());
		}

		return output;
	}

	//get the OTP needed to send for 2FA of radius client from emasIDAM restAPI using smsGateWays.
	public String getOtp(String username, String password, String mobileNumber) {
		String output = "";
		try {
			log.info("User Mobile Number {} ", mobileNumber);
			String url = "https://localhost:8081/securepass/sendOtpForApi";
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			String responseBody = "{\"user_name\":" + username + ",\"user_mobile_number\":" + mobileNumber + ",\"password\":" + password + "}";
			HttpEntity<String> entity = new HttpEntity<>(responseBody, headers);
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
			int responseCode = response.getStatusCodeValue(); // HTTP status code
			String responseBody1 = response.getBody(); // Response body
			log.info("RadiusServerWithOTP : getOtp responseCode {}", responseCode);
			if (responseCode == 200) {
				output = responseBody1;
			}
		}catch (Exception e) {
			log.error("RadiusServerWithOTP : getOtp  error {} ", e.getMessage());
		}

		return output;
	}

	public String authenticateUser(String username, String password, String radiusClientIp, String radiusServerIp, String idamServerIp, String secretKey) {
		String output = "";
		try {
			String url = "https://localhost:8081/securepass/authenticateRadiusPassword.htm";

			// Set headers (if needed)
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_JSON);
			String requestBody = "{\"username\":\"" + username + "\", \"password\":\"" + password + "\", \"RadiusClientIP\":\"" + radiusClientIp + "\", \"SecretKey\":\"" + secretKey + "\", \"IDAMServerIP\":\"" + idamServerIp + "\", \"RadiusServerIP\":\"" + radiusServerIp + "\"}";
			HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
			ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
			int responseCode = response.getStatusCodeValue(); // HTTP status code
			String responseBody = response.getBody(); // Response body
			if (responseCode == 200) {
				output = parseAuthResponse(responseBody);
			}
		}catch (Exception e) {
			log.error("RadiusServerWithOTP : authenticateUser  2nd try error {} ", e.getMessage());
		}
		return output;
	}
	
	private String parseAuthResponse(String responseBody) throws JSONException {
	    JSONObject jsonObject = new JSONObject(responseBody);

	    String isActiveStr = jsonObject.getString(isActive);
	    if ("Risk Profile Doesn't exist or Wrong Password".equalsIgnoreCase(isActiveStr)) {
	        return "Risk Profile Doesn't exist or Wrong Password";
	    } else if ("Wrong Password".equalsIgnoreCase(isActiveStr)) {
	        return "Wrong Password";
	    } else if ("Risk Profile Doesn't exist".equalsIgnoreCase(isActiveStr)) {
	        return "Risk Profile Doesn't exist";
	    }

	    usernamefromRP = jsonObject.getString("usernamefromRP");
	    policyAuthOne = jsonObject.getString("PolicyAuthOne");
	    userid = jsonObject.getString("userid");
	    policyAuthTwo = jsonObject.getString("PolicyAuthTwo");
	    isActive = jsonObject.getString(isActive);
	    isDeleted = jsonObject.getString("Is_deleted");

	    return "Success";
	}

	//Disable ssl certificate verification while calling restAPIS.
	public CloseableHttpClient getCloseableHttpClient() {
		CloseableHttpClient httpClient = null;
		try {
			httpClient = HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
					.setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
						public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
							return true;
						}
					}).build()).build();
		} catch (KeyManagementException e) {
			log.error("RadiusServerWithOTP : CloseableHttpClient KeyManagementException {}", e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error("RadiusServerWithOTP : CloseableHttpClient NoSuchAlgorithmException {} ", e.getMessage());
		} catch (KeyStoreException e) {
			log.error("RadiusServerWithOTP : CloseableHttpClient KeyStoreException {}", e.getMessage());
		}
		return httpClient;
	}
}