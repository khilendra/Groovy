import org.apache.commons.io.IOUtils
import java.nio.charset.*
import java.security.SignatureException
import java.security.Signature

import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.EncodedKeySpec

import java.util.Base64
import java.net.URLEncoder;
//import java.io.*

def flowFile = session.get()
if (!flowFile) return

//generate signature key
def static rsa(String data, String privateKeyString) throws java.security.SignatureException
	{
	  String result
	  try {
			if(privateKeyString == null){
			throw new Exception("PrivateKey should not be null  ");
			}

			byte[] privateBytes = privateKeyString.decodeBase64();
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = kf.generatePrivate(keySpec);

			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(privateKey);
			signer.update(data.getBytes("UTF-8"));
			byte[]  rawRsa = signer.sign();
			result= rawRsa.encodeBase64();
	  } catch (Exception e) {
		throw new SignatureException("Failed to generate RSA error : " + e.getMessage());
	  }
	  return result
	}

	def attributes = flowFile.getAttributes()

	// retrieve arguments of the requestUrl and split arguments
	def split_url = attributes.requestUrl.tokenize('?')

	def method = attributes.requestMethod
	def base_url = split_url[0]
	def arguments = (split_url.size() > 1 ? split_url[1].tokenize('&') : '')
	def privateKeyString = attributes.privateKey

	TreeMap map = [:]

	//additional argument add in base url string
	if(arguments !=''){
		for (String item : arguments) {
			def (key, value) = item.tokenize('=')
			map.put(key, value)
		}
	}


	map.put("oauth_consumer_key", attributes.oauth_consumer_key)
	map.put("oauth_nonce", attributes.oauth_nonce)
	map.put("oauth_signature_method", attributes.oauth_signature_method)
	map.put("oauth_timestamp", attributes.oauth_timestamp)
	map.put("oauth_token", attributes.oauth_token)
	map.put("oauth_version", attributes.oauth_version)

	//url encode change to properly encoded uri
	String.metaClass.encode = {
	java.net.URLEncoder.encode(delegate, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
	}

	String parameterString = map.collect { String key, String value ->
	"${key}=${value.encode()}"
	}.join("&")

	//create base url string
	String signatureBaseString = ""

	signatureBaseString += method.toUpperCase()
	signatureBaseString += '&'
	signatureBaseString += base_url.encode()
	signatureBaseString += '&'
	signatureBaseString += parameterString.encode()

	//create oauth signature key
	String oauthSignature = rsa(signatureBaseString, privateKeyString)

	flowFile = session.putAttribute(flowFile, 'oauth_signature', oauthSignature)

	//header authorization
	String oauth = 'OAuth '
	oauth += 'oauth_consumer_key="'
	oauth += attributes.oauth_consumer_key.encode()
	oauth += '", '
	oauth += 'oauth_nonce="'
	oauth += attributes.oauth_nonce.encode()
	oauth += '", '
	oauth += 'oauth_signature="'
	oauth += oauthSignature.encode()
	oauth += '", '
	oauth += 'oauth_signature_method="'
	oauth += attributes.oauth_signature_method.encode()
	oauth += '", '
	oauth += 'oauth_timestamp="'
	oauth += attributes.oauth_timestamp.encode()
	oauth += '", '
	oauth += 'oauth_token="'
	oauth += attributes.oauth_token.encode()
	oauth += '", '
	oauth += 'oauth_version="'
	oauth += attributes.oauth_version.encode()
	oauth += '"'


//flowFile = session.putAttribute(flowFile, "baseInfo", signatureBaseString)
flowFile = session.putAttribute(flowFile, "Authorization", oauth)

session.transfer(flowFile, REL_SUCCESS)