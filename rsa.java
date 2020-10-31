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

def static baseUrlString(String baseUrl, String urlArguments, String method, TreeMap data ){
        String result
        try{
            TreeMap map = data;

            if(urlArguments!=null){

                // retrieve arguments of the target and split arguments
                def arguments = urlArguments.tokenize('&');
                for (String item : arguments) {
                def (key, value) = item.tokenize('=')
                    map.put(key, value);
                }
            }

            String parameterString = map.collect { String key, String value ->
            "${key}=${URLEncoder.encode(value)}"
            }.join("&");

            String baseInfo = ""

            baseInfo += method.toUpperCase()
            baseInfo += '&'
            baseInfo += URLEncoder.encode(baseUrl, "UTF-8");
            baseInfo += '&'
            baseInfo += URLEncoder.encode(parameterString, "UTF-8");

            //encode the base string
            result = baseInfo;

        }catch(Exception e){
             println("Error: "+e.getMessage());
        }

   return result;
}

def static authorizationHeader(TreeMap data ){
        String result
        try{
              TreeMap map = data;

//            String headerString = map.collect { String key, String value ->
//                "${key}=${value}"}
//            }.join(", ");
            String parameterString="";
                map.each { key, value ->
                    parameterString += key
                    parameterString += '="'
                    parameterString += URLEncoder.encode(value, "UTF-8")
                    parameterString += '", '
                }

            String oauthHeader = "OAuth "+parameterString;

            //encode the base string
            result = oauthHeader;

        }catch(Exception e){
            println("Error: "+e.getMessage());
        }

        return result;
}

def attributes = flowFile.getAttributes()

def method = attributes.method
def base_url = attributes.base_url
def arguments = attributes.arguments
def privateKeyString = attributes.privateKey

TreeMap map = [:]

map.put("oauth_consumer_key", attributes.oauth_consumer_key)
map.put("oauth_token", attributes.oauth_token)
map.put("oauth_signature_method", attributes.oauth_signature_method)
map.put("oauth_timestamp", attributes.oauth_timestamp)
map.put("oauth_nonce", attributes.oauth_nonce)
map.put("oauth_version", attributes.oauth_version)
map.put("oauth_verifier", attributes.oauth_verifier)

//call url base string
def baseInfo = baseUrlString(base_url, arguments, method, map);
//get signature key
String oauthSignature = rsa(baseInfo, privateKeyString)

//add signature key on authorization header
map.put("oauth_signature", oauthSignature);

//call authorization api
def oauth = authorizationHeader(map);

flowFile = session.putAttribute(flowFile, 'oauth_signature', oauthSignature)
flowFile = session.putAttribute(flowFile, "baseInfo", baseInfo)

flowFile = session.putAttribute(flowFile, "Authorization", oauth)

session.transfer(flowFile, REL_SUCCESS)