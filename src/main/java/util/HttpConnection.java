package util;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpConnection 
{
	public static String sendGet(String url) throws Exception {
		return send(url, "GET");
	}
	
	public static String sendPost(String url) throws Exception {
		return send(url, "POST");
	}
	
	public static String sendPut(String url) throws Exception {
		return send(url, "PUT");
	}
	
	public static String sendDelete(String url) throws Exception {
		return send(url, "DELETE");
	}
	
	public static String send(String url, String verbo) throws Exception {

		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod(verbo);

		//add request header
		con.setRequestProperty("User-Agent", "Mozilla/5.0");

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		//print result
		return response.toString();
	}
}
