package process;

public class cenario_normal {
	static {
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){
 
	        public boolean verify(String hostname,
	                javax.net.ssl.SSLSession sslSession) {
	            return true;
	        }
	    });
	}
	
	public static void main(String[] args) throws Exception 
	{
		//local_access t1 = new local_access();
		//t1.start();
		//register_imported_roles t2 = new register_imported_roles();
		//t2.start();
		//export_roles t3 = new export_roles();
		//t3.start();
		remote_access t4 = new remote_access();
		t4.start();
	}

}
