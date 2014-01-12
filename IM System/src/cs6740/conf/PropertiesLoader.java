package cs6740.conf;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties; 
/*
 * Class of loading client properties or server properties
 */
public class PropertiesLoader extends Properties{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -869916595211700193L;

	public PropertiesLoader(String FileName) throws IOException{
		 InputStream is = new FileInputStream(FileName);
		 this.load(is);
	}
	
	/*
	 * load client property
	 */
	public static String getClientProperty(String propertyName){
		PropertiesLoader pl;
		try {
			pl = new PropertiesLoader("Properties/client_config.properties");
			return pl.getProperty(propertyName);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * load server property
	 */
	public static String getServerProperty(String propertyName){
		PropertiesLoader pl;
		try {
			pl = new PropertiesLoader("Properties/server_config.properties");
			return pl.getProperty(propertyName);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
