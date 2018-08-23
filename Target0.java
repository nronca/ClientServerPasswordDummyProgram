package project1;

import java.util.HashMap;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.io.IOException;


public class Target0 {
	protected static HashMap<String, String> passMap = new HashMap<String, String>();
	static Scanner c;
	static Target0 t;

	/*
	 * A use of oracle on I/O streams was referenced to set up the scanner
	 * for inputs, but not to solve the actual problem. 
	 */
	public static void main(String[] args) throws IOException {
		c = new Scanner(System.in);
		t = new Target0();
		t.client();
	}
	public void client(){
		System.out.println("username: " );
		String username = c.nextLine();
		System.out.println("enter your password: ");
		String password = c.nextLine();
		t.server(username, password);
	}				

	public int server(String username, String password){
		passMap.put("nronca", "12345");

		int fail = 0;
		while(fail < 5){
			if(fail>0){password = c.nextLine();}
			if(passMap.containsKey(username)){ 
				if(password.equals(passMap.get(username))){
					System.out.println("Login successful! Exiting.");
					c.close();
					break;

				}
				else{
					fail++;
					System.out.println("incorrect password, you have " + (5-fail) + " more attempts.");
				}
			}
			else{
				System.out.println("incorrect username, exiting login");
				c.close();
				break;
			}
		}
		if(fail >= 5 ){
			System.out.println("5 failed attempts, you must now wait 3 minutes. \n");
			try {
				TimeUnit.MINUTES.sleep(3);
				//TimeUnit.SECONDS.sleep(5);
				t.client();//start over again

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				passMap.notify();
			}
		}	

		return 0;
	}
}
//this prototype is no longer necessary
//this was coded before I realized I needed to separate server from client
/*public void client(){

System.out.println("username: " );
String username = c.nextLine();

search:{
	System.out.println("enter your password: ");
	int fail = 0;
	while(fail < 5){
		String password = c.nextLine();
		if(passMap.containsKey(username)){ 
			if(password.equals(passMap.get(username))){
				System.out.println("Login successful");
				c.close();
				break;

			}
			else{
				fail++;
				System.out.println("incorrect password, try again.");
			}
		}
		else{
			System.out.println("incorrect username, exiting login");
			c.close();
			break;
		}
	}
	if(fail >= 5 ){
		System.out.println("5 failed attempts, you must now wait 3 minutes. \n");
		try {
			//passMap.wait(180000);
			//TimeUnit.MINUTES.sleep(3);
			TimeUnit.SECONDS.sleep(5);
			break search;
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			passMap.notify();
		}
	}
}
}*/
