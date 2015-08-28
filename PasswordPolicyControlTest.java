
import com.novell.ldap.*;
import com.novell.ldap.controls.*;
import java.io.IOException;

public class PasswordPolicyControlTest {
   public static void main (String[] args)
   {
      if (args.length != 3)
      {
         usageInfo();
         System.exit(1);
      }
      
      String ldapServer = args[0];
      String bindDN = args[1];
      String password = args[2];
      
      String controlOID = "1.3.6.1.4.1.42.2.27.8.5.1";
      int ldapPort = 389;
      int ldapVersion = 3;
      LDAPConnection lc = new LDAPConnection();
      LDAPControl control = new LDAPControl(controlOID, false, null);
      LDAPConstraints  constraints = new LDAPConstraints();
      constraints.setControls(control);
      
      // Connect to LDAP server
      try
      {
         lc.connect(ldapServer, ldapPort);
         try
         {
            // Bind to server
            lc.bind(ldapVersion, bindDN, password.getBytes(), constraints);
            LDAPControl[] response = lc.getResponseControls();
            if (response == null)
            {
               System.out.println("No server controls received.");
            }
            else
            {
               // Check the password policy response
               checkResponse(response);
            }

         }
         catch (LDAPException e)
         {
            System.err.println("LDAP exception, Code " + e.getResultCode() +
                    " (" + e.getMessage() + ")");

            LDAPControl[] response = lc.getResponseControls();
            if (response == null)
            {
               System.out.println("No server controls received.");
            }
            else
            {
               // Check the password policy response
               checkResponse(response);
            }
         }
         finally
         {
            lc.disconnect();
         }
      }
      catch (LDAPException e)
      {
         System.err.println("Connection error " + e.toString());
      }
   }
   
   /* Check the password policy response and extract info */
   private static void checkResponse(LDAPControl[] response)
   {
      for (int i = 0; i < response.length; i++)
      {
         try
         {
            LDAPPasswordPolicyResponse lpr = 
                    new LDAPPasswordPolicyResponse(response[i].getID(),
                                                   response[i].isCritical(),
                                                   response[i].getValue());
            if (lpr.ppResponseHasGraceWarning())
            {
               System.out.println("Grace logins remaining: " +
                                  lpr.getGraceAuthNsRemaining());
            }
            else if (lpr.ppResponseHasTimeWarning())
            {
               System.out.println("Time to password expiry: " +
                                  lpr.getTimeBeforeExpiration() + " seconds");
            }
            if (lpr.ppResponseHasError())
            {
               System.out.println("Password policy error code: " +
                       lpr.getErrorCode() + 
                       " (" + lpr.ppErrorText() +")");
            }
         }
         catch (IOException f)
         {
            System.err.println(f.getMessage());
         }
      }
   }
   private static void usageInfo()
   {
      System.err.println("Usage: java PasswordPolicyControlTest <ldap server>"
                         + " <bind dn> <password>");
   }
}
