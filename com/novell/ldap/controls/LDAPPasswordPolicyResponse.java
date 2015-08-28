/* 
 * Copyright (c) 2007 Raymond B. Edah. All Rights Reserved.
 * 
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted only as authorized
 * by the OpenLDAP Public License.
 */

package com.novell.ldap.controls;

import java.io.*;
import com.novell.ldap.*;
import com.novell.ldap.asn1.*;
import com.novell.ldap.client.Debug;

/**
 * This class implements the password policy control as defined in the
 * Internet-Draft:  Password Policy for LDAP Directories (09).
 */
public class LDAPPasswordPolicyResponse extends LDAPControl
{
   
   private int timeBeforeExpiration;
   private int graceAuthNsRemaining;
   private int error;
   
   private boolean hasTimeBeforeExpirationWarning;
   private boolean hasGraceBindsWarning;
   private boolean hasError;
   
    /**
     * The constructor is called to instantiate an LDAPControl corresponding
     * to the Server response to a LDAP Password Policy request. It also parses
     * the contents of the response control.
     * <br>
     * The Password Policy for LDAP Directories draft (09) document defines 
     * this response control as follows:
     *
     * The controlValue is an OCTET STRING, whose
     * value is the BER encoding of a value of the following SEQUENCE:

     * The controlType is 1.3.6.1.4.1.42.2.27.8.5.1 and the controlValue is
     * the BER encoding of the following type:

       PasswordPolicyResponseValue ::= SEQUENCE {
          warning [0] CHOICE {
             timeBeforeExpiration [0] INTEGER (0 .. maxInt),
             graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
          error   [1] ENUMERATED {
             passwordExpired             (0),
             accountLocked               (1),
             changeAfterReset            (2),
             passwordModNotAllowed       (3),
             mustSupplyOldPassword       (4),
             insufficientPasswordQuality (5),
             passwordTooShort            (6),
             passwordTooYoung            (7),
             passwordInHistory           (8) } OPTIONAL }
     *
     *
     *  @param oid     The OID of the control, as a dotted string.
     *<br><br>
     *  @param critical   True if the LDAP operation should be discarded if
     *                    the control is not supported. False if
     *                    the operation can be processed without the control.
     *<br><br>
     *  @param values     The control-specific data.
     */
   public LDAPPasswordPolicyResponse (String oid, boolean critical, byte[] values)
                            throws IOException
   {
      super(oid, critical, values);
      
      /* Initialize instance variables to default values */
      timeBeforeExpiration = -1;
      graceAuthNsRemaining = -1;
      error = -1;
      
      hasTimeBeforeExpirationWarning = false;
      hasGraceBindsWarning = false;
      hasError = false;
      
      /* Create a decoder object */
      LBERDecoder decoder = new LBERDecoder();
      if (decoder == null)
         throw new IOException("Unable to create initial decoder object.");
      
      /* Expecting an ASN.1 Sequence object here */
      ASN1Object asnObj = decoder.decode(values);
      if ( (asnObj == null) || (!(asnObj instanceof ASN1Sequence)) )
         throw new IOException("Decoding error (Expecting ASN1Sequence).");
      
      /* Print ASN.1 Sequence if running debug code */
      if( Debug.LDAP_DEBUG)
      {
         Debug.trace( Debug.controls, "LDAPPasswordPolicy controlvalue = " + asnObj.toString());  
      }
      
      /* Process ASN.1 Sequence object if it contains any elements */
      if (((ASN1Sequence)asnObj).size() > 0)
      {
         for (int j = 0; j < ((ASN1Sequence)asnObj).size(); j++)
         {
            ASN1Object asn1Element = ((ASN1Sequence)asnObj).get(j);
            if ((asn1Element != null) && (asn1Element instanceof ASN1Tagged))
            {
               /* Deconstruct the element into its parts for further use */
               ASN1Tagged taggedElement = ((ASN1Tagged)asn1Element);
               ASN1Identifier taggedElementIdentifier = taggedElement.getIdentifier();
               ASN1Object taggedValue = taggedElement.taggedValue();
               
               if (taggedElementIdentifier.getTag() == 0)
               {
                  /* If the tag is 0, a warning has been encoded here. We again
                   * decompose the sub-element for further use.
                   */ 
                  byte[] taggedContent = ((ASN1OctetString)taggedValue).byteValue();
                  LBERDecoder wdecoder = new LBERDecoder();
                  ASN1Object warningElement = wdecoder.decode(taggedContent);
                  
                  /* Get the sub-element tag */
                  ASN1Identifier warningElementIdentifier = warningElement.getIdentifier ();
                  int warningTag = warningElementIdentifier.getTag ();

                  /* Extract the ASN1Integer object */
                  ASN1Tagged taggedSubElement = ((ASN1Tagged)warningElement);
                  ASN1Object taggedSubElementValue = taggedSubElement.taggedValue ();
                  byte[] warnByte = ((ASN1OctetString)taggedSubElementValue).byteValue();
                  ASN1Integer asn1WarningInt = new ASN1Integer(new LBERDecoder(),
                                                               new ByteArrayInputStream(warnByte),
                                                               warnByte.length);
                  /* Print ASN.1 Integer if running debug code */
                  if( Debug.LDAP_DEBUG)
                  {
                     Debug.trace( Debug.controls, "LDAPPasswordPolicy warning [" + 
                                                  warningTag + "] " + asn1WarningInt.toString());  
                  }

                  if (warningTag == 0)
                  {
                     /* If the sub-element tag is 0, we have a timeBeforeExpiration warning */
                     timeBeforeExpiration = asn1WarningInt.intValue();
                     hasTimeBeforeExpirationWarning = true;
                  }
                  else if (warningTag == 1)
                  {
                     /* Otherwise we have a graceAuthNsRemaining warning */
                     graceAuthNsRemaining = asn1WarningInt.intValue();
                     hasGraceBindsWarning = true;
                  }
                  else
                  {
                     throw new IOException("Invalid tag for password policy warning");
                  }
               }
               else if (taggedElementIdentifier.getTag() == 1)
               {
                  /* If the tag is 1, an error has been encoded here. */
                  byte[] errorByte = ((ASN1OctetString)taggedValue).byteValue();
                  ASN1Enumerated asn1Error = new ASN1Enumerated(new LBERDecoder(),
                                                                new ByteArrayInputStream(errorByte),
                                                                errorByte.length);
                  /* Print ASN.1 Enumerated if running debug code */
                  if( Debug.LDAP_DEBUG)
                  {
                     Debug.trace( Debug.controls, "LDAPPasswordPolicy error " + 
                                                  asn1Error.toString());  
                  }
                  error = asn1Error.intValue();
                  hasError = true;
               }
               else
               {
                  throw new IOException("Decoding error (Invalid password policy element tag)");
               }
            }
            else
            {
               throw new IOException("Decoding error (Untagged element)");
            }
         }
      }
      return;
   }
   
   /**
    * Returns the error code in the response control. If the server response
    * control did not contain an error, -1 is returned.
    */
   public int getErrorCode()
   {
      return error;
   }

   /**
    * Returns the value for timeBeforeExpiration in seconds. If the response
    * control did not include timeBeforeExpiration, -1 is returned.
    */
   public int getTimeBeforeExpiration()
   {
      return timeBeforeExpiration;
   }

   /**
    * Returns the value for graceAuthNsRemaining (Number of grace logins
    * left). If the response did not include graceAuthNsRemaining, -1 is 
    * returned.
    */
   public int getGraceAuthNsRemaining()
   {
      return graceAuthNsRemaining;
   }
   
   /**
    * Returns boolean TRUE if the response control from the server included
    * a warning with timeBeforeExpiration. Boolean FALSE is returned
    * otherwise.
    */
   public boolean ppResponseHasTimeWarning()
   {
      return hasTimeBeforeExpirationWarning;
   }
   
   /**
    * Returns boolean TRUE if the response control from the server included
    * a warning with graceAuthNsRemaining. Boolean FALSE is returned
    * otherwise.
    */
   public boolean ppResponseHasGraceWarning()
   {
      return hasGraceBindsWarning;
   }
   
   /**
    * Returns boolean TRUE if the response control from the server included an
    * error code. Boolean FALSE is returned otherwise.
    */
   public boolean ppResponseHasError()
   {
      return hasError;
   }
   
   /**
    * Returns a string interpretation of the error code in the response control
    * from the server. If the response control did not include an error code,
    * the string "Unknown error code" is returned.
    */
   public String ppErrorText()
   {   
      String errorText = new String();
      switch(error)
      {
         case 0:
            errorText = "Password expired";
            break;
         case 1:
            errorText = "Account locked";
            break;
         case 2:
            errorText = "Password must be changed";
            break;
         case 3:
            errorText = "Policy prevents password modification";
            break;
         case 4:
            errorText = "Policy requires old password in order to change password";
            break;
         case 5:
            errorText = "Password fails quality checks";
            break;
         case 6:
            errorText = "Password is too short for policy";
            break;
         case 7:
            errorText = "Password has been changed too recently";
            break;
         case 8:
            errorText = "New password is in list of old passwords";
            break;
         default:
            errorText = "Unknown error code";
      }
      return errorText;
   }
}
