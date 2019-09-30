https://github.com/signalapp/Signal-Android/blob/2882ef6d9f80eb011aeee908b61817602857d210/src/org/thoughtcrime/securesms/RegistrationActivity.java

```
import org.thoughtcrime.securesms.util.Util;
String password = Util.getSecret(18);

public static String getSecret(int size) {
  byte[] secret = getSecretBytes(size);
  return Base64.encodeBytes(secret);
}

public static byte[] getSecretBytes(int size) {
  byte[] secret = new byte[size];
  getSecureRandom().nextBytes(secret);
  return secret;
}

public static SecureRandom getSecureRandom() {
  return new SecureRandom();
}
```

*in golang*

```
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
```
*securesms/RegistrationActivity.java*
```
import org.whispersystems.libsignal.util.KeyHelper;
int registrationId = KeyHelper.generateRegistrationId(false)
String signalingKey = Util.getSecret(52);
accountManager.verifyAccountWithCode(code, signalingKey, registrationId, !registrationState.gcmToken.isPresent(), pin);
```

org.whispersystems.libsignal.util.KeyHelper

https://github.com/signalapp/libsignal-protocol-java/blob/master/java/src/main/java/org/whispersystems/libsignal/util/KeyHelper.java

```
public static int generateRegistrationId(boolean extendedRange) {
  try {
    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
    if (extendedRange) return secureRandom.nextInt(Integer.MAX_VALUE - 1) + 1;
    else               return secureRandom.nextInt(16380) + 1;
  } catch (NoSuchAlgorithmException e) {
    throw new AssertionError(e);
  }
}
```
means get a random number between 1 and 16380

*securesms/RegistrationActivity.java*

```
  private void verifyAccount(@NonNull String code, @Nullable String pin) throws IOException {
    int registrationId = KeyHelper.generateRegistrationId(false);
    TextSecurePreferences.setLocalRegistrationId(RegistrationActivity.this, registrationId);
    SessionUtil.archiveAllSessions(RegistrationActivity.this);

    String signalingKey = Util.getSecret(52);

    accountManager.verifyAccountWithCode(code, signalingKey, registrationId, !registrationState.gcmToken.isPresent(), pin);
```

The real registratation

```
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
 private SignalServiceAccountManager accountManager;

```

  accountManager.verifyAccountWithCode(

https://github.com/signalapp/libsignal-service-java/blob/master/java/src/main/java/org/whispersystems/signalservice/api/SignalServiceAccountManager.java
```
import org.whispersystems.signalservice.internal.push.PushServiceSocket;

public void verifyAccountWithCode(
  String verificationCode,
  String signalingKey,
  int signalProtocolRegistrationId,
  boolean fetchesMessages,
  String pin,
  byte[] unidentifiedAccessKey,
  boolean unrestrictedUnidentifiedAccess
)
    throws IOException
{
  this.pushServiceSocket.verifyAccountCode(verificationCode,
     signalingKey,
     signalProtocolRegistrationId,
     fetchesMessages,
     pin,
     unidentifiedAccessKey,                                      sunrestrictedUnidentifiedAccess);
}
```

*pushServiceSocket.verifyAccountCode(*

```
 private static final String VERIFY_ACCOUNT_CODE_PATH  = "/v1/accounts/code/%s";

public void verifyAccountCode(String verificationCode, String signalingKey, int registrationId, boolean fetchesMessages, String pin,
                              byte[] unidentifiedAccessKey, boolean unrestrictedUnidentifiedAccess)
    throws IOException
{
  AccountAttributes signalingKeyEntity = new AccountAttributes(
    signalingKey,
    registrationId,
    fetchesMessages,
    pin,
    unidentifiedAccessKey,
    unrestrictedUnidentifiedAccess);
  makeServiceRequest(String.format(VERIFY_ACCOUNT_CODE_PATH, verificationCode),
                     "PUT", JsonUtil.toJson(signalingKeyEntity));
}
```

# captcha

```
import org.thoughtcrime.securesms.registration.PushChallengeRequest;
Optional<String> pushChallenge = PushChallengeRequest.getPushChallengeBlocking(accountManager, fcmToken, e164number, PUSH_REQUEST_TIMEOUT_MS);

          accountManager.requestSmsVerificationCode(smsRetrieverSupported, registrationState.captchaToken, pushChallenge);
```
