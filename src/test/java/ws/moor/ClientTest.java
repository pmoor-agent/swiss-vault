package ws.moor;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Download;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.AriaRole;
import com.microsoft.playwright.options.Cookie;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import ws.moor.categories.Integration;
import ws.moor.swissvault.auth.TestCookies;

import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.google.common.truth.Truth.assertThat;
import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;

/** Drives the client in Chrome against the dev server. Every test runs as a new user. */
@Category(Integration.class)
public class ClientTest {

  /** Written by the original Closure/Crypto-JS client; "expected" holds the cleartext. */
  private static final JsonObject LEGACY_DATA = JsonParser.parseReader(new InputStreamReader(
      ClientTest.class.getResourceAsStream("/legacy-client-data.json"), StandardCharsets.UTF_8)).getAsJsonObject();

  private static Playwright playwright;
  private static Browser browser;

  private final HttpClient http = HttpClient.newHttpClient();
  private final List<String> errors = new ArrayList<>();
  private String authCookie;
  private BrowserContext context;
  private Page page;

  @BeforeClass
  public static void startBrowser() throws InterruptedException {
    DevServer.awaitStartup();
    playwright = Playwright.create(new Playwright.CreateOptions()
        .setEnv(Map.of("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")));
    browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
        .setExecutablePath(Paths.get(System.getProperty("chrome.path", "/usr/bin/google-chrome"))));
  }

  @AfterClass
  public static void stopBrowser() {
    if (playwright != null) {
      playwright.close();
    }
  }

  @Before
  public void newUser() {
    authCookie = TestCookies.authCookieValue("test-" + UUID.randomUUID());
    context = browser.newContext();
    context.addCookies(List.of(new Cookie("auth", authCookie).setDomain("localhost").setPath("/")));
    page = context.newPage();
    page.onDialog(dialog -> dialog.accept());
    page.onPageError(errors::add);
    page.onConsoleMessage(message -> {
      // the server deliberately has no favicon
      if (message.type().equals("error") && !message.location().contains("/favicon.ico")) {
        errors.add(message.text());
      }
    });
  }

  @After
  public void noErrors() {
    context.close();
    assertThat(errors).isEmpty();
  }

  @Test
  public void readsDataWrittenByLegacyClient() throws Exception {
    importLegacyData();

    for (JsonElement element : LEGACY_DATA.getAsJsonArray("expected")) {
      JsonObject expectedKey = element.getAsJsonObject();
      for (JsonElement passphrase : expectedKey.getAsJsonArray("passphrases")) {
        page.navigate(DevServer.BASE_URL + "/");
        Locator keys = unlock(passphrase.getAsString());
        assertThat(keys.locator("li")).hasCount(2);
        assertThat(keyItem(keys, string(expectedKey, "name"))).containsText(string(expectedKey, "description"));
        button(keyItem(keys, string(expectedKey, "name")), "select").click();

        List<JsonObject> expectedSecrets = new ArrayList<>();
        expectedKey.getAsJsonArray("secrets").forEach(secret -> expectedSecrets.add(secret.getAsJsonObject()));
        expectedSecrets.sort((a, b) -> string(a, "name").compareToIgnoreCase(string(b, "name")));
        assertThat(page.locator("div.secretName"))
            .hasText(expectedSecrets.stream().map(secret -> string(secret, "name")).toArray(String[]::new));

        for (JsonObject expectedSecret : expectedSecrets) {
          Locator secret = secretItem(string(expectedSecret, "name"));
          assertThat(secret.locator("div.secretDescription")).hasText(string(expectedSecret, "description"));
          assertThat(expandProperties(secret, expectedSecret.getAsJsonArray("properties").size()))
              .isEqualTo(toMap(expectedSecret.getAsJsonArray("properties"), "value"));
        }
      }
    }

    for (String wrongPassphrase : List.of("not a passphrase", "")) {
      page.navigate(DevServer.BASE_URL + "/");
      Locator keys = unlock(wrongPassphrase);
      assertThat(keys.locator("li")).hasCount(2);
      assertThat(keys.locator("li").first()).containsText("Key #");
      assertThat(keys.locator("li").last()).containsText("Key #");
      assertThat(button(keys, "select")).hasCount(0);
    }
  }

  @Test
  public void writesDataInTheDocumentedFormat() throws Exception {
    page.navigate(DevServer.BASE_URL + "/");
    button(unlock("my passphrase"), "Create new key...").click();
    Locator newKey = dialog("New Key");
    newKey.locator("input[name=name]").fill("Vault");
    newKey.locator("input[name=description]").fill("für alles");
    newKey.locator("input[name=passphrase1]").fill("my passphrase");
    newKey.locator("input[name=passphrase2]").fill("my passphrase");
    newKey.locator("input[type=submit]").click();

    button(keyItem(unlock("my passphrase"), "Vault"), "select").click();
    button(page, "new secret").click();
    Locator secret = page.locator(".secretListItem").last();
    secret.locator("input.secretNameEdit").fill("Bank");
    secret.locator("input.secretDescriptionEdit").fill("online banking");
    button(secret, "save").click();
    assertThat(secret.locator("div.secretName")).hasText("Bank");

    button(secret, "+").click();
    addProperty(secret, 0, "login", "alice");
    button(secret, "add property").click();
    addProperty(secret, 1, "password", "pä$$wörd 🔑");

    // read back what the server stored, with an implementation independent of the client
    JsonObject key = api("GET", "/keys", null).getAsJsonArray().get(0).getAsJsonObject();
    JsonObject encryption = key.getAsJsonArray("encryptions").get(0).getAsJsonObject();
    assertThat(encryption.get("algorithm").getAsString()).isEqualTo("PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256");
    byte[] rawSecret = EncryptionFormat.unwrapSecret("my passphrase", encryption);
    assertThat(rawSecret).isNotNull();
    assertThat(key.getAsJsonObject("name").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
    assertThat(key.getAsJsonObject("description").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
    assertThat(EncryptionFormat.decrypt(rawSecret, key.getAsJsonObject("name"))).isEqualTo("Vault");
    assertThat(EncryptionFormat.decrypt(rawSecret, key.getAsJsonObject("description"))).isEqualTo("für alles");
    assertThat(EncryptionFormat.unwrapSecret("wrong", encryption)).isNull();

    String keyId = key.get("id").getAsString();
    JsonObject storedSecret = api("GET", "/keys/" + keyId + "/secrets", null).getAsJsonArray().get(0).getAsJsonObject();
    assertThat(storedSecret.getAsJsonObject("name").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
    assertThat(storedSecret.getAsJsonObject("description").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
    assertThat(EncryptionFormat.decrypt(rawSecret, storedSecret.getAsJsonObject("name"))).isEqualTo("Bank");
    assertThat(EncryptionFormat.decrypt(rawSecret, storedSecret.getAsJsonObject("description"))).isEqualTo("online banking");
    Map<String, String> storedProperties = new HashMap<>();
    for (JsonElement property : api("GET", "/keys/" + keyId + "/secrets/" + storedSecret.get("id").getAsString() + "/properties", null).getAsJsonArray()) {
      JsonObject propObj = property.getAsJsonObject();
      assertThat(propObj.getAsJsonObject("name").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
      assertThat(propObj.getAsJsonObject("value").get("algorithm").getAsString()).isEqualTo("AES_256_GCM");
      storedProperties.put(
          EncryptionFormat.decrypt(rawSecret, propObj.getAsJsonObject("name")),
          EncryptionFormat.decrypt(rawSecret, propObj.getAsJsonObject("value")));
    }
    assertThat(storedProperties).isEqualTo(Map.of("login", "alice", "password", "pä$$wörd 🔑"));

    // and the client reads it back after a reload
    openKey("my passphrase", "Vault");
    assertThat(expandProperties(secretItem("Bank"), 2)).isEqualTo(storedProperties);
  }

  @Test
  public void editsAndDeletesSecretsAndProperties() throws Exception {
    importLegacyData();
    openKey("correct horse battery staple", "Family");

    // by position: the name changes, and is not displayed while editing (sorted: "bank", "Mail")
    Locator mail = page.locator(".secretListItem").nth(1);
    assertThat(mail.locator("div.secretName")).hasText("Mail");
    button(mail, "edit").click();
    mail.locator("input.secretNameEdit").fill("E-Mail");
    button(mail, "save").click();
    assertThat(mail.locator("div.secretName")).hasText("E-Mail");

    expandProperties(mail, 2);
    Locator password = propertyItem(mail, "password");
    button(password, "edit").click();
    password.locator("input.propertyValueEdit").fill("new password");
    button(password, "save property").click();
    assertThat(password.locator("div.propertyValue")).hasText("new password");

    Locator user = propertyItem(mail, "user");
    button(user, "edit").click();
    button(user, "delete property").click();
    assertThat(mail.locator("li.propertyListItem")).hasCount(1);

    expandProperties(secretItem("bank"), 2);
    button(secretItem("bank"), "delete secret").click();
    assertThat(page.locator(".secretListItem")).hasCount(1);

    openKey("correct horse battery staple", "Family");
    assertThat(page.locator("div.secretName")).hasText(new String[] {"E-Mail"});
    assertThat(expandProperties(secretItem("E-Mail"), 1)).isEqualTo(Map.of("password", "new password"));
  }

  @Test
  public void managesPassphrases() throws Exception {
    importLegacyData();

    page.navigate(DevServer.BASE_URL + "/");
    button(keyItem(unlock("other passphrase"), "Work"), "edit").click();
    Locator editKey = dialog("Edit Key");
    editKey.locator("input[name=passphrase]").fill("other passphrase");
    button(editKey, "try").click();
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #0 (legacy)");
    editKey.locator("input[name=new-passphrase]").fill("new passphrase");
    button(editKey, "add").click();
    assertThat(editKey.locator("li")).hasCount(2);
    // the key stays unlocked after saving
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #0 (legacy)");
    assertThat(button(editKey.locator("li").nth(1), "delete")).isVisible();
    button(editKey, "done").click();

    // now unlock with the new passphrase and remove the old one
    Locator keys = unlock("new passphrase");
    button(keyItem(keys, "Work"), "edit").click();
    editKey = dialog("Edit Key");
    editKey.locator("input[name=passphrase]").fill("new passphrase");
    button(editKey, "try").click();
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #1");
    button(editKey.locator("li").nth(0), "delete").click();
    assertThat(editKey.locator("li")).hasCount(1);
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #0");
    button(editKey, "done").click();

    keys = unlock("other passphrase");
    assertThat(keys.locator("li").filter(new Locator.FilterOptions().setHasText("Work"))).hasCount(0);
    openKey("new passphrase", "Work");
    assertThat(page.locator("div.secretName")).hasText(new String[] {"VPN"});
  }

  /** Re-wrapping with the same passphrase, then deleting the legacy encryption, as the user would. */
  @Test
  public void upgradesLegacyEncryptionManually() throws Exception {
    importLegacyData();

    page.navigate(DevServer.BASE_URL + "/");
    button(keyItem(unlock("correct horse battery staple"), "Family"), "edit").click();
    Locator editKey = dialog("Edit Key");
    editKey.locator("input[name=passphrase]").fill("correct horse battery staple");
    button(editKey, "try").click();
    assertThat(editKey.locator("li span")).hasText(new String[] {"Encryption #0 (legacy)", "Encryption #1 (legacy)"});
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #0 (legacy)");

    // the same passphrase again: added with the current algorithm, which is then the one used
    editKey.locator("input[name=new-passphrase]").fill("correct horse battery staple");
    button(editKey, "add").click();
    assertThat(editKey.locator("li span"))
        .hasText(new String[] {"Encryption #0 (legacy)", "Encryption #1 (legacy)", "Encryption #2"});
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #2");

    // once more: nothing to upgrade anymore
    editKey.locator("input[name=new-passphrase]").fill("correct horse battery staple");
    button(editKey, "add").click();
    assertThat(editKey.locator("li span"))
        .hasText(new String[] {"Encryption #0 (legacy)", "Encryption #1 (legacy)", "Encryption #2"});

    button(editKey.locator("li").nth(0), "delete").click();
    assertThat(editKey.locator("li span")).hasText(new String[] {"Encryption #0 (legacy)", "Encryption #1"});
    assertThat(editKey.locator("li.encryption-used")).hasText("Encryption #1");
    button(editKey, "done").click();

    // both passphrases still work, the upgraded one through the current algorithm only
    JsonObject family = null;
    for (JsonElement key : api("GET", "/keys", null).getAsJsonArray()) {
      if (key.getAsJsonObject().getAsJsonArray("encryptions").size() == 2) {
        family = key.getAsJsonObject();
      }
    }
    JsonArray encryptions = family.getAsJsonArray("encryptions");
    assertThat(encryptions.get(0).getAsJsonObject().get("algorithm").getAsString())
        .isEqualTo("PBKDF2_SHA1_AES_256_CBC_HMAC_SHA256");
    assertThat(encryptions.get(1).getAsJsonObject().get("algorithm").getAsString())
        .isEqualTo("PBKDF2_SHA512_210000_AES_256_CBC_HMAC_SHA256");
    assertThat(EncryptionFormat.unwrapSecret("correct horse battery staple", encryptions.get(0).getAsJsonObject())).isNull();
    byte[] rawSecret = EncryptionFormat.unwrapSecret("correct horse battery staple", encryptions.get(1).getAsJsonObject());
    assertThat(EncryptionFormat.decrypt(rawSecret, family.getAsJsonObject("name"))).isEqualTo("Family");

    openKey("correct horse battery staple", "Family");
    assertThat(page.locator("div.secretName")).hasText(new String[] {"bank", "Mail"});
    openKey("zweites Passwort ä", "Family");
    assertThat(page.locator("div.secretName")).hasText(new String[] {"bank", "Mail"});
  }

  @Test
  public void exportsDecryptedData() throws Exception {
    importLegacyData();
    openKey("zweites Passwort ä", "Family");
    button(page, "export data").click();

    Locator export = dialog("Export Data");
    assertThat(button(export, "download")).isEnabled();
    JsonArray exported = JsonParser.parseString(export.locator("textarea").inputValue()).getAsJsonArray();

    JsonObject family = LEGACY_DATA.getAsJsonArray("expected").get(0).getAsJsonObject();
    Map<String, Object> expected = new HashMap<>();
    for (JsonElement secret : family.getAsJsonArray("secrets")) {
      expected.put(string(secret.getAsJsonObject(), "name"), List.of(
          string(secret.getAsJsonObject(), "description"), toMap(secret.getAsJsonObject().getAsJsonArray("properties"), "value")));
    }
    Map<String, Object> actual = new HashMap<>();
    for (JsonElement secret : exported) {
      actual.put(string(secret.getAsJsonObject(), "name"), List.of(
          string(secret.getAsJsonObject(), "description"), toMap(secret.getAsJsonObject().getAsJsonArray("properties"), "value")));
    }
    assertThat(actual).isEqualTo(expected);

    Download download = page.waitForDownload(() -> button(export, "download").click());
    assertThat(download.suggestedFilename()).isEqualTo("swiss-vault-export.json");
    assertThat(JsonParser.parseString(Files.readString(download.path()))).isEqualTo(exported);

    button(export, "close").click();
    assertThat(page.locator("dialog[open]")).hasCount(0);
  }

  @Test
  public void searchHidesNonMatchingSecrets() throws Exception {
    importLegacyData();
    openKey("correct horse battery staple", "Family");
    Locator search = page.getByRole(AriaRole.SEARCHBOX, new Page.GetByRoleOptions().setName("Search secrets"));
    assertThat(search).isFocused();
    Locator visibleNames = page.locator(".secretListItem:visible div.secretName");

    search.fill("WEBMAIL");  // in the description, any case
    assertThat(visibleNames).hasText(new String[] {"Mail"});
    search.fill("web login");  // every word has to match
    assertThat(visibleNames).hasText(new String[] {"Mail"});
    search.fill("ban");
    assertThat(visibleNames).hasText(new String[] {"bank"});
    search.fill("bank mail");
    assertThat(page.locator(".secretListItem:visible")).hasCount(0);
    search.press("Escape");
    assertThat(search).hasValue("");
    assertThat(visibleNames).hasText(new String[] {"bank", "Mail"});

    // a new secret stays visible while it is being entered
    search.fill("bank");
    button(page, "new secret").click();
    assertThat(page.locator(".secretListItem:visible")).hasCount(2);
    assertThat(page.locator(".secretListItem:visible input.secretNameEdit")).isFocused();
  }

  @Test
  public void generatesPasswords() throws Exception {
    importLegacyData();
    openKey("correct horse battery staple", "Family");
    Locator mail = secretItem("Mail");
    expandProperties(mail, 2);
    Locator password = propertyItem(mail, "password");
    button(password, "edit").click();

    // Click "generate" to open the generator modal
    button(password, "generate").click();
    Locator generator = dialog("Generate Password");
    assertThat(generator).isVisible();

    // Check default length is 12 and slider is 12
    Locator lengthSlider = generator.locator("input[type=range]");
    assertThat(lengthSlider).hasValue("12");
    assertThat(generator.locator(".lengthDisplay")).hasText("12");

    // Check special characters checkbox is unchecked by default
    Locator specialCheckbox = generator.locator("input[type=checkbox]");
    assertThat(specialCheckbox).not().isChecked();

    // Check generated password is 12 characters and alphanumeric (no special characters)
    Locator passwordInput = generator.locator("input.generatedPassword");
    String initialPassword = passwordInput.inputValue();
    assertThat(initialPassword).matches("^[A-Za-z0-9]{12}$");

    // Regenerate produces another password
    button(generator, "regenerate").click();
    String regeneratedPassword = passwordInput.inputValue();
    assertThat(regeneratedPassword).matches("^[A-Za-z0-9]{12}$");

    // Changing slider updates length and password
    lengthSlider.evaluate("el => { el.value = 16; el.dispatchEvent(new Event('input', {bubbles: true})); }");
    assertThat(generator.locator(".lengthDisplay")).hasText("16");
    String length16Password = passwordInput.inputValue();
    assertThat(length16Password).matches("^[A-Za-z0-9]{16}$");

    // Toggling special characters generates password with special characters
    specialCheckbox.check();
    String specialPassword = passwordInput.inputValue();
    assertThat(specialPassword).hasLength(16);
    assertThat(specialPassword).matches(".*[!@#$%^&*()\\-_=+\\[\\]{}|;:,.<>?].*");

    // Cancelling leaves propertyValueEdit unchanged
    button(generator, "cancel").click();
    assertThat(page.locator("dialog[open]")).hasCount(0);
    assertThat(password.locator("input.propertyValueEdit")).hasValue("hunter2 äöü 🔑");

    // Generate again and insert
    button(password, "generate").click();
    generator = dialog("Generate Password");
    String toInsert = generator.locator("input.generatedPassword").inputValue();
    button(generator, "insert").click();
    assertThat(page.locator("dialog[open]")).hasCount(0);
    assertThat(password.locator("input.propertyValueEdit")).hasValue(toInsert);

    // Save and verify persisted
    button(password, "save property").click();
    assertThat(password.locator("div.propertyValue")).hasText(toInsert);

    // Re-read after page reload
    openKey("correct horse battery staple", "Family");
    assertThat(expandProperties(secretItem("Mail"), 2).get("password")).isEqualTo(toInsert);
  }

  /**
   * Records everything the browser sends during a session that touches every feature, and checks that
   * none of the passphrases, names, descriptions or values ever leave the browser.
   */
  @Test
  public void noPlaintextReachesTheServer() throws Exception {
    List<String> urls = new ArrayList<>();
    List<String> sent = new ArrayList<>();
    context.onRequest(request -> {
      urls.add(request.url());
      sent.add(request.method() + " " + request.url() + "\n" + request.allHeaders() + "\n"
          + (request.postData() == null ? "" : request.postData()));
    });
    List<String> plaintexts = List.of("PASSPHRASE-1-x7", "PASSPHRASE-2-x7", "KEY-NAME-x7", "KEY-DESCRIPTION-x7",
        "SECRET-NAME-x7", "SECRET-DESCRIPTION-x7", "PROPERTY-NAME-x7", "PROPERTY-VALUE-x7", "EDITED-VALUE-x7");

    page.navigate(DevServer.BASE_URL + "/");
    button(unlock("PASSPHRASE-1-x7"), "Create new key...").click();
    Locator newKey = dialog("New Key");
    newKey.locator("input[name=name]").fill("KEY-NAME-x7");
    newKey.locator("input[name=description]").fill("KEY-DESCRIPTION-x7");
    newKey.locator("input[name=passphrase1]").fill("PASSPHRASE-1-x7");
    newKey.locator("input[name=passphrase2]").fill("PASSPHRASE-1-x7");
    newKey.locator("input[type=submit]").click();

    button(keyItem(unlock("PASSPHRASE-1-x7"), "KEY-NAME-x7"), "edit").click();
    Locator editKey = dialog("Edit Key");
    editKey.locator("input[name=passphrase]").fill("PASSPHRASE-1-x7");
    button(editKey, "try").click();
    editKey.locator("input[name=new-passphrase]").fill("PASSPHRASE-2-x7");
    button(editKey, "add").click();
    assertThat(editKey.locator("li")).hasCount(2);
    button(editKey, "done").click();

    button(keyItem(unlock("PASSPHRASE-2-x7"), "KEY-NAME-x7"), "select").click();
    button(page, "new secret").click();
    Locator secret = page.locator(".secretListItem").last();
    secret.locator("input.secretNameEdit").fill("SECRET-NAME-x7");
    secret.locator("input.secretDescriptionEdit").fill("SECRET-DESCRIPTION-x7");
    button(secret, "save").click();
    button(secret, "+").click();
    addProperty(secret, 0, "PROPERTY-NAME-x7", "PROPERTY-VALUE-x7");
    Locator property = secret.locator("li.propertyListItem").first();
    button(property, "edit").click();
    property.locator("input.propertyValueEdit").fill("EDITED-VALUE-x7");
    button(property, "save property").click();
    assertThat(property.locator("div.propertyValue")).hasText("EDITED-VALUE-x7");

    button(page, "export data").click();
    assertThat(dialog("Export Data").locator("textarea")).hasValue(java.util.regex.Pattern.compile("EDITED-VALUE-x7"));

    // nothing goes anywhere but our own server
    for (String url : urls) {
      assertThat(url).startsWith(DevServer.BASE_URL + "/");
    }
    // the browser did send the data, encrypted
    assertThat(sent.stream().filter(request -> request.startsWith("POST ") || request.startsWith("PUT ")).count())
        .isAtLeast(5L);
    for (String request : sent) {
      for (String plaintext : plaintexts) {
        assertThat(request).doesNotContain(plaintext);
        assertThat(request).doesNotContain(Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8)));
      }
    }
  }

  private Locator dialog(String title) {
    return page.locator("dialog[open]").filter(new Locator.FilterOptions()
        .setHas(page.locator(".dialog-title").getByText(title, new Locator.GetByTextOptions().setExact(true))));
  }

  private Locator unlock(String passphrase) {
    Locator dialog = dialog("Enter Passphrase");
    dialog.locator("input[name=passphrase]").fill(passphrase);
    dialog.locator("input[type=submit]").click();
    return dialog("Secret Keys");
  }

  private void openKey(String passphrase, String keyName) {
    page.navigate(DevServer.BASE_URL + "/");
    button(keyItem(unlock(passphrase), keyName), "select").click();
    page.locator(".secretList").waitFor();
  }

  private static Locator keyItem(Locator keys, String name) {
    return keys.locator("li").filter(new Locator.FilterOptions().setHasText(name));
  }

  private Locator secretItem(String name) {
    return page.locator(".secretListItem").filter(new Locator.FilterOptions()
        .setHas(page.locator("div.secretName").getByText(name, new Locator.GetByTextOptions().setExact(true))));
  }

  private static Locator button(Locator scope, String name) {
    return scope.getByRole(AriaRole.BUTTON, new Locator.GetByRoleOptions().setName(name).setExact(true));
  }

  private static Locator button(Page page, String name) {
    return page.getByRole(AriaRole.BUTTON, new Page.GetByRoleOptions().setName(name).setExact(true));
  }

  /** By position, since the name is not displayed while editing. */
  private static Locator propertyItem(Locator secret, String name) {
    int index = secret.locator("div.propertyName").allTextContents().indexOf(name);
    assertThat(index).isAtLeast(0);
    return secret.locator("li.propertyListItem").nth(index);
  }

  private static void addProperty(Locator secret, int index, String name, String value) {
    Locator property = secret.locator("li.propertyListItem").nth(index);
    property.locator("input.propertyNameEdit").fill(name);
    property.locator("input.propertyValueEdit").fill(value);
    button(property, "save property").click();
    assertThat(property.locator("div.propertyValue")).hasText(value);
  }

  /** Expands a secret and returns its properties, name to value. */
  private static Map<String, String> expandProperties(Locator secret, int expectedCount) {
    button(secret, "+").click();
    assertThat(secret.locator("div.propertyName")).hasCount(expectedCount);
    List<String> names = secret.locator("div.propertyName").allTextContents();
    List<String> values = secret.locator("div.propertyValue").allTextContents();
    Map<String, String> properties = new HashMap<>();
    for (int i = 0; i < names.size(); i++) {
      properties.put(names.get(i), values.get(i));
    }
    return properties;
  }

  /** Stores the legacy client's data for the current user, exactly as the legacy client wrote it. */
  private void importLegacyData() throws Exception {
    for (JsonElement element : LEGACY_DATA.getAsJsonArray("keys")) {
      JsonObject key = element.getAsJsonObject();
      JsonObject keyJson = new JsonObject();
      for (String field : List.of("name", "description", "encryptions")) {
        keyJson.add(field, key.get(field));
      }
      String keyId = api("POST", "/keys", keyJson).getAsJsonObject().get("id").getAsString();
      for (JsonElement secretElement : key.getAsJsonArray("secrets")) {
        JsonObject secret = secretElement.getAsJsonObject();
        JsonObject secretJson = new JsonObject();
        secretJson.add("name", secret.get("name"));
        secretJson.add("description", secret.get("description"));
        String secretId = api("POST", "/keys/" + keyId + "/secrets", secretJson).getAsJsonObject().get("id").getAsString();
        for (JsonElement property : secret.getAsJsonArray("properties")) {
          api("POST", "/keys/" + keyId + "/secrets/" + secretId + "/properties", property.getAsJsonObject());
        }
      }
    }
  }

  private JsonElement api(String method, String path, JsonObject body) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(DevServer.BASE_URL + "/api" + path))
        .header("Cookie", "auth=" + authCookie)
        .header("Content-Type", "application/json")
        .method(method, body == null
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(new Gson().toJson(body)))
        .build();
    HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    return JsonParser.parseString(response.body());
  }

  private static Map<String, String> toMap(JsonArray properties, String valueField) {
    Map<String, String> map = new HashMap<>();
    for (JsonElement property : properties) {
      map.put(string(property.getAsJsonObject(), "name"), string(property.getAsJsonObject(), valueField));
    }
    return map;
  }

  private static String string(JsonObject object, String field) {
    return object.get(field).getAsString();
  }
}
